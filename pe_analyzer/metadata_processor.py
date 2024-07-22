import logging
import time

import boto3
import pefile
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf, struct
from pyspark.sql.types import StructType, StructField, StringType, LongType, IntegerType

from pe_analyzer.s3_handler import S3Handler
from pe_analyzer.db.db import Database
from pe_analyzer.settings import settings

logger = logging.getLogger(__name__)


class MetadataProcessor:
    def __init__(self, spark: SparkSession, n: int, db_url: str):
        self.spark = spark
        self.n = n
        self.s3_handler = S3Handler()
        self.database = Database(db_url=db_url)

    def process(self):
        process_start = time.time()
        logger.info("Processing new files...")
        # Problem: in the current implementation we get all the data from the database.
        # If the number of processed files is very large, this can be a bottleneck.
        processed_files = set(self.database.get_processed_files())
        logger.info(f"Found {len(processed_files)} processed files.")

        clean_files = self.s3_handler.list_files("0/", self.n // 2)
        malware_files = self.s3_handler.list_files("1/", self.n // 2)
        logger.info(f"Found {len(clean_files)} clean files and {len(malware_files)} malware files.")

        all_files = [f for f in clean_files + malware_files if f not in processed_files]

        # TODO: If all_files < N, do we need to get more files and process them?

        if not all_files:
            logger.info("No new files to process.")
            return

        logger.info(f"Processing {len(all_files)} new files...")

        schema = StructType(
            [
                StructField("path", StringType(), False),
                StructField("size", LongType(), False),
                StructField("file_type", StringType(), False),
                StructField("architecture", StringType(), True),
                StructField("num_imports", IntegerType(), True),
                StructField("num_exports", IntegerType(), True),
            ]
        )

        def analyze_pe_file(s3_path: str, s3_region: str, s3_bucket: str) -> tuple:
            file_type = s3_path.split(".")[-1].lower() if "." in s3_path else None

            s3 = boto3.client("s3", region_name=s3_region)

            try:
                obj = s3.get_object(Bucket=s3_bucket, Key=s3_path)
                file_content = obj["Body"].read()
                file_size = len(file_content)

                pe = pefile.PE(data=file_content, fast_load=False)
                arch = "x32" if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"] else "x64"

                import_count = (
                    sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
                    else 0
                )
                export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0

                return s3_path, file_size, file_type, arch, import_count, export_count
            except Exception:
                return s3_path, None, file_type, None, None, None
            finally:
                if "pe" in locals():
                    pe.close()

        def analyze_file_udf(row):
            return analyze_pe_file(row.path, s3_region=row.s3_region, s3_bucket=row.s3_bucket)

        analyze_udf = udf(analyze_file_udf, schema)

        df = self.spark.createDataFrame(
            [(f, settings.s3_region, settings.s3_bucket) for f in all_files], ["path", "s3_region", "s3_bucket"]
        )

        logger.info(f"Processing {df.count()} files...")

        start = time.time()
        df = df.select(analyze_udf(struct("path", "s3_region", "s3_bucket")).alias("metadata")).select("metadata.*")
        logger.info(f"Processing time: {time.time() - start:.2f} seconds.")

        start = time.time()
        metadata_list = df.collect()
        logger.info(f"Collect time: {time.time() - start:.2f} seconds.")

        self.database.save_metadata(metadata_list)

        logger.info(f"Processed {df.count()} new files.")

        logger.info(f"Total processing time: {time.time() - process_start:.2f} seconds.")
