import logging
import time

import boto3
import botocore.exceptions
import pefile
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf, struct
from pyspark.sql.types import StructType, StructField, StringType, LongType, IntegerType

from pe_analyzer.s3_handler import S3Handler
from pe_analyzer.db.db import Database
from pe_analyzer.settings import settings

logger = logging.getLogger(__name__)


class MetadataProcessor:
    def __init__(
        self,
        spark: SparkSession,
        n: int,
        db_url: str,
        batch_size: int = 100,
        partition_size: int = 10,
    ):
        self.spark = spark
        self.n = n
        self.s3_handler = S3Handler()
        self.database = Database(db_url=db_url)
        self.batch_size = batch_size
        self.partition_size = partition_size

    def process(self):
        process_start = time.time()
        logger.info("Processing new files...")

        clean_files = self.s3_handler.list_files("0/")
        malware_files = self.s3_handler.list_files("1/")

        clean_files = self.database.get_not_processed_files(clean_files)[: self.n // 2]
        malware_files = self.database.get_not_processed_files(malware_files)[: self.n // 2]

        logger.info(f"Found {len(clean_files)} clean files and {len(malware_files)} malware files.")

        all_files = clean_files + malware_files

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
                StructField("error", StringType(), True),
            ]
        )

        def analyze_pe_file(s3_path: str, s3_region: str, s3_bucket: str) -> tuple:
            file_type = s3_path.split(".")[-1].lower() if "." in s3_path else None

            s3 = boto3.client("s3", region_name=s3_region, aws_access_key_id="", aws_secret_access_key="")

            s3._request_signer.sign = lambda *args, **kwargs: None

            try:
                obj = s3.get_object(Bucket=s3_bucket, Key=s3_path)
                file_content = obj["Body"].read()
                file_size = len(file_content)

                pe = pefile.PE(data=file_content)
                arch = "x32" if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"] else "x64"

                import_count = (
                    sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
                    else 0
                )
                export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0

                return s3_path, file_size, file_type, arch, import_count, export_count, None
            except botocore.exceptions.EndpointConnectionError as err:
                # TODO: if the error is due to network issues, we need to retry
                return s3_path, None, file_type, None, None, None, str(err)
            except Exception as err:
                return s3_path, None, file_type, None, None, None, str(err)
            finally:
                if "pe" in locals():
                    pe.close()

        def analyze_file_udf(row):
            return analyze_pe_file(row.path, s3_region=row.s3_region, s3_bucket=row.s3_bucket)

        analyze_udf = udf(analyze_file_udf, schema)

        df = self.spark.createDataFrame(
            [(f, settings.s3_region, settings.s3_bucket) for f in all_files], ["path", "s3_region", "s3_bucket"]
        )

        start = time.time()

        df = df.select(analyze_udf(struct("path", "s3_region", "s3_bucket")).alias("metadata")).select("metadata.*")

        def process_partition(iterator):
            from sqlalchemy import create_engine, Table, MetaData
            from sqlalchemy.dialects.postgresql import insert

            engine = create_engine("postgresql://postgres:postgres@localhost:5432/metadata_db")
            file_metadata_table = Table("file_metadata", MetaData(), autoload_with=engine)

            batch = []
            with engine.connect() as connection:
                for row in iterator:
                    row_dict = row.asDict()
                    if row_dict["error"]:
                        print(f"Error processing {row_dict['path']}: {row_dict['error']}")
                    del row_dict["error"]
                    batch.append(row_dict)
                    if len(batch) >= 100:
                        connection.execute(insert(file_metadata_table).values(batch))
                        batch = []
                if batch:
                    connection.execute(insert(file_metadata_table).values(batch))
                connection.commit()

        df.foreachPartition(process_partition)

        logger.info(f"Processed {df.count()} new files in {time.time() - start:.2f} seconds.")
        logger.info(f"Total processing time: {time.time() - process_start:.2f} seconds.")
