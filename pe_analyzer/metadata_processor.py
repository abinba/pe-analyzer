import logging
import tempfile

from pyspark.sql import SparkSession
from pyspark.sql.functions import udf
from pyspark.sql.types import StructType, StructField, StringType, LongType, IntegerType

from pe_analyzer.s3_handler import S3Handler
from pe_analyzer.db.db import Database
from pe_analyzer.file_analyzer import FileAnalyzer, FileMetadataContext

logger = logging.getLogger(__name__)


class MetadataProcessor:
    def __init__(self, spark: SparkSession, n: int, db_url: str):
        self.spark = spark
        self.n = n
        self.s3_handler = S3Handler()
        self.database = Database(db_url=db_url)

    def process(self):
        logger.info("Processing new files...")

        processed_files = set(self.database.get_processed_files())

        logger.info(f"Found {len(processed_files)} processed files.")

        clean_files = self.s3_handler.list_files("0/", self.n // 2)
        malware_files = self.s3_handler.list_files("1/", self.n // 2)

        logger.info(f"Found {len(clean_files)} clean files and {len(malware_files)} malware files.")

        all_files = [f for f in clean_files + malware_files if f not in processed_files]

        if not all_files:
            logger.info("No new files to process.")
            return

        logger.info(f"Processing {len(all_files)} new files...")

        rdd = self.spark.sparkContext.parallelize(all_files)

        schema = StructType(
            [
                StructField("path", StringType(), True),
                StructField("size", LongType(), True),
                StructField("type", StringType(), True),
                StructField("arch", StringType(), True),
                StructField("imports", IntegerType(), True),
                StructField("exports", IntegerType(), True),
            ]
        )

        analyze_udf = udf(self.analyze_file, schema)

        df = rdd.toDF("path").withColumn("metadata", analyze_udf("path")).select("metadata.*")

        metadata_list = df.collect()
        self.database.save_metadata(metadata_list)

        logger.info(f"Processed {df.count()} new files.")

    def analyze_file(self, file_path: str) -> tuple:
        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            logger.info(f"Downloading {file_path} to {temp_file.name}...")
            self.s3_handler.download_file(file_path, temp_file.name)
            logger.info(f"Analyzing {file_path}...")
            result: FileMetadataContext = FileAnalyzer.analyze_pe_file(temp_file.name)
            logger.info(f"Deleting {temp_file.name}...")
        return result.to_tuple()
