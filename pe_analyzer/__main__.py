import logging
import socket
import sys

from pyspark.sql import SparkSession

from pe_analyzer.core.metadata_processor import process
from pe_analyzer.db.connector import SQLAlchemyConnector, DatabaseConnector
from pe_analyzer.file_analysis.pe_file_handler import PEFileHandler
from pe_analyzer.file_storage.s3 import S3ObjectStorage
from pe_analyzer.settings import settings
from pe_analyzer.task_provider.cmd_task import CommandLineTaskProvider

logging.basicConfig(level=settings.logging_level, format=settings.logging_format)
logger = logging.getLogger(__name__)

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10

    logger.info(f"Starting PE File Analyzer with n={n} and spark URL: {settings.spark_url}...")

    if settings.spark_local_mode:
        spark = SparkSession.builder.appName("PE File Analyzer").master("local[*]").getOrCreate()
    else:
        spark = SparkSession.builder.appName("PE File Analyzer").master(settings.spark_url).getOrCreate()

    spark.sparkContext.addPyFile("pe_analyzer.zip")

    file_storage_handler = S3ObjectStorage(
        bucket_name=settings.s3_bucket,
        region_name=settings.s3_region,
    )

    database: DatabaseConnector = SQLAlchemyConnector(
        db_url=settings.get_database_uri(),
        batch_size=settings.batch_size,
    )

    command_line_task_provider = CommandLineTaskProvider(
        n=n,
        database=database,
        file_storage_handler=file_storage_handler,
    )

    process(
        spark=spark,
        task_provider=command_line_task_provider,
        file_storage_handler=file_storage_handler,
        database=database,
        pe_file_handler=PEFileHandler(),
    )

    spark.stop()


if __name__ == "__main__":
    main()
