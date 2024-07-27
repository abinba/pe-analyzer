import logging
import socket
import sys

from pyspark.sql import SparkSession
from pe_analyzer.metadata_processor import MetadataProcessor
from pe_analyzer.settings import settings

logging.basicConfig(level=settings.logging_level, format=settings.logging_format)
logger = logging.getLogger(__name__)

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10

    logger.info(f"Starting PE File Analyzer with n={n}...")

    spark = (
        SparkSession.builder.appName("PE File Analyzer")
        # .master("local[*]")
        # .master("spark://localhost:7077")
        .getOrCreate()
    )

    processor = MetadataProcessor(spark, n, db_url=settings.get_database_uri())
    processor.process()

    spark.stop()


if __name__ == "__main__":
    main()
