import logging

from pyspark.sql import SparkSession
from pe_analyzer.metadata_processor import MetadataProcessor
from pe_analyzer.settings import settings

logging.basicConfig(level=settings.logging_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def main():
    n = 10

    logger.info(f"Starting PE File Analyzer with n={n}...")

    spark = SparkSession.builder.appName("PE File Analyzer").getOrCreate()

    processor = MetadataProcessor(spark, n, db_url=settings.get_database_uri())
    processor.process()

    spark.stop()


if __name__ == "__main__":
    main()
