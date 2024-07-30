import logging
import time
from typing import Iterable

from pyspark import Row
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf, struct

from pe_analyzer.file_analyzer import analyze_pe_file
from pe_analyzer.file_storage import FileObjectStorage
from pe_analyzer.schema import FileMetadataContainer
from pe_analyzer.db.db import DatabaseConnector
from pe_analyzer.task_provider import TaskProvider

logger = logging.getLogger(__name__)


def process(
    spark: SparkSession,
    task_provider: TaskProvider,
    file_storage_handler: FileObjectStorage,
    database: DatabaseConnector,
):
    process_start = time.time()
    logger.info("Gathering file paths from task provider...")

    file_paths: list[str] = task_provider.get_file_paths()
    if not file_paths:
        logger.error("No files to process.")
        return

    logger.info(f"Processing {len(file_paths)} new files...")

    schema = FileMetadataContainer.get_spark_schema()

    def analyze_file_udf(row: Row):
        """
        Download, analyze and return metadata for a single file.
        """
        return analyze_pe_file(path=row.path, file_storage_handler=file_storage_handler)

    analyze_udf = udf(analyze_file_udf, schema)
    df = spark.createDataFrame([(f,) for f in file_paths], ["path"])

    start = time.time()

    def process_partition(iterator: Iterable[Row]):
        """
        For each automatically selected partition, we save the files in batches for better performance.
        """
        database.save_metadata(iterator)

    df = df.select(analyze_udf(struct("path")).alias("metadata")).select("metadata.*")
    df.foreachPartition(process_partition)

    logger.info(f"Processed {df.count()} new files in {time.time() - start:.2f} seconds.")
    logger.info(f"Total processing time: {time.time() - process_start:.2f} seconds.")
