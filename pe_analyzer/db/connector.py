from abc import ABC, abstractmethod
import logging
from typing import Iterable

from pyspark import Row
from pyspark.sql import SparkSession
from sqlalchemy import create_engine, select, Table, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert

from pe_analyzer.db.models import FileMetadata

logger = logging.getLogger(__name__)


class DatabaseConnector(ABC):
    partitions_used: bool = False

    @abstractmethod
    def get_not_processed_files(self, file_paths: list[str]) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def save_metadata(self, metadata_list: Iterable[Row]) -> None:
        raise NotImplementedError


class SQLAlchemyConnector(DatabaseConnector):
    partitions_used: bool = True

    def __init__(
        self,
        db_url: str,
        batch_size: int,
        isolation_level: str,
        auto_flush: bool = False,
        expire_on_commit: bool = False,
    ):
        self.db_url = db_url
        self.batch_size = batch_size
        self.isolation_level = isolation_level
        self.auto_flush = auto_flush
        self.expire_on_commit = expire_on_commit

    def get_engine(self):
        return create_engine(
            self.db_url,
            isolation_level=self.isolation_level,
        )

    @staticmethod
    def get_table_name():
        return "file_metadata"

    def get_not_processed_files(self, file_paths: list[str]) -> list[str]:
        """
        Returns a list of file paths that are not yet processed

        :param file_paths: List of file paths to check
        """
        SessionLocal = sessionmaker(
            bind=self.get_engine(), autoflush=self.auto_flush, expire_on_commit=self.expire_on_commit
        )

        with SessionLocal() as session:
            # Get all the processed files within the list of file_paths
            stmt = select(FileMetadata.path).where(FileMetadata.path.in_(file_paths))
            processed_files = session.scalars(stmt).all()
            logger.info(f"Found {len(processed_files)} processed files.")

        # Exclude the ones that are already processed
        return list(set(file_paths).difference(set(processed_files)))

    def save_metadata(self, metadata_list: Iterable[Row]):
        """
        Used to save a partition of metadata PySpark Rows to the database.

        :param metadata_list: List of PySpark Rows to save
        """
        engine = self.get_engine()
        file_metadata_table = Table(self.get_table_name(), MetaData(), autoload_with=engine)

        batch = []
        with engine.connect() as connection:
            for row in metadata_list:
                batch.append(row.asDict())
                if len(batch) >= self.batch_size:
                    connection.execute(insert(file_metadata_table).values(batch))
                    batch = []
            if batch:
                connection.execute(insert(file_metadata_table).values(batch))
            connection.commit()


class JDBCConnector(DatabaseConnector):
    def __init__(self, db_url: str, db_properties: dict, spark: SparkSession):
        self.db_url = db_url
        self.db_properties = db_properties
        self.spark = spark

    @staticmethod
    def get_table_name():
        return "file_metadata"

    def get_processed_files(self):
        return self.spark.read.jdbc(self.db_url, self.get_table_name(), properties=self.db_properties).select("path")

    def get_not_processed_files(self, file_paths: list[str]):
        # TODO: is there a better way?
        processed_files_df = self.get_processed_files()
        file_paths_df = self.spark.createDataFrame(file_paths, "string").toDF("path")
        not_processed_files_df = file_paths_df.join(processed_files_df, on="path", how="left_anti")
        not_processed_files_list = not_processed_files_df.select("path").rdd.flatMap(lambda x: x).collect()
        return not_processed_files_list

    def save_metadata(self, metadata_df):
        metadata_df.write.jdbc(
            url=self.db_url,
            table=self.get_table_name(),
            mode="append",
            properties=self.db_properties,
        )
