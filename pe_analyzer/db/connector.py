from abc import ABC, abstractmethod
import logging
from typing import Iterable

from pyspark import Row
from sqlalchemy import create_engine, select, Table, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert

from pe_analyzer.db.models import FileMetadata

logger = logging.getLogger(__name__)


class DatabaseConnector(ABC):
    @abstractmethod
    def get_not_processed_files(self, file_paths: list[str]) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def save_metadata(self, metadata_list: Iterable[Row]) -> None:
        raise NotImplementedError


class SQLAlchemyConnector(DatabaseConnector):
    def __init__(self, db_url: str, batch_size: int):
        self.db_url = db_url
        self.batch_size = batch_size

    def get_engine(self):
        return create_engine(self.db_url)

    @staticmethod
    def get_table_name():
        return "file_metadata"

    def get_not_processed_files(self, file_paths: list[str]) -> list[str]:
        """
        Returns a list of file paths that are not yet processed

        :param file_paths: List of file paths to check
        """
        SessionLocal = sessionmaker(bind=self.get_engine())

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
                row_dict = row.asDict()
                if row_dict["error"]:
                    logger.warning(f"Error processing {row_dict['path']}: {row_dict['error']}")
                del row_dict["error"]
                batch.append(row_dict)
                if len(batch) >= self.batch_size:
                    connection.execute(insert(file_metadata_table).values(batch))
                    batch = []
            if batch:
                connection.execute(insert(file_metadata_table).values(batch))
            connection.commit()
