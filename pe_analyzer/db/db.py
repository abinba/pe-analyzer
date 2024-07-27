import logging
from typing import TypeAlias

from pyspark import Row
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert as pg_insert

from pe_analyzer.db.models import FileMetadata

logger = logging.getLogger(__name__)

FilePath: TypeAlias = str


class Database:
    def __init__(self, db_url):
        self.engine = create_engine(db_url)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def get_not_processed_files(self, file_paths: list[FilePath]) -> list:
        with self.SessionLocal() as session:
            # Get all the processed files within the list of file_paths
            stmt = select(FileMetadata.path).where(FileMetadata.path.in_(file_paths))
            processed_files = session.scalars(stmt).all()
            logger.info(f"Found {len(processed_files)} processed files.")
        # Exclude the ones that are already processed
        return list(set(file_paths).difference(set(processed_files)))

    def save_metadata(self, metadata_list: list[Row]):
        with self.SessionLocal() as session:
            metadata_dicts = []
            for metadata in metadata_list:
                metadata_dict = metadata.asDict()
                if metadata_dict["error"]:
                    # TODO: output errors somewhere else
                    logger.warning(f"Error processing {metadata_dict['path']}: {metadata_dict['error']}")
                del metadata_dict["error"]
                metadata_dicts.append(metadata_dict)

            stmt = pg_insert(FileMetadata).values(metadata_dicts)
            session.execute(stmt)
            session.commit()
