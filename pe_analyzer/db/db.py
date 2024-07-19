from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from pe_analyzer.db.models import FileMetadata


class Database:
    def __init__(self, db_url):
        self.engine = create_engine(db_url)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def get_processed_files(self):
        with self.SessionLocal() as session:
            return [row.path for row in session.execute(select(FileMetadata.path)).scalars()]

    def save_metadata(self, metadata_list):
        with self.SessionLocal() as session:
            for metadata in metadata_list:
                file_metadata = FileMetadata(**metadata)
                session.merge(file_metadata)
            session.commit()
