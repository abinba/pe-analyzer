import os

from pydantic import DirectoryPath
from pydantic_settings import BaseSettings


class DatabaseSettings(BaseSettings):
    db_protocol: str = "postgresql"
    db_user: str = "postgres"
    db_name: str = "metadata_db"
    db_port: int = 5432
    db_host: str = "localhost"
    db_password: str

    isolation_level: str = "READ COMMITTED"
    pool_size: int = 30
    pool_pre_ping: bool = False
    pool_recycle: int = 600
    max_overflow: int = 10
    auto_flush: bool = False
    expire_on_commit: bool = False

    class Config:
        extra = "allow"


class AppSettings(BaseSettings):
    debug: bool = False

    base_dir: DirectoryPath = os.path.dirname(os.path.abspath(__file__))

    logging_level: str = "INFO"

    database: DatabaseSettings = DatabaseSettings(_env_file="db.env", _env_file_encoding="utf-8")

    s3_bucket: str = "s3-nord-challenge-data"
    s3_region: str = "eu-central-1"

    def get_database_uri(self):
        return (
            f"{self.database.db_protocol}://"
            f"{self.database.db_user}:{self.database.db_password}@"
            f"{self.database.db_host}:{self.database.db_port}/{self.database.db_name}"
        )

    class Config:
        extra = "allow"


settings = AppSettings(_env_file=".env", _env_file_encoding="utf-8")
