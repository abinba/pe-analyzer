import logging

from pe_analyzer.db.connector import DatabaseConnector
from pe_analyzer.file_storage.base import FileObjectStorage
from pe_analyzer.task_provider.base import TaskProvider

logger = logging.getLogger(__name__)


class CommandLineTaskProvider(TaskProvider):
    """
    Provider that takes integer N that represents number of files to process from command line arguments.
    """

    def __init__(
        self,
        n: int,
        file_storage_handler: FileObjectStorage,
        database: DatabaseConnector,
    ):
        self.n = n
        self.file_storage_handler = file_storage_handler
        self.database = database

    def get_file_paths(self) -> list[str]:
        """
        1) Get clean and malware files list from storage
        2) Filter them to only ones that were not processed by filtering out processed ones
        3) Limit to (n / 2) for each: malware and clean
        4) Combine them and return
        """
        all_clean_files = self.file_storage_handler.list_files("0/")
        all_malware_files = self.file_storage_handler.list_files("1/")

        # TODO: we could use async here to make it a bit faster
        # TODO: consider using bloom filter
        clean_files = self.database.get_not_processed_files(all_clean_files)[: self.n // 2]
        malware_files = self.database.get_not_processed_files(all_malware_files)[: self.n // 2]

        logger.info(f"Found {len(clean_files)} clean files and {len(malware_files)} malware files.")

        return clean_files + malware_files
