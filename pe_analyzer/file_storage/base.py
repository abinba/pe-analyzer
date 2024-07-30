from abc import ABC


class FileObjectStorage(ABC):
    def list_files(self, prefix: str) -> list[str]:
        raise NotImplementedError

    def download_file(self, key: str) -> bytes:
        raise NotImplementedError
