import os
from abc import ABC
from typing import Type

import pefile

from pe_analyzer.exceptions import InvalidPEFileHandlerException
from pe_analyzer.file_storage import FileObjectStorage
from pe_analyzer.schema import FileMetadataContainer


class PEHandler(ABC):
    def __init__(self, file_content: bytes):
        self.file_content = file_content

    def __enter__(self):
        raise NotImplementedError

    @property
    def architecture(self) -> str:
        raise NotImplementedError

    @property
    def imports(self) -> int:
        raise NotImplementedError

    @property
    def exports(self) -> int:
        raise NotImplementedError

    def __exit__(self, exc_type, exc_val, exc_tb):
        raise NotImplementedError


class PEFileHandler(PEHandler):
    def __init__(self, file_content: bytes):
        super().__init__(file_content)
        self.pe = pefile.PE(data=self.file_content)

    def __enter__(self):
        return self

    @property
    def architecture(self) -> str:
        return "x32" if self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"] else "x64"

    @property
    def imports(self) -> int:
        return (
            sum(len(entry.imports) for entry in self.pe.DIRECTORY_ENTRY_IMPORT)
            if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT")
            else 0
        )

    @property
    def exports(self) -> int:
        return len(self.pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT") else 0

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.pe.close()


PE_FILE_HANDLER_METHODS: dict[str, Type[PEHandler]] = {
    "PEFileHandler": PEFileHandler,
}


def analyze_pe_file(
    path: str,
    file_storage_handler: FileObjectStorage,
    pe_file_handler_method: str = "PEFileHandler",
) -> tuple:
    file_type: str = get_file_type(path)

    try:
        file_content: bytes = file_storage_handler.download_file(path)
    except ConnectionError as err:
        # TODO: Retry if failed to connect to endpoint or "mark_for_retry"
        return FileMetadataContainer(
            path=path,
            file_size=None,
            file_type=file_type,
            arch=None,
            import_count=None,
            export_count=None,
            error=str(err),
        ).to_tuple()

    file_size = len(file_content)
    file_handler_method = PE_FILE_HANDLER_METHODS.get(pe_file_handler_method)

    if file_handler_method is None:
        raise InvalidPEFileHandlerException(f"Invalid PE file handler method: {pe_file_handler_method}")

    try:
        with file_handler_method(file_content) as pe_file:
            return FileMetadataContainer(
                path=path,
                file_size=file_size,
                file_type=file_type,
                arch=pe_file.architecture,
                import_count=pe_file.imports,
                export_count=pe_file.exports,
                error=None,
            ).to_tuple()
    except Exception as err:
        return FileMetadataContainer(
            path=path,
            file_size=file_size,
            file_type=file_type,
            arch=None,
            import_count=None,
            export_count=None,
            error=str(err),
        ).to_tuple()


def get_file_type(file_path: str) -> str:
    _, file_type = os.path.splitext(file_path)
    file_type = file_type.lstrip(".").lower()
    return file_type
