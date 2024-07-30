import pefile

from pe_analyzer.file_analysis.base import PEHandler
from pe_analyzer.file_analysis.exceptions import PEFileNotSetException


class PEFileHandler(PEHandler):
    def __init__(self):
        self.pe = None
        self.file_content: bytes | None = None

    def __enter__(self):
        if not self.file_content:
            raise PEFileNotSetException("PE file contents not set.")
        self.pe = pefile.PE(data=self.file_content)
        return self

    def set_contents(self, file_content: bytes):
        self.file_content = file_content

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
        return (
            len(self.pe.DIRECTORY_ENTRY_EXPORT.symbols)
            if (hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT") and self.pe.DIRECTORY_ENTRY_EXPORT)
            else 0
        )

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.pe.close()
