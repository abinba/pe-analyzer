import logging
import os
from dataclasses import dataclass
from typing import Optional

import pefile

logger = logging.getLogger(__name__)


@dataclass
class FileMetadataContext:
    file_path: str
    file_size: int
    file_type: str
    arch: Optional[str]
    import_count: Optional[int]
    export_count: Optional[int]

    def to_tuple(self):
        return (self.file_path, self.file_size, self.file_type, self.arch, self.import_count, self.export_count)


class FileAnalyzer:
    @staticmethod
    def analyze_pe_file(file_path: str) -> FileMetadataContext:
        file_type = file_path.split(".")[-1].lower() if "." in file_path else None
        file_size = os.path.getsize(file_path)

        try:
            pe = pefile.PE(file_path, fast_load=True)
            arch = "x32" if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"] else "x64"

            import_count = (
                sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
                else 0
            )
            export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0

            return FileMetadataContext(file_path, file_size, file_type, arch, import_count, export_count)
        except Exception as e:
            logger.error(f"Error processing {file_path}: {str(e)}")

            return FileMetadataContext(file_path, file_size, file_type, None, None, None)
        finally:
            if "pe" in locals():
                pe.close()
