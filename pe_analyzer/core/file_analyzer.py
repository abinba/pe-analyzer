from pe_analyzer.file_analysis.base import PEHandler
from pe_analyzer.file_storage.base import FileObjectStorage
from pe_analyzer.core.schema import FileMetadataContainer
from pe_analyzer.core.utils import get_file_type


def analyze_pe_file(
    path: str,
    file_storage_handler: FileObjectStorage,
    pe_file_handler: PEHandler,
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
    pe_file_handler.set_contents(file_content)

    try:
        with pe_file_handler as pe_file:
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
