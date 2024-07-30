from unittest.mock import Mock, patch, MagicMock

from pe_analyzer.file_analysis.base import PEHandler
from pe_analyzer.file_storage.base import FileObjectStorage
from pe_analyzer.core.schema import FileMetadataContainer
from pe_analyzer.core.file_analyzer import analyze_pe_file


class MockPEHandler(Mock):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


def test_analyze_pe_file_success():
    path = "test.exe"
    file_content = b"fake content"

    mock_file_storage_handler = Mock(spec=FileObjectStorage)
    mock_file_storage_handler.download_file.return_value = file_content

    mock_pe_file_handler = MockPEHandler(spec=PEHandler)
    mock_pe_file_handler.architecture = "x64"
    mock_pe_file_handler.imports = 5
    mock_pe_file_handler.exports = 3

    with patch("pe_analyzer.core.file_analyzer.get_file_type", return_value="exe"):
        result = analyze_pe_file(path, mock_file_storage_handler, mock_pe_file_handler)

    expected_result = FileMetadataContainer(
        path=path,
        file_size=len(file_content),
        file_type="exe",
        arch="x64",
        import_count=5,
        export_count=3,
        error=None,
    ).to_tuple()

    assert result == expected_result
    mock_file_storage_handler.download_file.assert_called_once_with(path)
    mock_pe_file_handler.set_contents.assert_called_once_with(file_content)


def test_analyze_pe_file_download_error():
    path = "test.exe"

    mock_file_storage_handler = Mock(spec=FileObjectStorage)
    mock_file_storage_handler.download_file.side_effect = ConnectionError("Failed to connect")

    mock_pe_file_handler = MockPEHandler(spec=PEHandler)

    with patch("pe_analyzer.core.file_analyzer.get_file_type", return_value="exe"):
        result = analyze_pe_file(path, mock_file_storage_handler, mock_pe_file_handler)

    expected_result = FileMetadataContainer(
        path=path,
        file_size=None,
        file_type="exe",
        arch=None,
        import_count=None,
        export_count=None,
        error="Failed to connect",
    ).to_tuple()

    assert result == expected_result
    mock_file_storage_handler.download_file.assert_called_once_with(path)
    mock_pe_file_handler.set_contents.assert_not_called()


def test_analyze_pe_file_open_error():
    path = "test.exe"
    file_content = b"fake content"

    mock_file_storage_handler = Mock(spec=FileObjectStorage)
    mock_file_storage_handler.download_file.return_value = file_content

    mock_pe_file_handler = MockPEHandler(spec=PEHandler)
    mock_pe_file_handler.__enter__ = MagicMock(side_effect=Exception("Failed to open file"))

    with patch("pe_analyzer.core.file_analyzer.get_file_type", return_value="exe"):
        result = analyze_pe_file(path, mock_file_storage_handler, mock_pe_file_handler)

    expected_result = FileMetadataContainer(
        path=path,
        file_size=len(file_content),
        file_type="exe",
        arch=None,
        import_count=None,
        export_count=None,
        error="Failed to open file",
    ).to_tuple()

    assert result == expected_result
    mock_file_storage_handler.download_file.assert_called_once_with(path)
    mock_pe_file_handler.set_contents.assert_called_once_with(file_content)
