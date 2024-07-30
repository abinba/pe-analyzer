import pytest
from unittest.mock import Mock, patch, PropertyMock

import pefile

from pe_analyzer.file_analysis.pe_file_handler import PEFileHandler
from pe_analyzer.file_analysis.exceptions import PEFileNotSetException


@patch("pefile.PE")
def test_pe_file_handler_success(mock_pe):
    file_content = b"fake PE file content"
    mock_pe_instance = mock_pe.return_value
    type(mock_pe_instance.FILE_HEADER).Machine = PropertyMock(
        return_value=pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]
    )
    type(mock_pe_instance).DIRECTORY_ENTRY_IMPORT = PropertyMock(return_value=[Mock(imports=["imp1", "imp2"])])
    type(mock_pe_instance).DIRECTORY_ENTRY_EXPORT = PropertyMock(return_value=Mock(symbols=["exp1", "exp2"]))

    handler = PEFileHandler()
    handler.set_contents(file_content)

    with handler as h:
        assert h.architecture == "x32"
        assert h.imports == 2
        assert h.exports == 2

    mock_pe.assert_called_once_with(data=file_content)
    mock_pe_instance.close.assert_called_once()


def test_pe_file_handler_no_content():
    handler = PEFileHandler()

    with pytest.raises(PEFileNotSetException, match="PE file contents not set."):
        with handler:
            pass


@patch("pefile.PE")
def test_pe_file_handler_missing_imports_exports(mock_pe):
    file_content = b"fake PE file content"
    mock_pe_instance = mock_pe.return_value
    type(mock_pe_instance.FILE_HEADER).Machine = PropertyMock(
        return_value=pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]
    )
    type(mock_pe_instance).DIRECTORY_ENTRY_IMPORT = PropertyMock(return_value=[])
    type(mock_pe_instance).DIRECTORY_ENTRY_EXPORT = PropertyMock(return_value=None)

    handler = PEFileHandler()
    handler.set_contents(file_content)

    with handler as h:
        assert h.architecture == "x32"
        assert h.imports == 0
        assert h.exports == 0

    mock_pe.assert_called_once_with(data=file_content)
    mock_pe_instance.close.assert_called_once()
