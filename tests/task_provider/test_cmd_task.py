from unittest.mock import Mock
from pe_analyzer.db.connector import DatabaseConnector
from pe_analyzer.file_storage.base import FileObjectStorage
from pe_analyzer.task_provider.cmd_task import CommandLineTaskProvider


def test_get_file_paths():
    n = 4
    clean_files_all = ["0/file1.exe", "0/file2.exe", "0/file3.exe", "0/file4.exe"]
    malware_files_all = ["1/file1.exe", "1/file2.exe", "1/file3.exe", "1/file4.exe"]
    clean_files_unprocessed = ["0/file1.exe", "0/file2.exe"]
    malware_files_unprocessed = ["1/file1.exe", "1/file2.exe"]

    mock_file_storage_handler = Mock(spec=FileObjectStorage)
    mock_file_storage_handler.list_files.side_effect = [clean_files_all, malware_files_all]

    mock_database = Mock(spec=DatabaseConnector)
    mock_database.get_not_processed_files.side_effect = [clean_files_unprocessed, malware_files_unprocessed]

    task_provider = CommandLineTaskProvider(n, mock_file_storage_handler, mock_database)

    result = task_provider.get_file_paths()

    expected_result = clean_files_unprocessed[: n // 2] + malware_files_unprocessed[: n // 2]

    assert result == expected_result
    mock_file_storage_handler.list_files.assert_any_call("0/")
    mock_file_storage_handler.list_files.assert_any_call("1/")
    mock_database.get_not_processed_files.assert_any_call(clean_files_all)
    mock_database.get_not_processed_files.assert_any_call(malware_files_all)


def test_get_file_paths_less_files():
    n = 4
    clean_files_all = ["0/file1.exe"]
    malware_files_all = ["1/file1.exe"]
    clean_files_unprocessed = ["0/file1.exe"]
    malware_files_unprocessed = ["1/file1.exe"]

    mock_file_storage_handler = Mock(spec=FileObjectStorage)
    mock_file_storage_handler.list_files.side_effect = [clean_files_all, malware_files_all]

    mock_database = Mock(spec=DatabaseConnector)
    mock_database.get_not_processed_files.side_effect = [clean_files_unprocessed, malware_files_unprocessed]

    task_provider = CommandLineTaskProvider(n, mock_file_storage_handler, mock_database)

    result = task_provider.get_file_paths()

    expected_result = clean_files_unprocessed + malware_files_unprocessed

    assert result == expected_result
    mock_file_storage_handler.list_files.assert_any_call("0/")
    mock_file_storage_handler.list_files.assert_any_call("1/")
    mock_database.get_not_processed_files.assert_any_call(clean_files_all)
    mock_database.get_not_processed_files.assert_any_call(malware_files_all)


def test_get_file_paths_no_files():
    n = 4
    clean_files_all = []
    malware_files_all = []
    clean_files_unprocessed = []
    malware_files_unprocessed = []

    mock_file_storage_handler = Mock(spec=FileObjectStorage)
    mock_file_storage_handler.list_files.side_effect = [clean_files_all, malware_files_all]

    mock_database = Mock(spec=DatabaseConnector)
    mock_database.get_not_processed_files.side_effect = [clean_files_unprocessed, malware_files_unprocessed]

    task_provider = CommandLineTaskProvider(n, mock_file_storage_handler, mock_database)

    result = task_provider.get_file_paths()

    expected_result = []

    assert result == expected_result
    mock_file_storage_handler.list_files.assert_any_call("0/")
    mock_file_storage_handler.list_files.assert_any_call("1/")
    mock_database.get_not_processed_files.assert_any_call(clean_files_all)
    mock_database.get_not_processed_files.assert_any_call(malware_files_all)
