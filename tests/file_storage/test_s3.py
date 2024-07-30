import pytest

from unittest.mock import Mock, patch
from botocore.exceptions import EndpointConnectionError, ClientError
from pe_analyzer.file_storage.s3 import S3ObjectStorage


def mock_boto3_client(public_bucket=True):
    s3_client = Mock()
    if public_bucket:
        s3_client._request_signer.sign = lambda *args, **kwargs: None
    return s3_client


@pytest.fixture
def s3_object_storage():
    return S3ObjectStorage(
        region_name="us-east-1",
        bucket_name="test-bucket",
        aws_access_key_id="fake-access-key",
        aws_secret_access_key="fake-secret-key",
        public_bucket=True,
    )


@patch("boto3.client", return_value=mock_boto3_client())
def test_list_files_success(mock_boto3, s3_object_storage):
    mock_s3_client = mock_boto3()
    mock_s3_client.list_objects_v2.return_value = {
        "Contents": [
            {"Key": "file1.txt"},
            {"Key": "file2.txt"},
        ]
    }

    with patch.object(s3_object_storage, "get_s3_client", return_value=mock_s3_client):
        files = s3_object_storage.list_files("prefix/")

    assert files == ["file1.txt", "file2.txt"]
    mock_s3_client.list_objects_v2.assert_called_once_with(Bucket="test-bucket", Prefix="prefix/")


@patch("boto3.client", return_value=mock_boto3_client())
def test_list_files_connection_error(mock_boto3, s3_object_storage):
    mock_s3_client = mock_boto3()
    mock_s3_client.list_objects_v2.side_effect = EndpointConnectionError(endpoint_url="https://s3.amazonaws.com")

    with patch.object(s3_object_storage, "get_s3_client", return_value=mock_s3_client):
        with pytest.raises(ConnectionError) as exc_info:
            s3_object_storage.list_files("prefix/")

    assert "Failed to connect to endpoint for listing files with prefix prefix/" in str(exc_info.value)
    mock_s3_client.list_objects_v2.assert_called_once_with(Bucket="test-bucket", Prefix="prefix/")


@patch("boto3.client", return_value=mock_boto3_client())
def test_download_file_success(mock_boto3, s3_object_storage):
    mock_s3_client = mock_boto3()
    mock_s3_client.get_object.return_value = {"Body": Mock(read=lambda: b"file content")}

    with patch.object(s3_object_storage, "get_s3_client", return_value=mock_s3_client):
        content = s3_object_storage.download_file("file1.txt")

    assert content == b"file content"
    mock_s3_client.get_object.assert_called_once_with(Bucket="test-bucket", Key="file1.txt")


@patch("boto3.client", return_value=mock_boto3_client())
def test_download_file_not_found_error(mock_boto3, s3_object_storage):
    mock_s3_client = mock_boto3()
    mock_s3_client.get_object.side_effect = ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")

    with patch.object(s3_object_storage, "get_s3_client", return_value=mock_s3_client):
        with pytest.raises(FileNotFoundError) as exc_info:
            s3_object_storage.download_file("file1.txt")

    assert "File not found: file1.txt" in str(exc_info.value)
    mock_s3_client.get_object.assert_called_once_with(Bucket="test-bucket", Key="file1.txt")


@patch("boto3.client", return_value=mock_boto3_client())
def test_download_file_connection_error(mock_boto3, s3_object_storage):
    mock_s3_client = mock_boto3()
    mock_s3_client.get_object.side_effect = EndpointConnectionError(endpoint_url="https://s3.amazonaws.com")

    with patch.object(s3_object_storage, "get_s3_client", return_value=mock_s3_client):
        with pytest.raises(ConnectionError) as exc_info:
            s3_object_storage.download_file("file1.txt")

    assert "Failed to connect to endpoint to download file with key: file1.txt" in str(exc_info.value)
    mock_s3_client.get_object.assert_called_once_with(Bucket="test-bucket", Key="file1.txt")


if __name__ == "__main__":
    pytest.main()
