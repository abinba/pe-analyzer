import boto3
import botocore.exceptions

from pe_analyzer.file_storage.base import FileObjectStorage


class S3ObjectStorage(FileObjectStorage):
    def __init__(
        self,
        region_name: str,
        bucket_name: str,
        aws_access_key_id: str = "",
        aws_secret_access_key: str = "",
        public_bucket: bool = True,
    ):
        self.region_name = region_name
        self.bucket_name = bucket_name
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.public_bucket = public_bucket

    # TODO: find a better way to manage boto3 client, now it's required for pickling to work correctly
    def get_s3_client(self):
        s3_client = boto3.client(
            "s3",
            region_name=self.region_name,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
        )

        if self.public_bucket:
            # Signing is not required for public buckets
            s3_client._request_signer.sign = lambda *args, **kwargs: None

        return s3_client

    def list_files(self, prefix: str) -> list[str]:
        try:
            s3_client = self.get_s3_client()
            response = s3_client.list_objects_v2(Bucket=self.bucket_name, Prefix=prefix)
            return [obj["Key"] for obj in response.get("Contents", [])]
        except botocore.exceptions.EndpointConnectionError as err:
            raise ConnectionError(f"Failed to connect to endpoint for listing files with prefix {prefix}") from err

    def download_file(self, key: str) -> bytes:
        try:
            s3_client = self.get_s3_client()
            obj = s3_client.get_object(Bucket=self.bucket_name, Key=key)
            return obj["Body"].read()
        except botocore.exceptions.ClientError as err:
            raise FileNotFoundError(f"File not found: {key}") from err
        except botocore.exceptions.EndpointConnectionError as err:
            raise ConnectionError(f"Failed to connect to endpoint to download file with key: {key}") from err
