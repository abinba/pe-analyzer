import boto3
from pe_analyzer.settings import settings


class S3Handler:
    def __init__(self, region_name: str = settings.s3_region, bucket_name: str = settings.s3_bucket):
        self.s3_client = boto3.client("s3", region_name=region_name)
        self.bucket_name = bucket_name

    def list_files(self, prefix: str) -> list[str]:
        response = self.s3_client.list_objects_v2(Bucket=self.bucket_name, Prefix=prefix)
        return [obj["Key"] for obj in response.get("Contents", [])]
