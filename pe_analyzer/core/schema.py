from dataclasses import dataclass
from typing import Optional

from pyspark.sql.types import StructType, StructField, StringType, LongType, IntegerType


@dataclass
class FileMetadataContainer:
    path: str
    file_size: Optional[int]
    file_type: Optional[str]
    arch: Optional[str]
    import_count: Optional[int]
    export_count: Optional[int]

    def to_tuple(self):
        return (
            self.path,
            self.file_size,
            self.file_type,
            self.arch,
            self.import_count,
            self.export_count,
        )

    @classmethod
    def get_spark_schema(cls):
        return StructType(
            [
                StructField("path", StringType(), nullable=False),
                StructField("size", LongType(), nullable=False),
                StructField("file_type", StringType(), nullable=True),
                StructField("architecture", StringType(), nullable=True),
                StructField("num_imports", IntegerType(), nullable=True),
                StructField("num_exports", IntegerType(), nullable=True),
            ]
        )
