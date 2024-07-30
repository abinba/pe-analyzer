import os


def get_file_type(file_path: str) -> str:
    _, file_type = os.path.splitext(file_path)
    file_type = file_type.lstrip(".").lower()
    return file_type
