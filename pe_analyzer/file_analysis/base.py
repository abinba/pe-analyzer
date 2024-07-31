from abc import ABC, abstractmethod
from typing import Optional


class PEHandler(ABC):
    def __enter__(self):
        raise NotImplementedError

    @abstractmethod
    def set_contents(self, file_content: bytes):
        raise NotImplementedError

    @property
    def architecture(self) -> str:
        raise NotImplementedError

    @property
    def imports(self) -> int:
        raise NotImplementedError

    @property
    def exports(self) -> int:
        raise NotImplementedError

    @property
    def file_type(self) -> Optional[str]:
        raise NotImplementedError

    def __exit__(self, exc_type, exc_val, exc_tb):
        raise NotImplementedError
