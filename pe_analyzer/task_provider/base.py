from abc import ABC, abstractmethod


class TaskProvider(ABC):
    @abstractmethod
    def get_file_paths(self) -> list[str]:
        raise NotImplementedError
