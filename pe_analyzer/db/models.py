from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer


class Base(DeclarativeBase):
    pass


class FileMetadata(Base):
    __tablename__ = "file_metadata"

    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    file_type: Mapped[str] = mapped_column(String, nullable=False)
    architecture: Mapped[str] = mapped_column(String, nullable=False)
    num_imports: Mapped[int] = mapped_column(Integer, nullable=False)
    num_exports: Mapped[int] = mapped_column(Integer, nullable=False)

    def __repr__(self) -> str:
        return f"FileMetadata(id={self.id!r}, path={self.path!r}, file_type={self.file_type!r})"
