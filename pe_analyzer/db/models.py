from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer


class Base(DeclarativeBase):
    pass


class FileMetadata(Base):
    __tablename__ = "file_metadata"

    # In case of horizontal scaling, we could use UUIDs instead of integers
    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    file_type: Mapped[str] = mapped_column(String, nullable=True)
    # TODO: use enum for x32, x64
    architecture: Mapped[str] = mapped_column(String, nullable=True)
    num_imports: Mapped[int] = mapped_column(Integer, nullable=True)
    num_exports: Mapped[int] = mapped_column(Integer, nullable=True)

    def __repr__(self) -> str:
        return f"FileMetadata(id={self.id!r}, path={self.path!r}, file_type={self.file_type!r})"
