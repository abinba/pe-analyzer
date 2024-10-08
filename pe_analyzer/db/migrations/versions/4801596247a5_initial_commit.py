"""initial commit

Revision ID: 4801596247a5
Revises:
Create Date: 2024-07-19 18:26:24.221453

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "4801596247a5"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "file_metadata",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("file_type", sa.String(), nullable=False),
        sa.Column("architecture", sa.String(), nullable=False),
        sa.Column("num_imports", sa.Integer(), nullable=False),
        sa.Column("num_exports", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("path"),
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("file_metadata")
    # ### end Alembic commands ###
