"""assets.is_archived

Revision ID: 0015
Revises: 0014
Create Date: 2026-06-11
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("is_archived", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.create_index("ix_assets_is_archived", "assets", ["is_archived"])


def downgrade() -> None:
    op.drop_index("ix_assets_is_archived", "assets")
    op.drop_column("assets", "is_archived")
