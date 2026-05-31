"""asset_snapshots

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-30
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("data", postgresql.JSONB(), nullable=False),   # vollständiger Zustand
        sa.Column("diff", postgresql.JSONB(), nullable=True),    # Änderungen zum Vortag
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.UniqueConstraint("asset_id", "snapshot_date", name="uq_snapshot_asset_date"),
    )
    op.create_index("ix_snapshots_asset_date", "asset_snapshots",
                    ["asset_id", "snapshot_date"])


def downgrade() -> None:
    op.drop_table("asset_snapshots")
