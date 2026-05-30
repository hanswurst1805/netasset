"""conflict_queue Tabelle

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "conflict_queue",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("incoming_data", postgresql.JSONB(), nullable=False),
        sa.Column("source", sa.String(100)),
        sa.Column("confidence", sa.Float()),
        sa.Column("matched_on", postgresql.ARRAY(sa.String())),
        sa.Column("candidate_asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("resolved_by", sa.String(200)),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_conflict_queue_status", "conflict_queue", ["status"])


def downgrade() -> None:
    op.drop_table("conflict_queue")
