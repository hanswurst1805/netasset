"""applications + owner-fk fix

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-29
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "applications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("app_type", sa.String(50)),
        sa.Column("version", sa.String(100)),
        sa.Column("url", sa.String(500)),
        sa.Column("process_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("business_processes.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("owners.id", ondelete="SET NULL"), nullable=True),
        sa.Column("criticality", sa.Integer()),
        sa.Column("asset_ids", postgresql.JSONB()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("applications")
