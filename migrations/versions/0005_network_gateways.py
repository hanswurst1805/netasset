"""network_gateways Tabelle

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-30
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "network_gateways",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("from_segment", sa.String(100), nullable=False),
        sa.Column("to_segment", sa.String(100), nullable=False),
        sa.Column("is_primary", sa.Boolean(), server_default="false"),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
    )
    op.create_index("ix_network_gateways_asset", "network_gateways", ["asset_id"])


def downgrade() -> None:
    op.drop_table("network_gateways")
