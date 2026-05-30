"""ip_networks Tabelle + assets.network_id

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-30
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ip_networks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("cidr", sa.String(50), nullable=False, unique=True),
        # z.B. "192.168.178.0/24", "10.0.0.0/8"
        sa.Column("description", sa.Text()),
        sa.Column("exposure_level", sa.String(20), server_default="INTERN"),
        sa.Column("color", sa.String(20)),   # Farbe für UI (#hex)
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
    )

    op.add_column(
        "assets",
        sa.Column("network_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("ip_networks.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_assets_network_id", "assets", ["network_id"])


def downgrade() -> None:
    op.drop_index("ix_assets_network_id", "assets")
    op.drop_column("assets", "network_id")
    op.drop_table("ip_networks")
