"""services: Listener Port → Prozess → SBOM-Paket

Revision ID: 0023
Revises: 0022
Create Date: 2026-06-18
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("proto", sa.String(10), server_default="tcp"),
        sa.Column("bind_address", sa.String(64)),
        sa.Column("bind_scope", sa.String(16), server_default="lan"),
        sa.Column("process_name", sa.String(200)),
        sa.Column("process_path", sa.String(500)),
        sa.Column("sbom_pkg", sa.String(300)),
        sa.Column("container_name", sa.String(200)),
        sa.Column("container_image", sa.String(300)),
        sa.Column("source", sa.String(100)),
        sa.Column("scanned_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.UniqueConstraint("asset_id", "port", "proto", "bind_address", name="uq_service_asset_port"),
    )


def downgrade() -> None:
    op.drop_table("services")
