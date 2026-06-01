"""ip_networks.gateway_asset_id

Optionaler Router/Firewall der dieses Netz nach oben verbindet.
Ermöglicht direkte Baumstruktur: Netz → Router → übergeordnetes Netz.

Revision ID: 0013
Revises: 0012
Create Date: 2026-05-31
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ip_networks",
        sa.Column(
            "gateway_asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("ip_networks", "gateway_asset_id")
