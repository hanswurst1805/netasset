"""assets.additional_ips

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-31
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("additional_ips", postgresql.ARRAY(sa.String(50)), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "additional_ips")
