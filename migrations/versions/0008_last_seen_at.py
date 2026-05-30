"""assets.last_seen_at

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-30
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column(
            "last_seen_at",
            sa.DateTime(),
            nullable=True,
            server_default=sa.text("now()"),
        ),
    )
    # Bestehende Assets: last_seen_at = updated_at
    op.execute("UPDATE assets SET last_seen_at = updated_at")


def downgrade() -> None:
    op.drop_column("assets", "last_seen_at")
