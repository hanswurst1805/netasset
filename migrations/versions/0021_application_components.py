"""application_components

Revision ID: 0021
Revises: 0020
Create Date: 2026-06-17
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "application_components",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("application_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("match_kind", sa.String(20), server_default="name"),
        sa.Column("match_value", sa.String(500), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("origin", sa.String(20), server_default="manual"),
        sa.Column("confirmed", sa.Boolean(), server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.UniqueConstraint("application_id", "match_kind", "match_value", "asset_id",
                            name="uq_app_component"),
    )


def downgrade() -> None:
    op.drop_table("application_components")
