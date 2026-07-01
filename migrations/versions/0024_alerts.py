"""alerts (ESET detections)

Revision ID: 0024
Revises: 0023
Create Date: 2026-07-01
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("external_id", sa.String(128), nullable=False, unique=True, index=True),
        sa.Column("source", sa.String(50), server_default="eset"),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("device_uuid", sa.String(128)),
        sa.Column("device_name", sa.String(255)),
        sa.Column("severity", sa.String(30), index=True),
        sa.Column("severity_score", sa.Integer()),
        sa.Column("threat", sa.String(500)),
        sa.Column("type_name", sa.String(200)),
        sa.Column("category", sa.String(120)),
        sa.Column("resolved", sa.Boolean(), server_default=sa.text("false"), index=True),
        sa.Column("occurred_at", sa.DateTime(), index=True),
        sa.Column("user_name", sa.String(200)),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("alerts")
