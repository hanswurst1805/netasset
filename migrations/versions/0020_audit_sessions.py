"""audit_sessions

Revision ID: 0020
Revises: 0019
Create Date: 2026-06-15
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("session_uuid", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("operator", sa.String(120), nullable=False),
        sa.Column("jumpbox_host", sa.String(255)),
        sa.Column("target_host", sa.String(255), nullable=False, index=True),
        sa.Column("target_user", sa.String(120)),
        sa.Column("target_asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("started_at", sa.DateTime()),
        sa.Column("ended_at", sa.DateTime()),
        sa.Column("duration_sec", sa.Integer()),
        sa.Column("exit_code", sa.Integer()),
        sa.Column("recording_format", sa.String(30), server_default="script-typescript"),
        sa.Column("recording", sa.Text()),
        sa.Column("timing", sa.Text()),
        sa.Column("client_ip", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
    )

    op.create_table(
        "audit_session_commands",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("audit_sessions.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("executed_at", sa.DateTime()),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("cwd", sa.String(500)),
        sa.Column("os_user", sa.String(120)),
        sa.UniqueConstraint("session_id", "seq", name="uq_audit_cmd_session_seq"),
    )


def downgrade() -> None:
    op.drop_table("audit_session_commands")
    op.drop_table("audit_sessions")
