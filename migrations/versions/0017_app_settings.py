"""app_settings table

Revision ID: 0017
Revises: 0016
Create Date: 2026-06-11
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hide_vm_microcode_cves", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.execute("INSERT INTO app_settings (id, hide_vm_microcode_cves) VALUES (1, true)")


def downgrade() -> None:
    op.drop_table("app_settings")
