"""cve_entries.is_kev + kev_due_date

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-31
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("cve_entries", sa.Column("is_kev", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("cve_entries", sa.Column("kev_due_date", sa.String(20), nullable=True))
    op.add_column("cve_entries", sa.Column("kev_ransomware", sa.Boolean(), server_default="false", nullable=False))
    op.create_index("ix_cve_entries_is_kev", "cve_entries", ["is_kev"])


def downgrade() -> None:
    op.drop_index("ix_cve_entries_is_kev", "cve_entries")
    op.drop_column("cve_entries", "kev_ransomware")
    op.drop_column("cve_entries", "kev_due_date")
    op.drop_column("cve_entries", "is_kev")
