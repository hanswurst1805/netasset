"""assets.is_obsolete -> assets.is_archived (rename)

Revision ID: 0016
Revises: 0015
Create Date: 2026-06-11
"""

from typing import Sequence, Union

from alembic import op

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column("assets", "is_obsolete", new_column_name="is_archived")
    op.execute("ALTER INDEX ix_assets_is_obsolete RENAME TO ix_assets_is_archived")


def downgrade() -> None:
    op.alter_column("assets", "is_archived", new_column_name="is_obsolete")
    op.execute("ALTER INDEX ix_assets_is_archived RENAME TO ix_assets_is_obsolete")
