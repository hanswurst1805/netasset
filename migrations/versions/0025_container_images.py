"""container_images, container_packages, container_vulns

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-08
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0025"
down_revision: Union[str, None] = "0024"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "container_images",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), index=True),
        sa.Column("image_id", sa.String(100), nullable=False),
        sa.Column("image_ref", sa.String(300), nullable=False),
        sa.Column("distro", sa.String(100)),
        sa.Column("containers", postgresql.JSONB()),
        sa.Column("sbom_at", sa.DateTime()),
        sa.Column("osv_at", sa.DateTime()),
        sa.Column("last_seen_at", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint("asset_id", "image_id", name="uq_container_image_asset_image"),
    )
    op.create_table(
        "container_packages",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("image_pk", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("container_images.id", ondelete="CASCADE"), index=True),
        sa.Column("pkg_name", sa.String(300), nullable=False),
        sa.Column("pkg_version", sa.String(200), nullable=False),
        sa.Column("pkg_type", sa.String(50)),
        sa.Column("purl", sa.String(800)),
    )
    op.create_table(
        "container_vulns",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("image_pk", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("container_images.id", ondelete="CASCADE"), index=True),
        sa.Column("vuln_id", sa.String(100), nullable=False),
        sa.Column("osv_id", sa.String(100)),
        sa.Column("pkg_name", sa.String(300), nullable=False),
        sa.Column("pkg_version", sa.String(200), nullable=False),
        sa.Column("ecosystem", sa.String(50)),
        sa.Column("severity", sa.String(20), server_default="UNKNOWN"),
        sa.Column("cvss", sa.Float()),
        sa.Column("fixed_version", sa.String(200)),
        sa.Column("summary", sa.Text()),
    )


def downgrade() -> None:
    op.drop_table("container_vulns")
    op.drop_table("container_packages")
    op.drop_table("container_images")
