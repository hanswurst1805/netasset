"""initial schema – alle OBASHI-Schichten

Revision ID: 0001
Revises:
Create Date: 2026-05-29
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # pgvector Extension
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # O – Owners
    op.create_table(
        "owners",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("email", sa.String(200)),
        sa.Column("team", sa.String(200)),
        sa.Column("department", sa.String(200)),
        sa.Column("role", sa.String(100)),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
    )

    # H – Assets (Hardware + S-Layer)
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mac_address", sa.String(50), index=True),
        sa.Column("serial_number", sa.String(200), index=True),
        sa.Column("chassis_id", sa.String(200)),
        sa.Column("hostname", sa.String(300), index=True),
        sa.Column("ip_address", sa.String(50), index=True),
        sa.Column("fqdn", sa.String(500)),
        sa.Column("asset_type", sa.String(50), nullable=False, server_default="server"),
        sa.Column("os_name", sa.String(100)),
        sa.Column("os_version", sa.String(100)),
        sa.Column("os_arch", sa.String(50)),
        sa.Column("manufacturer", sa.String(200)),
        sa.Column("model", sa.String(200)),
        sa.Column("firmware_version", sa.String(100)),
        sa.Column("exposure_level", sa.String(20), nullable=False, server_default="INTERN"),
        sa.Column("open_ports", postgresql.JSONB()),
        sa.Column("rack_id", sa.String(200)),
        sa.Column("rack_unit", sa.Integer()),
        sa.Column("location", sa.String(300)),
        sa.Column("tags", postgresql.ARRAY(sa.String())),
        sa.Column("sources", postgresql.JSONB()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()")),
    )

    # B – Business Processes
    op.create_table(
        "business_processes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("criticality", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("sla_rto_hours", sa.Integer()),
        sa.Column("sla_rpo_hours", sa.Integer()),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("owners.id")),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
    )

    # B↔H – Process-Asset Verknüpfung
    op.create_table(
        "process_assets",
        sa.Column("process_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("business_processes.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("role", sa.String(100)),
    )

    # A – SBOM
    op.create_table(
        "sbom_entries",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("pkg_name", sa.String(300), nullable=False),
        sa.Column("pkg_version", sa.String(100), nullable=False),
        sa.Column("pkg_type", sa.String(50)),
        sa.Column("cpe", sa.String(500)),
        sa.Column("purl", sa.String(500)),
        sa.Column("source", sa.String(100)),
        sa.Column("scanned_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.UniqueConstraint("asset_id", "pkg_name", "pkg_version", name="uq_sbom_asset_pkg_ver"),
    )

    # I – Port Scans
    op.create_table(
        "port_scans",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(10), server_default="tcp"),
        sa.Column("state", sa.String(20)),
        sa.Column("service", sa.String(100)),
        sa.Column("version", sa.String(200)),
        sa.Column("scanned_from", sa.String(50)),
        sa.Column("scanned_at", sa.DateTime(), server_default=sa.text("now()")),
    )

    # CVE-Einträge mit pgvector
    op.create_table(
        "cve_entries",
        sa.Column("cve_id", sa.String(50), primary_key=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cvss_score", sa.Float()),
        sa.Column("cvss_vector", sa.String(200)),
        sa.Column("attack_vector", sa.String(50)),
        sa.Column("severity", sa.String(20)),
        sa.Column("affected_pkgs", postgresql.JSONB()),
        sa.Column("published_at", sa.DateTime()),
        sa.Column("modified_at", sa.DateTime()),
        sa.Column("embedding", sa.types.UserDefinedType(), nullable=True),
        sa.Column("raw", postgresql.JSONB()),
    )
    # Vector-Spalte manuell (pgvector Typ)
    op.execute("ALTER TABLE cve_entries ALTER COLUMN embedding TYPE vector(384) USING embedding::vector(384)")

    # HNSW-Index für schnelle Cosine-Similarity-Suche
    op.execute("CREATE INDEX cve_embedding_hnsw ON cve_entries USING hnsw (embedding vector_cosine_ops)")

    # CVE-Impact (gecacht)
    op.create_table(
        "cve_impact",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(50), sa.ForeignKey("cve_entries.cve_id")),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id")),
        sa.Column("risk_level", sa.String(20)),
        sa.Column("risk_score", sa.Float()),
        sa.Column("reasoning", sa.Text()),
        sa.Column("affected_pkg", sa.String(300)),
        sa.Column("affected_ver", sa.String(100)),
        sa.Column("computed_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.UniqueConstraint("cve_id", "asset_id", name="uq_cve_impact_cve_asset"),
    )


def downgrade() -> None:
    op.drop_table("cve_impact")
    op.drop_table("cve_entries")
    op.drop_table("port_scans")
    op.drop_table("sbom_entries")
    op.drop_table("process_assets")
    op.drop_table("business_processes")
    op.drop_table("assets")
    op.drop_table("owners")
