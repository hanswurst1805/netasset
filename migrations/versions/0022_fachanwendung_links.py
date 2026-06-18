"""fachanwendung links: process n:m + netz-elemente

Revision ID: 0022
Revises: 0021
Create Date: 2026-06-18
"""

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "process_applications",
        sa.Column("process_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("business_processes.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("application_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_table(
        "application_ip_networks",
        sa.Column("application_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("network_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("ip_networks.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_table(
        "application_gateways",
        sa.Column("application_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("gateway_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("network_gateways.id", ondelete="CASCADE"), primary_key=True),
    )

    # Bestehende 1:n-Zuordnung (applications.process_id) in n:m übernehmen
    op.execute(
        "INSERT INTO process_applications (process_id, application_id) "
        "SELECT process_id, id FROM applications WHERE process_id IS NOT NULL "
        "ON CONFLICT DO NOTHING"
    )

    # process_id darf jetzt NULL sein (Fachanwendung ohne/unabhängig vom Prozess)
    op.alter_column("applications", "process_id", existing_type=postgresql.UUID(as_uuid=True),
                    nullable=True)


def downgrade() -> None:
    op.drop_table("application_gateways")
    op.drop_table("application_ip_networks")
    op.drop_table("process_applications")
    op.alter_column("applications", "process_id", existing_type=postgresql.UUID(as_uuid=True),
                    nullable=True)
