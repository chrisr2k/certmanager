"""Add certificate_key_bundles for encrypted ACME private key downloads.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "certificate_key_bundles",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "certificate_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("certificates.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_job_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("encrypted_private_key", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("downloaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now() + interval '48 hours'"),
        ),
    )
    op.create_index(
        "idx_certificate_key_bundles_certificate",
        "certificate_key_bundles",
        ["certificate_id"],
    )
    op.create_index(
        "idx_certificate_key_bundles_expires",
        "certificate_key_bundles",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_certificate_key_bundles_expires", table_name="certificate_key_bundles")
    op.drop_index("idx_certificate_key_bundles_certificate", table_name="certificate_key_bundles")
    op.drop_table("certificate_key_bundles")
