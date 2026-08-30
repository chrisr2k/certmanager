"""Initial schema — all CertManager tables.

Revision ID: 0001
Revises: None
Create Date: 2026-06-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- RBAC ---
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255)),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
        sa.Column("is_superuser", sa.Boolean(), default=False, nullable=False),
        sa.Column("mfa_secret", sa.String(64)),
        sa.Column("mfa_enabled", sa.Boolean(), default=False, nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("name", sa.String(100), unique=True, nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    op.create_table(
        "permissions",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("resource", sa.String(100), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.UniqueConstraint("resource", "action", name="uq_permission_resource_action"),
    )

    op.create_table(
        "role_permissions",
        sa.Column(
            "role_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("roles.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "permission_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("permissions.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    op.create_table(
        "user_roles",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "role_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("roles.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    # --- Datacenters ---
    op.create_table(
        "datacenters",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("name", sa.String(100), unique=True, nullable=False),
        sa.Column("code", sa.String(10), unique=True, nullable=False),
        sa.Column("location", sa.String(255)),
        sa.Column("timezone", sa.String(50), default="UTC", nullable=False),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(), default=sa.text("'{}'::jsonb")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    # --- Certificate Authorities ---
    op.create_table(
        "certificate_authorities",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("ca_type", sa.String(50), nullable=False),
        sa.Column(
            "datacenter_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("datacenters.id", ondelete="SET NULL"),
        ),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
        sa.Column("config", postgresql.JSONB(), default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("credential_ref", sa.String(255)),
        sa.Column("last_scan_at", sa.DateTime(timezone=True)),
        sa.Column("last_scan_status", sa.String(50)),
        sa.Column("last_error", sa.Text()),
        sa.Column("health_status", sa.String(20), default="unknown"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("name", "ca_type", name="uq_ca_name_type"),
    )

    op.create_table(
        "ca_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("lookup_key", sa.String(255), unique=True, nullable=False),
        sa.Column("encrypted_value", sa.LargeBinary(), nullable=False),
        sa.Column("encryption_key_id", sa.String(100), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("rotated_at", sa.DateTime(timezone=True)),
    )

    # --- Certificates ---
    op.create_table(
        "certificates",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("common_name", sa.String(500)),
        sa.Column("subject", sa.Text()),
        sa.Column("issuer", sa.Text()),
        sa.Column("serial_number", sa.String(255)),
        sa.Column("thumbprint_sha256", sa.String(64)),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validity_days", sa.Integer(), nullable=False),
        sa.Column("cert_type", sa.String(50)),
        sa.Column("key_algorithm", sa.String(50)),
        sa.Column("signature_algorithm", sa.String(50)),
        sa.Column("sans", postgresql.ARRAY(sa.Text())),
        sa.Column(
            "source_ca_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("certificate_authorities.id", ondelete="SET NULL"),
        ),
        sa.Column("source_type", sa.String(50), nullable=False),
        sa.Column("source_detail", postgresql.JSONB(), default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.String(30), default="active"),
        sa.Column("is_wildcard", sa.Boolean(), default=False, nullable=False),
        sa.Column("is_ca", sa.Boolean(), default=False, nullable=False),
        sa.Column(
            "datacenter_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("datacenters.id", ondelete="SET NULL"),
        ),
        sa.Column("owner", sa.String(255)),
        sa.Column("tags", postgresql.JSONB(), default=sa.text("'{}'::jsonb")),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("discovered_by", sa.String(100)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_certificates_expiry", "certificates", ["not_after", "status"])
    op.create_index("idx_certificates_thumbprint", "certificates", ["thumbprint_sha256"])
    op.create_index("idx_certificates_ca", "certificates", ["source_ca_id"])
    op.create_index("idx_certificates_dc", "certificates", ["datacenter_id"])
    op.create_index("idx_certificates_type_status", "certificates", ["cert_type", "status"])
    op.create_index(
        "idx_certificates_search",
        "certificates",
        [
            sa.text(
                "to_tsvector('english', coalesce(common_name,'') || ' ' || coalesce(subject,'') || ' ' || coalesce(issuer,''))"
            )
        ],
        postgresql_using="GIN",
    )
    op.create_index("idx_certificates_sans", "certificates", ["sans"], postgresql_using="GIN")

    # --- Certificate Chains ---
    op.create_table(
        "certificate_chains",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "leaf_cert_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("certificates.id", ondelete="CASCADE"),
        ),
        sa.Column("chain_order", sa.Integer(), nullable=False),
        sa.Column("cert_pem_sha256", sa.String(64), nullable=False),
        sa.Column("cert_subject", sa.Text()),
        sa.Column("cert_issuer", sa.Text()),
        sa.Column("not_after", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_chains_leaf", "certificate_chains", ["leaf_cert_id"])

    # --- CT Log Entries ---
    op.create_table(
        "ct_log_entries",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("log_name", sa.String(255)),
        sa.Column("log_url", sa.Text()),
        sa.Column("entry_index", sa.BigInteger()),
        sa.Column("logged_at", sa.DateTime(timezone=True)),
        sa.Column("cert_thumbprint", sa.String(64)),
        sa.Column("domains", postgresql.ARRAY(sa.Text())),
        sa.Column("issuer", sa.Text()),
        sa.Column("not_before", sa.DateTime(timezone=True)),
        sa.Column("not_after", sa.DateTime(timezone=True)),
        sa.Column("is_precert", sa.Boolean(), default=False),
        sa.Column(
            "matched_cert_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("certificates.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_ct_entries_domains", "ct_log_entries", ["domains"], postgresql_using="GIN")
    op.create_index("idx_ct_entries_thumbprint", "ct_log_entries", ["cert_thumbprint"])

    # --- Alert Rules ---
    op.create_table(
        "alert_rules",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("is_enabled", sa.Boolean(), default=True, nullable=False),
        sa.Column("condition_type", sa.String(50), nullable=False),
        sa.Column(
            "condition_config", postgresql.JSONB(), default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("scope_filter", postgresql.JSONB(), default=sa.text("'{}'::jsonb")),
        sa.Column("severity", sa.String(20), default="warning", nullable=False),
        sa.Column("cooldown_minutes", sa.Integer(), default=60, nullable=False),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    op.create_table(
        "alert_rule_channels",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "alert_rule_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("alert_rules.id", ondelete="CASCADE"),
        ),
        sa.Column("channel_type", sa.String(50), nullable=False),
        sa.Column(
            "channel_config", postgresql.JSONB(), default=sa.text("'{}'::jsonb"), nullable=False
        ),
    )

    op.create_table(
        "alert_events",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "alert_rule_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("alert_rules.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "cert_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("certificates.id", ondelete="SET NULL"),
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("context", postgresql.JSONB(), default=sa.text("'{}'::jsonb")),
        sa.Column("is_acknowledged", sa.Boolean(), default=False, nullable=False),
        sa.Column(
            "acknowledged_by",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_alert_events_unacked", "alert_events", ["is_acknowledged", "created_at"])
    op.create_index("idx_alert_events_rule", "alert_events", ["alert_rule_id", "created_at"])
    op.create_index("idx_alert_events_cert", "alert_events", ["cert_id", "created_at"])

    # --- Scan Jobs ---
    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("job_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(30), default="pending", nullable=False),
        sa.Column("triggered_by", sa.String(50), nullable=False),
        sa.Column(
            "triggered_by_user",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("scope_config", postgresql.JSONB(), default=sa.text("'{}'::jsonb")),
        sa.Column("correlation_id", sa.String(100)),
        sa.Column("total_checked", sa.Integer(), default=0),
        sa.Column("total_new", sa.Integer(), default=0),
        sa.Column("total_updated", sa.Integer(), default=0),
        sa.Column("total_errors", sa.Integer(), default=0),
        sa.Column("error_detail", postgresql.JSONB(), default=sa.text("'[]'::jsonb")),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    # --- Agents ---
    op.create_table(
        "agents",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("agent_type", sa.String(50), nullable=False),
        sa.Column(
            "datacenter_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("datacenters.id", ondelete="SET NULL"),
        ),
        sa.Column("hostname", sa.String(255)),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("version", sa.String(50)),
        sa.Column("auth_token_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), default="offline", nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("last_job_at", sa.DateTime(timezone=True)),
        sa.Column("config", postgresql.JSONB(), default=sa.text("'{}'::jsonb")),
        sa.Column("is_approved", sa.Boolean(), default=False, nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    # --- Audit Log ---
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("actor_type", sa.String(20), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=False)),
        sa.Column("actor_email", sa.String(255)),
        sa.Column("resource_type", sa.String(100)),
        sa.Column("resource_id", postgresql.UUID(as_uuid=False)),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("details", postgresql.JSONB(), default=sa.text("'{}'::jsonb")),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("user_agent", sa.Text()),
        sa.Column("correlation_id", sa.String(100)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_audit_actor", "audit_log", ["actor_type", "actor_id", "created_at"])
    op.create_index(
        "idx_audit_resource", "audit_log", ["resource_type", "resource_id", "created_at"]
    )
    op.create_index("idx_audit_event_type", "audit_log", ["event_type", "created_at"])

    # --- Notification Channels ---
    op.create_table(
        "notification_channels",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("channel_type", sa.String(50), nullable=False),
        sa.Column("config", postgresql.JSONB(), default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("is_verified", sa.Boolean(), default=False, nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    # --- API Keys ---
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("users.id", ondelete="CASCADE")
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("key_hash", sa.String(128), unique=True, nullable=False),
        sa.Column("prefix", sa.String(8), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.Text()), default=["read"]),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    # --- Compliance Reports ---
    op.create_table(
        "compliance_reports",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("report_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(30), default="pending", nullable=False),
        sa.Column("parameters", postgresql.JSONB(), default=sa.text("'{}'::jsonb")),
        sa.Column("file_path", sa.Text()),
        sa.Column("file_format", sa.String(20)),
        sa.Column(
            "generated_by",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("generated_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def downgrade() -> None:
    op.drop_table("compliance_reports")
    op.drop_table("api_keys")
    op.drop_table("notification_channels")
    op.drop_table("audit_log")
    op.drop_table("agents")
    op.drop_table("scan_jobs")
    op.drop_table("alert_events")
    op.drop_table("alert_rule_channels")
    op.drop_table("alert_rules")
    op.drop_table("ct_log_entries")
    op.drop_table("certificate_chains")
    op.drop_table("certificates")
    op.drop_table("ca_credentials")
    op.drop_table("certificate_authorities")
    op.drop_table("datacenters")
    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_table("permissions")
    op.drop_table("roles")
    op.drop_table("users")
