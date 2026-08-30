"""SQLAlchemy ORM models for the CertManager database.

All models use:
- UUID primary keys
- UTC timestamps (TIMESTAMPTZ)
- Async-compatible SQLAlchemy 2.0 patterns
- JSONB for flexible metadata/config fields

IMPORTANT: The certificates table stores only certificate METADATA.
Private keys are NEVER persisted in this database.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, List, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Type variants: JSONB on PostgreSQL, plain JSON elsewhere (SQLite in tests).
# This keeps a single model layer while the migration stays PG-native.
JSONVariant = JSON().with_variant(JSONB, "postgresql")
ARRAYVariant = JSON().with_variant(ARRAY(Text), "postgresql")
# UUID: native UUID on PG; plain 32-char hex strings on SQLite (no UUID
# object conversion, so values round-trip exactly as Python writes them).
UUIDHex = postgresql.UUID(as_uuid=False).with_variant(String(32), "sqlite")
# Big autoincrement PK: BIGSERIAL on PG; SQLite only autoincrements plain
# INTEGER PRIMARY KEY, so the variant switches type per dialect.
BigIntPK = BigInteger().with_variant(Integer, "sqlite")


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    """Base class for all ORM models."""

    type_annotation_map = {
        dict[str, Any]: JSONVariant,
        list[str]: ARRAYVariant,
        list[dict]: JSONVariant,
    }


# ---------------------------------------------------------------------------
# Mixins
# ---------------------------------------------------------------------------
class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


def _new_uuid() -> str:
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# RBAC: Users, Roles, Permissions
# ---------------------------------------------------------------------------
class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(64))
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    recovery_codes: Mapped[list[str]] = mapped_column(
        JSONVariant, default=list, nullable=False
    )  # hashes of one-time MFA recovery codes

    # Relationships
    roles: Mapped[list["Role"]] = relationship(
        secondary="user_roles", back_populates="users", lazy="selectin"
    )
    api_keys: Mapped[list["APIKey"]] = relationship(back_populates="user", lazy="selectin")
    alert_rules: Mapped[list["AlertRule"]] = relationship(
        back_populates="created_by_user", lazy="selectin"
    )


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    users: Mapped[list["User"]] = relationship(
        secondary="user_roles", back_populates="roles", lazy="selectin"
    )
    permissions: Mapped[list["Permission"]] = relationship(
        secondary="role_permissions", back_populates="roles", lazy="selectin"
    )


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    resource: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)

    # Relationships
    roles: Mapped[list["Role"]] = relationship(
        secondary="role_permissions", back_populates="permissions", lazy="selectin"
    )

    __table_args__ = (UniqueConstraint("resource", "action", name="uq_permission_resource_action"),)


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[str] = mapped_column(
        UUIDHex, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[str] = mapped_column(
        UUIDHex, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[str] = mapped_column(
        UUIDHex, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[str] = mapped_column(
        UUIDHex, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )


# ---------------------------------------------------------------------------
# Topology: Datacenters and Certificate Authorities
# ---------------------------------------------------------------------------
class Datacenter(Base, TimestampMixin):
    __tablename__ = "datacenters"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    code: Mapped[str] = mapped_column(String(10), unique=True, nullable=False)
    location: Mapped[Optional[str]] = mapped_column(String(255))
    timezone: Mapped[str] = mapped_column(String(50), default="UTC", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    metadata_: Mapped[dict] = mapped_column("metadata_json", JSONVariant, default=dict)

    # Relationships
    certificate_authorities: Mapped[list["CertificateAuthority"]] = relationship(
        back_populates="datacenter", lazy="selectin"
    )
    certificates: Mapped[list["Certificate"]] = relationship(back_populates="datacenter", lazy="selectin")
    agents: Mapped[list["Agent"]] = relationship(back_populates="datacenter", lazy="selectin")


class CertificateAuthority(Base, TimestampMixin):
    __tablename__ = "certificate_authorities"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    ca_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # aws_acm | azure_keyvault | adcs
    datacenter_id: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("datacenters.id", ondelete="SET NULL")
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Type-specific configuration (JSONB)
    # AWS: {"account_id": "...", "regions": ["us-east-1"], "role_arn": "..."}
    # Azure: {"subscription_id": "...", "vault_url": "...", "tenant_id": "..."}
    # ADCS: {"agent_id": "...", "ca_server": "...", "ca_name": "..."}
    config: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)

    # Reference to encrypted credentials in ca_credentials table
    credential_ref: Mapped[Optional[str]] = mapped_column(String(255))

    # Health tracking
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_scan_status: Mapped[Optional[str]] = mapped_column(String(50))  # success | partial | failed
    last_error: Mapped[Optional[str]] = mapped_column(Text)
    health_status: Mapped[str] = mapped_column(String(20), default="unknown")  # healthy | degraded | unhealthy | unknown

    # Relationships
    datacenter: Mapped[Optional["Datacenter"]] = relationship(back_populates="certificate_authorities")
    certificates: Mapped[list["Certificate"]] = relationship(
        back_populates="source_ca", lazy="selectin"
    )

    __table_args__ = (UniqueConstraint("name", "ca_type", name="uq_ca_name_type"),)


class CACredential(Base):
    __tablename__ = "ca_credentials"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    lookup_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    encrypted_value: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )
    encryption_key_id: Mapped[str] = mapped_column(String(100), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    rotated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


# ---------------------------------------------------------------------------
# Certificates (Core Inventory)
# ---------------------------------------------------------------------------
class Certificate(Base, TimestampMixin):
    """Canonical certificate inventory record.

    NEVER stores private keys. Contains only observable metadata:
    subject, issuer, validity dates, fingerprints, SANs, etc.
    """

    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)

    # Identity
    common_name: Mapped[Optional[str]] = mapped_column(String(500))
    subject: Mapped[Optional[str]] = mapped_column(Text)
    issuer: Mapped[Optional[str]] = mapped_column(Text)
    serial_number: Mapped[Optional[str]] = mapped_column(String(255))
    thumbprint_sha256: Mapped[Optional[str]] = mapped_column(String(64))

    # Validity
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    validity_days: Mapped[int] = mapped_column(Integer, nullable=False)

    # Type / Usage
    cert_type: Mapped[Optional[str]] = mapped_column(String(50))  # server | client | code_signing | ca | intermediate
    key_algorithm: Mapped[Optional[str]] = mapped_column(String(50))  # RSA-2048 | RSA-4096 | ECDSA-P256 | ECDSA-P384
    signature_algorithm: Mapped[Optional[str]] = mapped_column(String(50))

    # Subject Alternative Names
    sans: Mapped[Optional[list[str]]] = mapped_column(ARRAYVariant)

    # Source
    source_ca_id: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("certificate_authorities.id", ondelete="SET NULL")
    )
    source_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # aws_acm | azure_keyvault | adcs | manual | tls_scan
    source_detail: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    # {"aws_arn": "...", "azure_vault_url": "...", "adcs_template": "..."}

    # Status
    status: Mapped[str] = mapped_column(String(30), default="active")  # active | expired | revoked | pending_revocation | unknown
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_ca: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Association
    datacenter_id: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("datacenters.id", ondelete="SET NULL")
    )
    owner: Mapped[Optional[str]] = mapped_column(String(255))
    tags: Mapped[dict] = mapped_column(JSONVariant, default=dict)

    # Discovery tracking
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    discovered_by: Mapped[Optional[str]] = mapped_column(String(100))  # scan_job_id | "manual"

    # Relationships
    source_ca: Mapped[Optional["CertificateAuthority"]] = relationship(back_populates="certificates")
    datacenter: Mapped[Optional["Datacenter"]] = relationship(back_populates="certificates")
    chain_certs: Mapped[list["CertificateChain"]] = relationship(
        back_populates="leaf_cert", lazy="selectin"
    )
    alert_events: Mapped[list["AlertEvent"]] = relationship(
        back_populates="certificate", lazy="selectin"
    )
    ct_entries: Mapped[list["CTLogEntry"]] = relationship(back_populates="matched_cert", lazy="selectin")

    # Indexes are defined in __table_args__
    __table_args__ = (
        Index("idx_certificates_expiry", "not_after", "status"),
        Index("idx_certificates_thumbprint", "thumbprint_sha256"),
        Index("idx_certificates_ca", "source_ca_id"),
        Index("idx_certificates_dc", "datacenter_id"),
        # NOTE: the PostgreSQL tsvector GIN search index
        # (idx_certificates_search) is created in migration 0001 only —
        # it cannot be expressed portably across dialects.
        Index("idx_certificates_sans", "sans", postgresql_using="GIN"),
        Index("idx_certificates_type_status", "cert_type", "status"),
    )


class CertificateChain(Base):
    """Certificate chain entries (leaf → intermediates → root)."""

    __tablename__ = "certificate_chains"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    leaf_cert_id: Mapped[str] = mapped_column(
        UUIDHex, ForeignKey("certificates.id", ondelete="CASCADE")
    )
    chain_order: Mapped[int] = mapped_column(Integer, nullable=False)  # 0 = leaf, 1..N = intermediates, N+1 = root
    cert_pem_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    cert_subject: Mapped[Optional[str]] = mapped_column(Text)
    cert_issuer: Mapped[Optional[str]] = mapped_column(Text)
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    # Relationships
    leaf_cert: Mapped["Certificate"] = relationship(back_populates="chain_certs")

    __table_args__ = (Index("idx_chains_leaf", "leaf_cert_id"),)


# ---------------------------------------------------------------------------
# Certificate Transparency
# ---------------------------------------------------------------------------
class CTLogEntry(Base):
    __tablename__ = "ct_log_entries"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    log_name: Mapped[Optional[str]] = mapped_column(String(255))
    log_url: Mapped[Optional[str]] = mapped_column(Text)
    entry_index: Mapped[Optional[int]] = mapped_column(BigInteger)
    logged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    cert_thumbprint: Mapped[Optional[str]] = mapped_column(String(64))
    domains: Mapped[Optional[list[str]]] = mapped_column(ARRAYVariant)
    issuer: Mapped[Optional[str]] = mapped_column(Text)
    not_before: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_precert: Mapped[bool] = mapped_column(Boolean, default=False)
    matched_cert_id: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("certificates.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    # Relationships
    matched_cert: Mapped[Optional["Certificate"]] = relationship(back_populates="ct_entries")

    __table_args__ = (
        Index("idx_ct_entries_domains", "domains", postgresql_using="GIN"),
        Index("idx_ct_entries_thumbprint", "cert_thumbprint"),
    )


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
class AlertRule(Base, TimestampMixin):
    __tablename__ = "alert_rules"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    condition_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # expiry_days | issuer_match | status_change | ct_new_cert | ca_health
    condition_config: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    scope_filter: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    severity: Mapped[str] = mapped_column(
        String(20), default="warning", nullable=False
    )  # info | warning | critical
    cooldown_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("users.id", ondelete="SET NULL")
    )

    # Relationships
    created_by_user: Mapped[Optional["User"]] = relationship(back_populates="alert_rules")
    channels: Mapped[list["AlertRuleChannel"]] = relationship(
        back_populates="alert_rule", lazy="selectin", cascade="all, delete-orphan"
    )
    events: Mapped[list["AlertEvent"]] = relationship(back_populates="alert_rule", lazy="selectin")


class AlertRuleChannel(Base):
    __tablename__ = "alert_rule_channels"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    alert_rule_id: Mapped[str] = mapped_column(
        UUIDHex, ForeignKey("alert_rules.id", ondelete="CASCADE")
    )
    channel_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # email | webhook | slack | teams | pagerduty
    channel_config: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)

    # Relationships
    alert_rule: Mapped["AlertRule"] = relationship(back_populates="channels")


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    alert_rule_id: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("alert_rules.id", ondelete="SET NULL")
    )
    cert_id: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("certificates.id", ondelete="SET NULL")
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    context: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    acknowledged_by: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("users.id", ondelete="SET NULL")
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    # Relationships
    alert_rule: Mapped[Optional["AlertRule"]] = relationship(back_populates="events")
    certificate: Mapped[Optional["Certificate"]] = relationship(back_populates="alert_events")

    __table_args__ = (
        Index("idx_alert_events_unacked", "is_acknowledged", "created_at"),
        Index("idx_alert_events_rule", "alert_rule_id", "created_at"),
        Index("idx_alert_events_cert", "cert_id", "created_at"),
    )


# ---------------------------------------------------------------------------
# Scan Jobs
# ---------------------------------------------------------------------------
class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    job_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # full_discovery | ca_sync | tls_scan | adcs_scan | ct_monitor
    status: Mapped[str] = mapped_column(
        String(30), default="pending", nullable=False
    )  # pending | running | completed | failed | cancelled
    triggered_by: Mapped[str] = mapped_column(String(50), nullable=False)  # schedule | manual | api
    triggered_by_user: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("users.id", ondelete="SET NULL")
    )
    scope_config: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(100))
    total_checked: Mapped[int] = mapped_column(Integer, default=0)
    total_new: Mapped[int] = mapped_column(Integer, default=0)
    total_updated: Mapped[int] = mapped_column(Integer, default=0)
    total_errors: Mapped[int] = mapped_column(Integer, default=0)
    error_detail: Mapped[list] = mapped_column(JSONVariant, default=list)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------
class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    agent_type: Mapped[str] = mapped_column(String(50), nullable=False)  # adcs | tls_scanner | generic
    datacenter_id: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("datacenters.id", ondelete="SET NULL")
    )
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # INET field
    version: Mapped[Optional[str]] = mapped_column(String(50))
    auth_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256 of agent token
    status: Mapped[str] = mapped_column(
        String(20), default="offline", nullable=False
    )  # online | offline | degraded | unapproved
    last_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_job_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    config: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    is_approved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    datacenter: Mapped[Optional["Datacenter"]] = relationship(back_populates="agents")


# ---------------------------------------------------------------------------
# Audit Log (append-only, TimescaleDB hypertable in migration)
# ---------------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)  # user | agent | system | api_key
    actor_id: Mapped[Optional[str]] = mapped_column(UUIDHex)
    actor_email: Mapped[Optional[str]] = mapped_column(String(255))
    resource_type: Mapped[Optional[str]] = mapped_column(String(100))
    resource_id: Mapped[Optional[str]] = mapped_column(UUIDHex)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    details: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    __table_args__ = (
        Index("idx_audit_actor", "actor_type", "actor_id", "created_at"),
        Index("idx_audit_resource", "resource_type", "resource_id", "created_at"),
        Index("idx_audit_event_type", "event_type", "created_at"),
    )


# ---------------------------------------------------------------------------
# Notification Channels
# ---------------------------------------------------------------------------
class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    channel_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # email | webhook | slack | teams | pagerduty
    config: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------
class APIKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    user_id: Mapped[str] = mapped_column(
        UUIDHex, ForeignKey("users.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    prefix: Mapped[str] = mapped_column(String(8), nullable=False)  # "cm_a1b2..."
    scopes: Mapped[list[str]] = mapped_column(ARRAYVariant, default=["read"])
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="api_keys")


# ---------------------------------------------------------------------------
# Compliance Reports
# ---------------------------------------------------------------------------
class ComplianceReport(Base):
    __tablename__ = "compliance_reports"

    id: Mapped[str] = mapped_column(UUIDHex, primary_key=True, default=_new_uuid)
    report_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # expiry_summary | full_inventory | change_report | audit_export
    status: Mapped[str] = mapped_column(
        String(30), default="pending", nullable=False
    )  # pending | generating | completed | failed
    parameters: Mapped[dict] = mapped_column(JSONVariant, default=dict)
    file_path: Mapped[Optional[str]] = mapped_column(Text)
    file_format: Mapped[Optional[str]] = mapped_column(String(20))  # pdf | csv | json
    generated_by: Mapped[Optional[str]] = mapped_column(
        UUIDHex, ForeignKey("users.id", ondelete="SET NULL")
    )
    generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
