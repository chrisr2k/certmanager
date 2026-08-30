"""Certificate request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class CertificateCreate(BaseModel):
    """Manual certificate registration (metadata only — no private key)."""

    common_name: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    thumbprint_sha256: Optional[str] = None
    not_before: datetime
    not_after: datetime
    validity_days: int
    cert_type: Optional[str] = None
    key_algorithm: Optional[str] = None
    signature_algorithm: Optional[str] = None
    sans: Optional[list[str]] = None
    source_type: str = "manual"
    source_detail: dict = Field(default_factory=dict)
    datacenter_id: Optional[str] = None
    owner: Optional[str] = None
    tags: dict = Field(default_factory=dict)


class CertificateUpdate(BaseModel):
    """Fields that can be updated on a certificate record."""

    owner: Optional[str] = None
    tags: Optional[dict] = None
    status: Optional[str] = None
    datacenter_id: Optional[str] = None


class CertificateResponse(BaseModel):
    """Full certificate record (never includes private key)."""

    id: str
    common_name: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    thumbprint_sha256: Optional[str] = None
    not_before: datetime
    not_after: datetime
    validity_days: int
    cert_type: Optional[str] = None
    key_algorithm: Optional[str] = None
    signature_algorithm: Optional[str] = None
    sans: Optional[list[str]] = None
    source_type: str
    source_ca_id: Optional[str] = None
    source_detail: dict
    status: str
    is_wildcard: bool
    is_ca: bool
    datacenter_id: Optional[str] = None
    owner: Optional[str] = None
    tags: dict
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CertificateListResponse(BaseModel):
    """Paginated certificate list."""

    items: list[CertificateResponse]
    total: int
    page: int
    page_size: int


class CertStats(BaseModel):
    """Aggregated certificate statistics."""

    total: int
    active: int
    expired: int
    revoked: int
    expiring_in_30_days: int
    expiring_in_60_days: int
    expiring_in_90_days: int
    by_datacenter: dict[str, int]
    by_ca_type: dict[str, int]
    by_cert_type: dict[str, int]
