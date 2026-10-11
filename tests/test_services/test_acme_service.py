"""AcmeService orchestration tests — stub connector (no real ACME calls),
asserting Certificate/CertificateChain/CertificateKeyBundle rows land
correctly and the encrypted key blob round-trips."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.connectors.base import CertificateRecord, IssueResult
from certmanager.core.crypto import decrypt_value
from certmanager.core.exceptions import NotFoundError, ValidationError
from certmanager.core.models import (
    Certificate,
    CertificateAuthority,
    CertificateKeyBundle,
    ScanJob,
)
from certmanager.services.acme_service import AcmeService


def _issue_result(cn: str = "www.example.com") -> IssueResult:
    now = datetime.now(UTC)
    return IssueResult(
        certificate=CertificateRecord(
            common_name=cn,
            subject=f"CN={cn}",
            issuer="CN=Fake LE Intermediate",
            serial_number="01",
            thumbprint_sha256="a" * 64,
            not_before=now,
            not_after=now + timedelta(days=90),
            validity_days=90,
            sans=[cn],
            source_detail={"cert_pem": "FAKE-CERT-PEM", "chain_pem": "FAKE-CHAIN-PEM"},
        ),
        private_key_pem="-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----",
    )


class _StubConnector:
    """Mirrors ACMEConnector's public surface without touching ACME/DNS."""

    def __init__(self, issue_result: IssueResult, new_account=(None, None)):
        self._issue_result = issue_result
        self._new_account = new_account
        self.issue_calls = []
        self.renew_calls = []

    async def ensure_account(self):
        return self._new_account

    async def issue_certificate(self, request):
        self.issue_calls.append(request)
        return self._issue_result

    async def renew_certificate(self, source_id):
        self.renew_calls.append(source_id)
        return self._issue_result


@pytest_asyncio.fixture
async def acme_authority(seeded_db: AsyncSession) -> CertificateAuthority:
    authority = CertificateAuthority(
        name="Test LE",
        ca_type="acme",
        config={"contact_email": "a@b.com", "domains": ["example.com"]},
    )
    seeded_db.add(authority)
    await seeded_db.flush()
    return authority


@pytest_asyncio.fixture
async def scan_job(seeded_db: AsyncSession) -> ScanJob:
    job = ScanJob(job_type="acme_issue", status="pending", triggered_by="manual")
    seeded_db.add(job)
    await seeded_db.flush()
    return job


async def test_issue_creates_certificate_and_key_bundle(
    seeded_db: AsyncSession, acme_authority, scan_job, monkeypatch
):
    stub = _StubConnector(_issue_result())
    monkeypatch.setattr(
        "certmanager.services.acme_service.get_connector", lambda authority: stub
    )

    service = AcmeService(seeded_db)
    outcome = await service.issue_or_renew(
        authority_id=acme_authority.id,
        mode="issue",
        scan_job_id=scan_job.id,
        common_name="www.example.com",
    )
    await seeded_db.commit()

    cert = (
        await seeded_db.execute(select(Certificate).where(Certificate.id == outcome["certificate_id"]))
    ).scalar_one()
    assert cert.common_name == "www.example.com"
    assert cert.source_type == "acme"
    assert cert.source_ca_id == acme_authority.id

    bundle = (
        await seeded_db.execute(
            select(CertificateKeyBundle).where(CertificateKeyBundle.id == outcome["key_bundle_id"])
        )
    ).scalar_one()
    assert bundle.certificate_id == cert.id
    assert bundle.scan_job_id == scan_job.id
    assert decrypt_value(bundle.encrypted_private_key) == (
        "-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----"
    )
    assert len(stub.issue_calls) == 1


async def test_ensure_account_persists_new_key_and_url(
    seeded_db: AsyncSession, acme_authority, scan_job, monkeypatch
):
    stub = _StubConnector(_issue_result(), new_account=("NEW-KEY-PEM", "https://acme.test/acct/1"))
    monkeypatch.setattr(
        "certmanager.services.acme_service.get_connector", lambda authority: stub
    )

    service = AcmeService(seeded_db)
    await service.issue_or_renew(
        authority_id=acme_authority.id,
        mode="issue",
        scan_job_id=scan_job.id,
        common_name="www.example.com",
    )
    await seeded_db.commit()
    await seeded_db.refresh(acme_authority)

    # Persisted and encrypted (not plaintext in the stored config).
    assert acme_authority.config["account_url"] == "https://acme.test/acct/1"
    assert acme_authority.config["account_key_pem"] != "NEW-KEY-PEM"
    assert "__enc" in acme_authority.config["account_key_pem"]


async def test_idempotent_retry_does_not_reissue(
    seeded_db: AsyncSession, acme_authority, scan_job, monkeypatch
):
    stub = _StubConnector(_issue_result())
    monkeypatch.setattr(
        "certmanager.services.acme_service.get_connector", lambda authority: stub
    )

    service = AcmeService(seeded_db)
    first = await service.issue_or_renew(
        authority_id=acme_authority.id,
        mode="issue",
        scan_job_id=scan_job.id,
        common_name="www.example.com",
    )
    await seeded_db.commit()

    second = await service.issue_or_renew(
        authority_id=acme_authority.id,
        mode="issue",
        scan_job_id=scan_job.id,
        common_name="www.example.com",
    )

    assert second == first
    assert len(stub.issue_calls) == 1  # no second ACME order placed


async def test_renew_uses_stored_cert_pem(
    seeded_db: AsyncSession, acme_authority, scan_job, monkeypatch
):
    stub = _StubConnector(_issue_result("renewed.example.com"))
    monkeypatch.setattr(
        "certmanager.services.acme_service.get_connector", lambda authority: stub
    )

    existing_cert = Certificate(
        common_name="renewed.example.com",
        not_before=datetime.now(UTC),
        not_after=datetime.now(UTC) + timedelta(days=5),
        validity_days=5,
        source_type="acme",
        source_ca_id=acme_authority.id,
        source_detail={"cert_pem": "EXISTING-CERT-PEM"},
    )
    seeded_db.add(existing_cert)
    await seeded_db.flush()

    service = AcmeService(seeded_db)
    await service.issue_or_renew(
        authority_id=acme_authority.id,
        mode="renew",
        scan_job_id=scan_job.id,
        renew_certificate_id=existing_cert.id,
    )

    assert stub.renew_calls == ["EXISTING-CERT-PEM"]


async def test_renew_without_cert_pem_raises_validation_error(
    seeded_db: AsyncSession, acme_authority, scan_job, monkeypatch
):
    stub = _StubConnector(_issue_result())
    monkeypatch.setattr(
        "certmanager.services.acme_service.get_connector", lambda authority: stub
    )

    existing_cert = Certificate(
        common_name="no-pem.example.com",
        not_before=datetime.now(UTC),
        not_after=datetime.now(UTC) + timedelta(days=5),
        validity_days=5,
        source_type="manual",
        source_detail={},
    )
    seeded_db.add(existing_cert)
    await seeded_db.flush()

    service = AcmeService(seeded_db)
    with pytest.raises(ValidationError, match="no stored PEM"):
        await service.issue_or_renew(
            authority_id=acme_authority.id,
            mode="renew",
            scan_job_id=scan_job.id,
            renew_certificate_id=existing_cert.id,
        )


async def test_unknown_authority_raises_not_found(seeded_db: AsyncSession, scan_job):
    service = AcmeService(seeded_db)
    with pytest.raises(NotFoundError):
        await service.issue_or_renew(
            authority_id="11111111-1111-4111-8111-111111111111",
            mode="issue",
            scan_job_id=scan_job.id,
            common_name="x.example.com",
        )


async def test_non_acme_authority_raises_validation_error(seeded_db: AsyncSession, scan_job):
    authority = CertificateAuthority(name="Not ACME", ca_type="aws_acm", config={})
    seeded_db.add(authority)
    await seeded_db.flush()

    service = AcmeService(seeded_db)
    with pytest.raises(ValidationError, match="not an ACME authority"):
        await service.issue_or_renew(
            authority_id=authority.id,
            mode="issue",
            scan_job_id=scan_job.id,
            common_name="x.example.com",
        )
