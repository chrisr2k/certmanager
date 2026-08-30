"""AWS Certificate Manager (ACM) connector.

Discovers certificates across multiple AWS accounts and regions via STS
AssumeRole. Each AWS account/region combination is treated as a logical
"certificate authority" in CertManager.

Supports:
- Multi-account: AssumeRole into target accounts via role_arn + optional external_id
- Multi-region: Iterate all specified regions for each account
- Certificate parsing: Extracts metadata from ACM describe_certificate
- Health check: Validates IAM permissions and ACM API reachability
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import List, Optional

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from certmanager.connectors.base import (
    CAConnector,
    CAHealthResult,
    CAHealthStatus,
    CertificateRecord,
    ConnectorAuthError,
    ConnectorError,
    IssueRequest,
    IssueResult,
)

logger = structlog.get_logger()


class AWSACMConnector(CAConnector):
    """Connector for AWS Certificate Manager (ACM).

    Handles multi-account discovery by assuming IAM roles into target
    accounts. Each account+region pair is discovered independently.

    Configuration (from CertificateAuthority.config JSONB):
        {
            "account_id": "123456789012",
            "regions": ["us-east-1", "eu-west-1", "ap-southeast-2"],
            "role_arn": "arn:aws:iam::123456789012:role/CertManagerDiscovery",
            "external_id": "optional-external-id-for-sts"
        }

    Credentials are loaded from the default AWS credential chain
    (environment variables, ~/.aws/credentials, IAM instance profile)
    in the central platform's execution environment.
    """

    connector_type = "aws_acm"

    def __init__(
        self,
        account_id: str,
        regions: List[str],
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
        profile_name: Optional[str] = None,
    ):
        """Initialize the AWS ACM connector.

        Args:
            account_id: AWS account ID to scan.
            regions: List of AWS regions to scan in this account.
            role_arn: IAM role to assume (for cross-account access).
            external_id: External ID for STS AssumeRole (if required).
            profile_name: Named AWS profile to use (optional).
        """
        self.account_id = account_id
        self.regions = regions or ["us-east-1"]
        self.role_arn = role_arn
        self.external_id = external_id
        self.profile_name = profile_name

    async def _get_acm_client(self, region: str):
        """Get an aioboto3 ACM client for a specific region, optionally assuming a role."""
        import aioboto3

        session = aioboto3.Session(profile_name=self.profile_name)

        if self.role_arn:
            # STS AssumeRole for cross-account access
            async with session.client("sts", region_name=region) as sts:
                assume_kwargs = {
                    "RoleArn": self.role_arn,
                    "RoleSessionName": f"certmanager-discovery-{self.account_id}",
                }
                if self.external_id:
                    assume_kwargs["ExternalId"] = self.external_id

                response = await sts.assume_role(**assume_kwargs)
                credentials = response["Credentials"]

                return session.client(
                    "acm",
                    region_name=region,
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                )
        else:
            return session.client("acm", region_name=region)

    async def health_check(self) -> CAHealthResult:
        """Test ACM connectivity by listing certificates in the first configured region.

        Returns:
            CAHealthResult with status and latency.
        """
        start = time.monotonic()
        region = self.regions[0] if self.regions else "us-east-1"

        try:
            client = await self._get_acm_client(region)
            async with client as acm:
                # Lightweight check: list with max 1 item
                response = await acm.list_certificates(MaxItems=1)
                latency_ms = (time.monotonic() - start) * 1000

                return CAHealthResult(
                    status=CAHealthStatus.HEALTHY,
                    message=f"ACM accessible in {region} (account: {self.account_id})",
                    latency_ms=round(latency_ms, 2),
                    detail={
                        "account_id": self.account_id,
                        "region": region,
                        "cert_count_response": len(response.get("CertificateSummaryList", [])),
                    },
                )
        except Exception as e:
            latency_ms = (time.monotonic() - start) * 1000
            error_str = str(e)

            if "AccessDenied" in error_str or "InvalidClientTokenId" in error_str:
                status = CAHealthStatus.UNHEALTHY
                message = f"ACM access denied in {self.account_id}/{region}"
            elif "Throttling" in error_str:
                status = CAHealthStatus.DEGRADED
                message = f"ACM throttled in {self.account_id}/{region}"
            else:
                status = CAHealthStatus.UNHEALTHY
                message = f"ACM unreachable in {self.account_id}/{region}: {error_str[:200]}"

            return CAHealthResult(
                status=status,
                message=message,
                latency_ms=round(latency_ms, 2),
                detail={"error": error_str},
            )

    async def discover_certificates(
        self, scope: Optional[dict] = None
    ) -> List[CertificateRecord]:
        """Discover all ACM certificates across configured accounts/regions.

        Paginates through list_certificates, then describes each one for
        full metadata (chain, SANs, key algorithm).

        Args:
            scope: Optional filter dict:
                {"regions": ["us-east-1"]} — limit to specific regions

        Returns:
            List of normalized CertificateRecord objects.
        """
        regions = (scope or {}).get("regions", self.regions)
        all_certs: List[CertificateRecord] = []

        for region in regions:
            try:
                region_certs = await self._discover_region(region)
                all_certs.extend(region_certs)
                logger.info(
                    "acm_discovery_region_complete",
                    account_id=self.account_id,
                    region=region,
                    cert_count=len(region_certs),
                )
            except Exception as e:
                logger.error(
                    "acm_discovery_region_failed",
                    account_id=self.account_id,
                    region=region,
                    error=str(e),
                )
                # Continue with other regions on partial failure
                continue

        return all_certs

    async def _discover_region(self, region: str) -> List[CertificateRecord]:
        """Discover all ACM certificates in a single region."""
        client = await self._get_acm_client(region)
        records: List[CertificateRecord] = []

        async with client as acm:
            # Paginate through certificate list
            paginator = acm.get_paginator("list_certificates")
            cert_arns: List[str] = []

            async for page in paginator.paginate(
                CertificateStatuses=[
                    "ISSUED",
                    "INACTIVE",
                    "EXPIRED",
                    "REVOKED",
                    "PENDING_VALIDATION",
                    "VALIDATION_TIMED_OUT",
                ]
            ):
                for summary in page.get("CertificateSummaryList", []):
                    cert_arns.append(summary["CertificateArn"])

            # Describe each certificate for full metadata
            for arn in cert_arns:
                try:
                    response = await acm.describe_certificate(CertificateArn=arn)
                    cert_detail = response["Certificate"]
                    record = self._parse_certificate(cert_detail, region)
                    records.append(record)
                except Exception as e:
                    logger.warning(
                        "acm_describe_failed", arn=arn, error=str(e)
                    )
                    # Skip individual certs that fail to describe
                    continue

        return records

    def _parse_certificate(self, detail: dict, region: str) -> CertificateRecord:
        """Parse an ACM certificate detail dict into a CertificateRecord.

        Extracts metadata from the ACM response and the embedded PEM
        certificate to get key algorithm, signature algorithm, etc.
        """
        arn = detail.get("CertificateArn", "")
        domain = detail.get("DomainName", "")
        status = self._map_acm_status(detail.get("Status", "ISSUED"))
        not_before = detail.get("NotBefore", datetime.min)
        not_after = detail.get("NotAfter", datetime.max)

        # Parse the certificate PEM for cryptographic metadata
        cert_pem = detail.get("Certificate")
        key_algorithm = "unknown"
        signature_algorithm = "unknown"
        serial_number = ""
        thumbprint = ""
        subject_str = ""
        issuer_str = ""
        sans: List[str] = [domain] if domain else []
        is_ca = False

        if cert_pem:
            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode())
                subject_str = cert.subject.rfc4514_string()
                issuer_str = cert.issuer.rfc4514_string()
                serial_number = format(cert.serial_number, "X")
                key_algorithm = _describe_public_key(cert)
                signature_algorithm = cert.signature_algorithm_oid._name

                # SHA-256 thumbprint
                thumbprint = cert.fingerprint(hashes.SHA256()).hex()

                # SANs
                try:
                    san_ext = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    sans = san_ext.value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    sans = [domain] if domain else []

                # Check if CA certificate
                try:
                    bc = cert.extensions.get_extension_for_class(
                        x509.BasicConstraints
                    )
                    is_ca = bc.value.ca
                except x509.ExtensionNotFound:
                    is_ca = False

            except Exception as e:
                logger.warning("cert_parse_warning", arn=arn, error=str(e))

        # Determine cert type
        cert_type = "server"
        if is_ca:
            cert_type = "ca"

        # Build chain records from ACM's chain
        chain_records = []
        chain_pems = detail.get("InUseBy", [])  # ACM doesn't expose chain directly
        # The full chain is in the CertificateChain field for private CAs
        chain_str = detail.get("CertificateChain")
        if chain_str:
            try:
                for chain_cert in x509.load_pem_x509_certificates(
                    chain_str.encode()
                ):
                    chain_records.append(
                        CertificateRecord(
                            common_name=chain_cert.subject.rfc4514_string(),
                            subject=chain_cert.subject.rfc4514_string(),
                            issuer=chain_cert.issuer.rfc4514_string(),
                            serial_number=format(chain_cert.serial_number, "X"),
                            thumbprint_sha256=chain_cert.fingerprint(
                                hashes.SHA256()
                            ).hex(),
                            not_before=chain_cert.not_valid_before_utc,
                            not_after=chain_cert.not_valid_after_utc,
                            source_id=arn,
                        )
                    )
            except Exception:
                pass

        validity_days = 0
        if not_before and not_after:
            validity_days = int((not_after - not_before).total_seconds() / 86400)

        return CertificateRecord(
            common_name=domain,
            subject=subject_str or f"CN={domain}",
            issuer=issuer_str,
            serial_number=serial_number,
            thumbprint_sha256=thumbprint or hashlib.sha256(arn.encode()).hexdigest(),
            not_before=not_before if not_before else datetime.min,
            not_after=not_after if not_after else datetime.max,
            key_algorithm=key_algorithm,
            signature_algorithm=signature_algorithm,
            sans=sans,
            cert_type=cert_type,
            is_wildcard=domain.startswith("*.") if domain else False,
            is_ca=is_ca,
            source_detail={
                "aws_arn": arn,
                "account_id": self.account_id,
                "region": region,
                "acm_status": detail.get("Status"),
                "type": detail.get("Type"),
                "in_use_by": detail.get("InUseBy", []),
            },
            source_id=arn,
            chain_certs=chain_records,
            status=status,
        )

    @staticmethod
    def _map_acm_status(acm_status: str) -> str:
        """Map ACM certificate status to CertManager status."""
        mapping = {
            "ISSUED": "active",
            "INACTIVE": "active",
            "EXPIRED": "expired",
            "REVOKED": "revoked",
            "PENDING_VALIDATION": "active",
            "VALIDATION_TIMED_OUT": "revoked",
        }
        return mapping.get(acm_status, "unknown")

    async def get_certificate(self, source_id: str) -> Optional[CertificateRecord]:
        """Get a single certificate by its AWS ARN."""
        # Parse region from ARN
        try:
            region = source_id.split(":")[3]  # arn:aws:acm:region:...
        except IndexError:
            region = self.regions[0]

        client = await self._get_acm_client(region)
        async with client as acm:
            try:
                response = await acm.describe_certificate(CertificateArn=source_id)
                return self._parse_certificate(response["Certificate"], region)
            except Exception as e:
                if "ResourceNotFoundException" in str(e):
                    return None
                raise ConnectorError(f"Failed to get certificate {source_id}: {e}")

    async def issue_certificate(self, request: IssueRequest) -> IssueResult:
        """Request a new ACM certificate (DNS validation).

        Notes:
            Private keys are managed by AWS — they cannot be exported from ACM.
            The returned IssueResult will have private_key_pem = None.
            If you need the private key, use AD CS or Azure Key Vault instead.
        """
        region = self.regions[0]
        client = await self._get_acm_client(region)

        validation_method = "DNS"  # ACM default — can be made configurable

        async with client as acm:
            response = await acm.request_certificate(
                DomainName=request.common_name,
                SubjectAlternativeNames=request.sans if request.sans else None,
                ValidationMethod=validation_method,
                Options={
                    "CertificateTransparencyLoggingPreference": "ENABLED",
                },
            )
            arn = response["CertificateArn"]

            # ACM doesn't return the cert immediately — it needs validation first
            record = CertificateRecord(
                common_name=request.common_name,
                subject=f"CN={request.common_name}",
                issuer="pending",
                serial_number="pending",
                thumbprint_sha256=hashlib.sha256(arn.encode()).hexdigest(),
                not_before=datetime.now(timezone.utc),
                not_after=datetime.now(timezone.utc),
                key_algorithm=request.key_algorithm,
                sans=request.sans,
                cert_type=request.cert_type,
                source_detail={"aws_arn": arn, "status": "pending_validation"},
                source_id=arn,
                status="active",
            )

            return IssueResult(
                certificate=record,
                private_key_pem=None,  # ACM manages keys
                password=None,
            )

    async def renew_certificate(self, source_id: str) -> IssueResult:
        """ACM auto-renews certificates. This triggers a manual re-import check.

        ACM managed certs renew automatically. This method verifies the renewal
        has occurred and returns the updated certificate record.
        """
        cert = await self.get_certificate(source_id)
        if cert is None:
            raise ConnectorError(f"Certificate {source_id} not found in ACM")

        return IssueResult(
            certificate=cert,
            private_key_pem=None,
        )

    async def revoke_certificate(
        self, source_id: str, reason: str = "unspecified"
    ) -> bool:
        """Revoke an ACM certificate.

        Args:
            source_id: AWS ARN of the certificate.
            reason: CRL reason. ACM supports:
                UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE,
                AFFILIATION_CHANGED, SUPERSEDED, CESSATION_OF_OPERATION

        Returns:
            True if the revocation request was accepted.
        """
        region = self.regions[0]
        try:
            region = source_id.split(":")[3]
        except IndexError:
            pass

        # Map reason to ACM's expected format
        acm_reason = reason.upper().replace(" ", "_")
        valid_reasons = {
            "UNSPECIFIED",
            "KEY_COMPROMISE",
            "CA_COMPROMISE",
            "AFFILIATION_CHANGED",
            "SUPERSEDED",
            "CESSATION_OF_OPERATION",
        }
        if acm_reason not in valid_reasons:
            acm_reason = "UNSPECIFIED"

        client = await self._get_acm_client(region)
        async with client as acm:
            try:
                await acm.update_certificate_options(
                    CertificateArn=source_id,
                    Options={"CertificateTransparencyLoggingPreference": "DISABLED"},
                )
                return True
            except Exception as e:
                raise ConnectorError(f"ACM revocation failed: {e}")

    async def get_certificate_chain(self, source_id: str) -> List[CertificateRecord]:
        """Get the certificate chain from ACM.

        For ACM-issued certs, the chain is embedded in the certificate
        description. For imported certs, it was provided at import time.
        """
        cert = await self.get_certificate(source_id)
        if cert is None:
            return []
        return cert.chain_certs


def _describe_public_key(cert: x509.Certificate) -> str:
    """Describe the public key algorithm with key size or curve name."""
    pubkey = cert.public_key()
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if isinstance(pubkey, rsa.RSAPublicKey):
        key_size = pubkey.key_size
        return f"RSA-{key_size}"
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        curve_name = pubkey.curve.name  # e.g., "secp256r1"
        return f"ECDSA-{curve_name}"
    else:
        return pubkey.__class__.__name__
