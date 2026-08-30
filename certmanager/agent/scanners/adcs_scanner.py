"""Active Directory Certificate Services scanner.

Enumerates issued certificates from an AD CS CA using:
1. PowerShell PKI module (preferred) — Get-IssuedRequest, Get-CertificationAuthority
2. certutil -view (fallback) — parses CSV output
3. LDAP query for published certificates (alternative)

Runs as a subprocess on the agent host (Windows or Linux with PS Core).
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

from certmanager.agent.scanners.base import HealthStatus, ScannerPlugin, ScanResult

logger = structlog.get_logger()

# PowerShell script for certificate enumeration (bundled)
ADCS_ENUM_SCRIPT = Path(__file__).parent.parent / "templates" / "adcs_cert_enum.ps1"


class ADCSLocalScanner(ScannerPlugin):
    """Discovers certificates issued by an AD CS Certificate Authority.

    The scanner runs PowerShell commands locally on the agent host.
    The agent must be installed on a Windows server with the AD CS
    management tools or PowerShell PKI module available.
    """

    name = "adcs"

    def __init__(
        self,
        ca_server: str = "",
        ca_name: str = "",
        use_winrm: bool = False,
        winrm_endpoint: str = "",
    ):
        """Initialize the AD CS scanner.

        Args:
            ca_server: Hostname of the AD CS server.
            ca_name: Common name of the Certificate Authority.
            use_winrm: If True, use WinRM to run commands remotely.
            winrm_endpoint: WinRM endpoint URL.
        """
        self.ca_server = ca_server or os.environ.get("COMPUTERNAME", "localhost")
        self.ca_name = ca_name or ""
        self.use_winrm = use_winrm
        self.winrm_endpoint = winrm_endpoint

    async def health_check(self) -> HealthStatus:
        """Verify PowerShell and AD CS connectivity."""
        try:
            # Check if PowerShell is available
            proc = await asyncio.create_subprocess_exec(
                "powershell",
                "-NoProfile",
                "-Command",
                "Write-Output 'ok'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=10
            )

            if b"ok" not in stdout:
                return HealthStatus(
                    status="error",
                    message="PowerShell not available",
                    detail={"stdout": stdout.decode(errors="replace")[:500]},
                )

            # Try to access the CA
            ps_cmd = f"Get-CertificationAuthority -Name '{self.ca_name}' 2>$null | Select-Object -ExpandProperty DisplayName"
            proc = await asyncio.create_subprocess_exec(
                "powershell",
                "-NoProfile",
                "-Command",
                ps_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )

            if proc.returncode == 0 and stdout.strip():
                return HealthStatus(
                    status="ok",
                    message=f"AD CS accessible: {stdout.decode().strip()}",
                    detail={"ca_server": self.ca_server, "ca_name": self.ca_name},
                )
            else:
                return HealthStatus(
                    status="degraded",
                    message=f"PowerShell available but CA '{self.ca_name}' not found",
                    detail={"stderr": stderr.decode(errors="replace")[:500]},
                )

        except asyncio.TimeoutError:
            return HealthStatus(
                status="error",
                message="PowerShell health check timed out",
            )
        except Exception as e:
            return HealthStatus(
                status="error",
                message=f"Health check failed: {e}",
            )

    async def scan(self, scope: dict | None = None) -> ScanResult:
        """Execute AD CS certificate enumeration.

        Args:
            scope: Optional filter dict:
                {"templates": ["WebServer"], "since": "2026-01-01",
                 "include_expired": false, "include_revoked": false}

        Returns:
            ScanResult with discovered certificates.
        """
        start = time.monotonic()
        scope = scope or {}
        errors: list[str] = []
        all_certs: list[dict] = []

        # Build filter parameters
        templates = scope.get("templates", [])
        since = scope.get("since")
        include_expired = scope.get("include_expired", False)
        include_revoked = scope.get("include_revoked", False)

        # Try PowerShell PKI module first
        try:
            certs, ps_errors = await self._enumerate_via_powershell(
                templates=templates,
                since=since,
                include_expired=include_expired,
                include_revoked=include_revoked,
            )
            all_certs.extend(certs)
            errors.extend(ps_errors)
        except Exception as e:
            logger.warning("powershell_enum_failed", error=str(e))
            errors.append(f"PowerShell enumeration failed: {e}")

            # Fallback: certutil
            try:
                certs, cu_errors = await self._enumerate_via_certutil(
                    since=since,
                    include_expired=include_expired,
                )
                all_certs.extend(certs)
                errors.extend(cu_errors)
            except Exception as e2:
                logger.error("certutil_enum_failed", error=str(e2))
                errors.append(f"CertUtil enumeration failed: {e2}")

        # Normalize certificates
        normalized = []
        for cert_data in all_certs:
            try:
                normalized.append(self._normalize_cert(cert_data))
            except Exception as e:
                logger.warning("cert_normalize_failed", error=str(e))

        duration_ms = (time.monotonic() - start) * 1000

        return ScanResult(
            scanner_name=self.name,
            total_checked=len(all_certs),
            total_new=len(normalized),
            certificates=normalized,
            errors=errors,
            duration_ms=round(duration_ms, 2),
            metadata={
                "ca_server": self.ca_server,
                "ca_name": self.ca_name,
                "enum_method": "powershell" if not any("CertUtil" in e for e in errors) else "certutil",
            },
        )

    async def _enumerate_via_powershell(
        self,
        templates: list[str],
        since: Optional[str],
        include_expired: bool,
        include_revoked: bool,
    ) -> tuple[list[dict], list[str]]:
        """Enumerate certificates using the AD CS PKI PowerShell module.

        Runs Get-IssuedRequest or Get-CertificationAuthority to list
        all issued certificates with their properties.
        """
        errors: list[str] = []

        # Build the PowerShell command
        ps_lines = [
            "$ErrorActionPreference = 'Stop'",
            "try {",
        ]

        # Import PKI module if available
        ps_lines.append("  if (Get-Module -ListAvailable -Name PSPKI) {")
        ps_lines.append("    Import-Module PSPKI -ErrorAction SilentlyContinue")
        ps_lines.append("  }")

        # Query issued certs
        if self.ca_name:
            ca_filter = f"-Name '{self.ca_name}'"
        else:
            ca_filter = ""

        ps_lines.append(f"  $ca = Get-CertificationAuthority {ca_filter}")
        ps_lines.append("  if (-not $ca) { throw 'CA not found' }")

        # Get issued certificates
        template_filter = ""
        if templates:
            template_list = ", ".join(f"'{t}'" for t in templates)
            template_filter = f" | Where-Object {{ $_.CertificateTemplate -in @({template_list}) }}"

        date_filter = ""
        if since:
            date_filter = f" | Where-Object {{ $_.NotBefore -ge [datetime]'{since}' }}"

        ps_lines.append(
            f"  $certs = Get-IssuedRequest -CertificationAuthority $ca "
            f"| Where-Object {{ $_.Status -eq 'Issued' }}"
            f"{template_filter}{date_filter}"
        )

        # Serialize to JSON
        ps_lines.extend([
            "  $result = @()",
            "  foreach ($cert in $certs) {",
            "    $result += @{",
            "      RequestID = $cert.RequestID",
            "      SerialNumber = $cert.SerialNumber",
            "      CommonName = $cert.CommonName",
            "      NotBefore = $cert.NotBefore.ToString('o')",
            "      NotAfter = $cert.NotAfter.ToString('o')",
            "      Template = $cert.CertificateTemplate",
            "      RequesterName = $cert.RequesterName",
            "      Subject = $cert.Subject",
            "      Issuer = $cert.Issuer",
            "      Thumbprint = $cert.Thumbprint",
            "      Status = $cert.Status",
            "    }",
            "  }",
            "  ConvertTo-Json -InputObject $result -Depth 3",
            "} catch {",
            "  Write-Error $_.Exception.Message",
            "  exit 1",
            "}",
        ])

        ps_script = "\n".join(ps_lines)

        proc = await asyncio.create_subprocess_exec(
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            ps_script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )
        except asyncio.TimeoutError:
            proc.kill()
            return [], ["PowerShell enumeration timed out after 120s"]

        if proc.returncode != 0:
            error_msg = stderr.decode(errors="replace")[:1000]
            return [], [f"PowerShell returned exit code {proc.returncode}: {error_msg}"]

        # Parse JSON output
        try:
            output = stdout.decode("utf-8", errors="replace").strip()

            # PowerShell sometimes wraps JSON in array brackets oddly
            if not output.startswith("["):
                # Try to find the JSON array
                start_idx = output.find("[")
                end_idx = output.rfind("]")
                if start_idx >= 0 and end_idx > start_idx:
                    output = output[start_idx:end_idx + 1]

            certs = json.loads(output)
            if isinstance(certs, dict):
                certs = [certs]  # Single cert case
            return certs, errors
        except json.JSONDecodeError as e:
            return [], [f"Failed to parse PowerShell JSON output: {e}"]

    async def _enumerate_via_certutil(
        self,
        since: Optional[str],
        include_expired: bool,
    ) -> tuple[list[dict], list[str]]:
        """Fallback: enumerate certificates using certutil -view.

        Parses CSV output from certutil. Less feature-rich than PowerShell
        but available on all Windows Server editions with AD CS.
        """
        errors: list[str] = []

        # Build certutil command
        # certutil -view -restrict "Disposition=20" -out "RequestID,SerialNumber,CommonName,..." CSV
        restrict = "Disposition=20"  # 20 = issued
        if include_expired:
            restrict = "Disposition>=20"

        cmd = (
            f'certutil -view -restrict "{restrict}" '
            f'-out "RequestID,SerialNumber,CommonName,NotBefore,NotAfter,'
            f'CertificateTemplate,RequesterName,CertificateSubNameString,'
            f'CertificateIssuerNameString,CertificateHash,CertificateSerialNumber" CSV'
        )

        proc = await asyncio.create_subprocess_exec(
            "cmd",
            "/c",
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )
        except asyncio.TimeoutError:
            proc.kill()
            return [], ["CertUtil enumeration timed out after 120s"]

        if proc.returncode != 0 and proc.returncode != 1:
            # Exit code 1 can mean "no rows" which is fine
            error_msg = stderr.decode(errors="replace")[:500]
            if "no rows" not in error_msg.lower():
                return [], [f"CertUtil failed: {error_msg}"]

        # Parse CSV output
        output = stdout.decode("utf-8", errors="replace")
        return self._parse_certutil_csv(output), errors

    def _parse_certutil_csv(self, output: str) -> list[dict]:
        """Parse certutil CSV output into cert dicts.

        CertUtil CSV format is non-standard — it includes header lines
        and multi-row output. We extract the actual CSV rows.
        """
        certs = []
        lines = output.split("\n")
        in_csv = False
        headers: list[str] = []

        for line in lines:
            line = line.strip()

            # Find the CSV header line
            if "RequestID" in line and "SerialNumber" in line:
                headers = [h.strip().strip('"') for h in line.split(",")]
                in_csv = True
                continue

            if in_csv and line and not line.startswith("---") and not line.startswith("Row"):
                # Parse CSV row
                try:
                    reader = csv.reader(io.StringIO(line))
                    row = next(reader)
                except StopIteration:
                    continue

                if len(row) >= len(headers):
                    cert_data = {}
                    for i, header in enumerate(headers):
                        if i < len(row):
                            cert_data[header] = row[i].strip().strip('"')

                    # Map to standard fields
                    certs.append({
                        "RequestID": cert_data.get("RequestID", ""),
                        "SerialNumber": cert_data.get("SerialNumber", cert_data.get("CertificateSerialNumber", "")),
                        "CommonName": cert_data.get("CommonName", ""),
                        "NotBefore": cert_data.get("NotBefore", ""),
                        "NotAfter": cert_data.get("NotAfter", ""),
                        "Template": cert_data.get("CertificateTemplate", ""),
                        "RequesterName": cert_data.get("RequesterName", ""),
                        "Subject": cert_data.get("CertificateSubNameString", ""),
                        "Issuer": cert_data.get("CertificateIssuerNameString", ""),
                        "Thumbprint": cert_data.get("CertificateHash", ""),
                        "Status": "Issued",
                    })

        return certs

    def _normalize_cert(self, cert_data: dict) -> dict:
        """Normalize a certificate dict to the format expected by the central API.

        Converts PowerShell/certutil field names to the standardized
        certificate record format.
        """
        # Parse dates
        not_before = self._parse_date(cert_data.get("NotBefore"))
        not_after = self._parse_date(cert_data.get("NotAfter"))

        # Determine cert type from template
        template = (cert_data.get("Template") or "").lower()
        cert_type = "server"
        if "user" in template or "client" in template:
            cert_type = "client"
        elif "codesigning" in template or "code_signing" in template:
            cert_type = "code_signing"
        elif "subca" in template or "subordinate" in template:
            cert_type = "ca"

        cn = cert_data.get("CommonName", "")
        is_wildcard = cn.startswith("*.")

        return {
            "common_name": cn,
            "subject": cert_data.get("Subject", f"CN={cn}"),
            "issuer": cert_data.get("Issuer", f"CN={self.ca_name}"),
            "serial_number": cert_data.get("SerialNumber", ""),
            "thumbprint": cert_data.get("Thumbprint", ""),
            "not_before": not_before.isoformat() if not_before else "",
            "not_after": not_after.isoformat() if not_after else "",
            "key_algorithm": cert_data.get("KeyAlgorithm", "RSA-2048"),
            "signature_algorithm": cert_data.get("SignatureAlgorithm", "SHA256"),
            "sans": self._parse_sans(cert_data.get("Subject", "")),
            "cert_type": cert_type,
            "is_wildcard": is_wildcard,
            "is_ca": "ca" in template,
            "request_id": cert_data.get("RequestID", ""),
            "template": cert_data.get("Template", ""),
            "status": "active",
            "source": "adcs",
        }

    @staticmethod
    def _parse_date(date_str) -> Optional[datetime]:
        """Parse a date string from PowerShell/certutil output."""
        if not date_str:
            return None

        # Try multiple formats
        formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%m/%d/%Y %H:%M",
            "%m/%d/%Y %I:%M %p",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str.strip(), fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

        # Last resort: try ISO parsing
        try:
            return datetime.fromisoformat(date_str.strip().replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _parse_sans(subject: str) -> list[str]:
        """Extract DNS names from a certificate subject string.

        Subject format: "CN=host.example.com, OU=..., DC=..."
        """
        sans = []
        cn_match = re.search(r"CN=([^,]+)", subject)
        if cn_match:
            cn = cn_match.group(1).strip()
            if cn and not cn.startswith("*"):
                sans.append(cn)
        return sans
