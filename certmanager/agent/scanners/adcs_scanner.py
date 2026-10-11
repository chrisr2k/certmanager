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
import secrets
import shutil
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs12,
)
from cryptography.x509.oid import ExtensionOID, NameOID

from certmanager.agent.scanners.base import HealthStatus, ScannerPlugin, ScanResult

logger = structlog.get_logger()

# PowerShell script for certificate enumeration (bundled)
ADCS_ENUM_SCRIPT = Path(__file__).parent.parent / "templates" / "adcs_cert_enum.ps1"


class _AdcsCommandError(RuntimeError):
    """A certreq/certutil subprocess exited non-zero or timed out."""


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

    @staticmethod
    def _ps_escape(value: str) -> str:
        """Escape a value for single-quoted PowerShell string interpolation.

        Prevents PowerShell code injection when CA names / template names /
        dates originating from job scope config are interpolated into scripts.
        """
        return str(value).replace("'", "''")

    @staticmethod
    def _powershell_binary() -> str:
        """Return the PowerShell executable for this platform."""
        import sys

        return "powershell" if sys.platform == "win32" else "pwsh"

    async def health_check(self) -> HealthStatus:
        """Verify PowerShell and AD CS connectivity."""
        try:
            # Check if PowerShell is available
            proc = await asyncio.create_subprocess_exec(
                self._powershell_binary(),
                "-NoProfile",
                "-Command",
                "Write-Output 'ok'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)

            if b"ok" not in stdout:
                return HealthStatus(
                    status="error",
                    message="PowerShell not available",
                    detail={"stdout": stdout.decode(errors="replace")[:500]},
                )

            # Try to access the CA
            ps_cmd = (
                f"Get-CertificationAuthority -Name '{self._ps_escape(self.ca_name)}' "
                "2>$null | Select-Object -ExpandProperty DisplayName"
            )
            proc = await asyncio.create_subprocess_exec(
                self._powershell_binary(),
                "-NoProfile",
                "-Command",
                ps_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

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

        except TimeoutError:
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
                "enum_method": "powershell"
                if not any("CertUtil" in e for e in errors)
                else "certutil",
            },
        )

    async def _enumerate_via_powershell(
        self,
        templates: list[str],
        since: str | None,
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
            ca_filter = f"-Name '{self._ps_escape(self.ca_name)}'"
        else:
            ca_filter = ""

        ps_lines.append(f"  $ca = Get-CertificationAuthority {ca_filter}")
        ps_lines.append("  if (-not $ca) { throw 'CA not found' }")

        # Get issued certificates
        template_filter = ""
        if templates:
            template_list = ", ".join(f"'{self._ps_escape(t)}'" for t in templates)
            template_filter = f" | Where-Object {{ $_.CertificateTemplate -in @({template_list}) }}"

        date_filter = ""
        if since:
            date_filter = (
                f" | Where-Object {{ $_.NotBefore -ge [datetime]'{self._ps_escape(since)}' }}"
            )

        ps_lines.append(
            f"  $certs = Get-IssuedRequest -CertificationAuthority $ca "
            f"| Where-Object {{ $_.Status -eq 'Issued' }}"
            f"{template_filter}{date_filter}"
        )

        # Serialize to JSON
        ps_lines.extend(
            [
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
            ]
        )

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
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except TimeoutError:
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
                    output = output[start_idx : end_idx + 1]

            certs = json.loads(output)
            if isinstance(certs, dict):
                certs = [certs]  # Single cert case
            return certs, errors
        except json.JSONDecodeError as e:
            return [], [f"Failed to parse PowerShell JSON output: {e}"]

    async def _enumerate_via_certutil(
        self,
        since: str | None,
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
            f"CertificateTemplate,RequesterName,CertificateSubNameString,"
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
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except TimeoutError:
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
                    certs.append(
                        {
                            "RequestID": cert_data.get("RequestID", ""),
                            "SerialNumber": cert_data.get(
                                "SerialNumber", cert_data.get("CertificateSerialNumber", "")
                            ),
                            "CommonName": cert_data.get("CommonName", ""),
                            "NotBefore": cert_data.get("NotBefore", ""),
                            "NotAfter": cert_data.get("NotAfter", ""),
                            "Template": cert_data.get("CertificateTemplate", ""),
                            "RequesterName": cert_data.get("RequesterName", ""),
                            "Subject": cert_data.get("CertificateSubNameString", ""),
                            "Issuer": cert_data.get("CertificateIssuerNameString", ""),
                            "Thumbprint": cert_data.get("CertificateHash", ""),
                            "Status": "Issued",
                        }
                    )

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
    def _parse_date(date_str) -> datetime | None:
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
                return datetime.strptime(date_str.strip(), fmt).replace(tzinfo=UTC)
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

    # --- Lifecycle operations: issue / renew / revoke -------------------
    #
    # Unlike scan() (read-only enumeration), these mutate the CA and the
    # local machine certificate store. The key-custody rule: a key is only
    # ever exported from the store (and thus able to leave this method) when
    # the caller asked for a file deployment or opted in to central delivery
    # — never by default.

    async def issue(self, scope: dict | None = None) -> ScanResult:
        """Request a new certificate via certreq and install it locally."""
        return await self._issue_or_renew(scope or {}, operation="issue")

    async def renew(self, scope: dict | None = None) -> ScanResult:
        """Request a replacement certificate via certreq.

        certreq always generates a fresh key/CSR/serial — there is no
        in-place renewal at the AD CS protocol level. Central is
        responsible for marking the prior certificate row superseded;
        this method's job is identical to issue().
        """
        return await self._issue_or_renew(scope or {}, operation="renew")

    async def revoke(self, scope: dict | None = None) -> ScanResult:
        """Revoke a previously issued certificate at the CA."""
        start = time.monotonic()
        scope = scope or {}
        serial_number = (scope.get("serial_number") or "").strip()
        reason_code = scope.get("reason_code", 0)
        ca_server = scope.get("ca_server") or self.ca_server
        ca_name = (scope.get("ca_name") or self.ca_name or "").strip()

        if not serial_number:
            return self._failure_result(
                "revoke", ["serial_number is required to revoke a certificate"], start
            )
        if not ca_name:
            return self._failure_result(
                "revoke", ["ca_name is required to revoke a certificate"], start
            )

        tmpdir = tempfile.mkdtemp(prefix="certmanager_adcs_")
        html_cutoff = time.time()
        try:
            config_str = f"{ca_server}\\{ca_name}" if ca_server else ca_name
            await self._run_cmd(
                ["certutil", "-config", config_str, "-revoke", serial_number, str(reason_code)],
                cwd=tmpdir,
            )
            duration_ms = (time.monotonic() - start) * 1000
            return ScanResult(
                scanner_name=self.name,
                total_checked=1,
                total_new=0,
                certificates=[],
                errors=[],
                duration_ms=round(duration_ms, 2),
                metadata={"operation": "revoke", "serial_number": serial_number},
            )
        except _AdcsCommandError as e:
            return self._failure_result("revoke", [str(e)], start)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
            self._cleanup_html_logs(html_cutoff)

    async def _issue_or_renew(self, scope: dict, operation: str) -> ScanResult:
        start = time.monotonic()
        common_name = (scope.get("common_name") or "").strip()
        sans = [s for s in (scope.get("sans") or []) if s]
        template = (scope.get("template") or "").strip()
        deployment_target = scope.get("deployment_target") or "store"
        deployment_path = scope.get("deployment_path") or ""
        post_install_hook = scope.get("post_install_hook") or ""
        deliver_key_to_central = bool(scope.get("deliver_key_to_central", False))

        if not common_name:
            return self._failure_result(operation, ["common_name is required"], start)
        if not template:
            return self._failure_result(
                operation,
                [
                    "template is required — configure a default template on the CA "
                    "(must be permitted for autoenrollment; manual-approval templates "
                    "are not supported)"
                ],
                start,
            )
        if deployment_target not in ("store", "file"):
            return self._failure_result(
                operation, [f"Unknown deployment_target: {deployment_target!r}"], start
            )
        if deployment_target == "file" and not deployment_path:
            return self._failure_result(
                operation,
                ["deployment_path is required when deployment_target is 'file'"],
                start,
            )

        # Exportable is only ever turned on when the key actually needs to
        # leave the local machine store — for a file deployment, or because
        # the operator explicitly opted in to central delivery.
        exportable = deployment_target == "file" or deliver_key_to_central
        tmpdir = tempfile.mkdtemp(prefix="certmanager_adcs_")
        html_cutoff = time.time()

        try:
            inf_path = os.path.join(tmpdir, "request.inf")
            req_path = os.path.join(tmpdir, "request.req")
            cer_path = os.path.join(tmpdir, "issued.cer")

            Path(inf_path).write_text(
                self._build_inf(common_name, sans, template, exportable), encoding="utf-8"
            )

            await self._run_cmd(["certreq", "-new", "-q", inf_path, req_path], cwd=tmpdir)

            config_str = (
                f"{self.ca_server}\\{self.ca_name}"
                if self.ca_server and self.ca_name
                else (self.ca_name or self.ca_server)
            )
            submit_output = await self._run_cmd(
                ["certreq", "-submit", "-q", "-config", config_str, req_path, cer_path],
                cwd=tmpdir,
            )

            if not os.path.exists(cer_path):
                # Pending/manual-approval templates return a RequestID
                # instead of an issued cert — a clear v1 failure rather
                # than a silent hang or a second poll-and-retrieve path.
                return self._failure_result(
                    operation,
                    [
                        "Certificate request did not complete immediately — the template "
                        "may require manual approval, which this version does not "
                        "support. Configure the template for autoenrollment. certreq "
                        f"output: {submit_output.strip()[:500]}"
                    ],
                    start,
                )

            await self._run_cmd(["certreq", "-accept", "-q", cer_path], cwd=tmpdir)

            cert = self._load_cert_file(cer_path)
            cert_info = self._normalize_issued_cert(cert, template)

            private_key_pem = cert_pem = chain_pem = None
            if exportable:
                pfx_path = os.path.join(tmpdir, "cert.pfx")
                pfx_password = secrets.token_urlsafe(24)
                try:
                    await self._run_cmd(
                        [
                            "certutil",
                            "-exportPFX",
                            "-p",
                            pfx_password,
                            "My",
                            cert_info["thumbprint"],
                            pfx_path,
                        ],
                        cwd=tmpdir,
                    )
                    private_key_pem, cert_pem, chain_pem = self._split_pfx(pfx_path, pfx_password)
                finally:
                    pfx_password = None  # discard immediately; never logged

                if deployment_target == "file":
                    self._write_deployment_files(
                        deployment_path, private_key_pem, cert_pem, chain_pem
                    )
                    # The store copy only existed to extract the PEM for the
                    # file deployment — remove it so it isn't left sitting
                    # around exportable for no reason.
                    await self._delete_from_store(cert_info["thumbprint"], tmpdir)

            if post_install_hook:
                await self._run_post_install_hook(post_install_hook, cert_info)

            if deliver_key_to_central and private_key_pem:
                cert_info["private_key_pem"] = private_key_pem
                cert_info["cert_pem"] = cert_pem
                cert_info["chain_pem"] = chain_pem

            duration_ms = (time.monotonic() - start) * 1000
            return ScanResult(
                scanner_name=self.name,
                total_checked=1,
                total_new=1,
                certificates=[cert_info],
                errors=[],
                duration_ms=round(duration_ms, 2),
                metadata={
                    "ca_server": self.ca_server,
                    "ca_name": self.ca_name,
                    "operation": operation,
                    "template": template,
                },
            )
        except _AdcsCommandError as e:
            return self._failure_result(operation, [str(e)], start)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
            self._cleanup_html_logs(html_cutoff)

    def _failure_result(self, operation: str, errors: list[str], start: float) -> ScanResult:
        duration_ms = (time.monotonic() - start) * 1000
        return ScanResult(
            scanner_name=self.name,
            total_checked=0 if operation == "revoke" else 1,
            total_new=0,
            total_errors=1,
            certificates=[],
            errors=errors,
            duration_ms=round(duration_ms, 2),
            metadata={"operation": operation},
        )

    async def _run_cmd(self, args: list[str], cwd: str, timeout: int = 120) -> str:
        """Run a certreq/certutil subprocess, raising on failure or timeout."""
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            raise _AdcsCommandError(f"{args[0]} timed out after {timeout}s") from None

        output = stdout.decode(errors="replace")
        if proc.returncode != 0:
            raise _AdcsCommandError(
                f"{' '.join(args[:2])} failed (exit {proc.returncode}): "
                f"{stderr.decode(errors='replace')[:800] or output[:800]}"
            )
        return output

    @staticmethod
    def _inf_escape(value: str) -> str:
        """Strip characters that would break out of an INF value's quotes."""
        return str(value).replace('"', "").replace("\n", "").replace("\r", "")

    def _build_inf(self, common_name: str, sans: list[str], template: str, exportable: bool) -> str:
        """Build a certreq .inf request file.

        SANs use the OID-keyed [Extensions] + _continue_ line-folding
        syntax — not a simple field — per current Microsoft documentation.
        """
        cn = self._inf_escape(common_name)
        lines = [
            "[NewRequest]",
            f'Subject = "CN={cn}"',
            "KeySpec = 1",
            "KeyLength = 2048",
            f"Exportable = {'TRUE' if exportable else 'FALSE'}",
            "MachineKeySet = TRUE",
            'ProviderName = "Microsoft RSA SChannel Cryptographic Provider"',
            "RequestType = PKCS10",
            "HashAlgorithm = SHA256",
            f'CertificateTemplate = "{self._inf_escape(template)}"',
        ]

        all_sans = [cn] + [self._inf_escape(s) for s in sans if s and s != common_name]
        if all_sans:
            lines.append("")
            lines.append("[Extensions]")
            lines.append('2.5.29.17 = "{text}"')
            for i, san in enumerate(all_sans):
                suffix = "&" if i < len(all_sans) - 1 else ""
                lines.append(f'_continue_ = "dns={san}{suffix}"')

        return "\n".join(lines) + "\n"

    @staticmethod
    def _load_cert_file(path: str) -> x509.Certificate:
        """Load an issued certificate — certreq's output may be PEM or DER."""
        data = Path(path).read_bytes()
        try:
            return x509.load_pem_x509_certificate(data)
        except ValueError:
            return x509.load_der_x509_certificate(data)

    def _normalize_issued_cert(self, cert: x509.Certificate, template: str) -> dict:
        """Build the same normalized shape _normalize_cert() produces for
        discovery, from a freshly-issued certificate object."""
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            cn = ""

        sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = list(san_ext.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass

        template_lower = template.lower()
        cert_type = "server"
        if "user" in template_lower or "client" in template_lower:
            cert_type = "client"
        elif "codesign" in template_lower:
            cert_type = "code_signing"
        elif "subca" in template_lower or "subordinate" in template_lower:
            cert_type = "ca"

        signature_algorithm = (
            cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "SHA256"
        )

        return {
            "common_name": cn,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": format(cert.serial_number, "x"),
            "thumbprint": cert.fingerprint(hashes.SHA256()).hex(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "key_algorithm": "RSA-2048",
            "signature_algorithm": signature_algorithm,
            "sans": sans,
            "cert_type": cert_type,
            "is_wildcard": cn.startswith("*."),
            "is_ca": "ca" in template_lower,
            "request_id": "",
            "template": template,
            "status": "active",
            "source": "adcs",
        }

    @staticmethod
    def _split_pfx(pfx_path: str, password: str) -> tuple[str, str, str]:
        """Extract private key + cert + chain PEM from an exported PFX."""
        data = Path(pfx_path).read_bytes()
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            data, password.encode("utf-8")
        )
        private_key_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode("utf-8")
        cert_pem = certificate.public_bytes(Encoding.PEM).decode("utf-8")
        chain_pem = "\n".join(
            c.public_bytes(Encoding.PEM).decode("utf-8") for c in (additional_certs or [])
        )
        return private_key_pem, cert_pem, chain_pem

    @staticmethod
    def _write_deployment_files(
        deployment_path: str, private_key_pem: str, cert_pem: str, chain_pem: str
    ) -> None:
        """Write the key + fullchain PEM to the configured deployment path.

        `deployment_path` is treated as a base path without extension —
        e.g. `C:\\certs\\mysite` becomes `mysite.key.pem` + `mysite.fullchain.pem`.
        """
        base = Path(deployment_path)
        base.parent.mkdir(parents=True, exist_ok=True)
        fullchain = f"{cert_pem}\n{chain_pem}".strip() + "\n"
        base.with_suffix(".key.pem").write_text(private_key_pem, encoding="utf-8")
        base.with_suffix(".fullchain.pem").write_text(fullchain, encoding="utf-8")

    async def _delete_from_store(self, thumbprint: str, tmpdir: str) -> None:
        """Remove the transient exportable store copy after a file export.

        Best-effort: the certificate was already successfully issued and
        deployed, so a cleanup failure here is logged, not raised.
        """
        try:
            await self._run_cmd(["certutil", "-delstore", "My", thumbprint], cwd=tmpdir)
        except _AdcsCommandError as e:
            logger.warning("adcs_store_cleanup_failed", thumbprint=thumbprint, error=str(e))

    @staticmethod
    def _cleanup_html_logs(since_ts: float) -> None:
        """Delete certutil's %TEMP%\\*.html action logs written during this
        operation — they can contain command details and must not be left
        sitting in a world-readable temp directory."""
        import glob

        for path in glob.glob(os.path.join(tempfile.gettempdir(), "*.html")):
            try:
                if os.path.getmtime(path) >= since_ts:
                    os.remove(path)
            except OSError:
                pass

    async def _run_post_install_hook(self, hook: str, cert_info: dict) -> None:
        """Run an optional post-install command after issuance/renewal.

        Best-effort: the certificate was already issued/deployed, so a
        failing hook is logged, not raised.
        """
        import shlex
        import sys

        env = os.environ.copy()
        env["CERTMANAGER_THUMBPRINT"] = cert_info.get("thumbprint", "")
        env["CERTMANAGER_SERIAL_NUMBER"] = cert_info.get("serial_number", "")
        env["CERTMANAGER_COMMON_NAME"] = cert_info.get("common_name", "")

        try:
            args = ["cmd", "/c", hook] if sys.platform == "win32" else shlex.split(hook)
            proc = await asyncio.create_subprocess_exec(
                *args,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode != 0:
                logger.warning(
                    "adcs_post_install_hook_failed",
                    hook=hook,
                    exit_code=proc.returncode,
                    stderr=stderr.decode(errors="replace")[:500],
                )
        except Exception as e:
            logger.warning("adcs_post_install_hook_error", hook=hook, error=str(e))
