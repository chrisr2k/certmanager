"""AD CS lifecycle tests: issue/renew/revoke via certreq/certutil.

certreq.exe and certutil.exe only exist on Windows with AD CS tools
installed, so every subprocess call is mocked. The [Extensions] SAN block
is the easiest part of the INF file to get subtly wrong, so it gets its
own direct test independent of the subprocess mocking.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from certmanager.agent.scanners.adcs_scanner import ADCSLocalScanner, _AdcsCommandError


def _make_self_signed_cert(common_name: str = "www.example.com", sans: list[str] | None = None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    return key, cert


class _FakeProc:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr

    def kill(self):
        pass


def _subprocess_mock(tmpdir: Path, key, cert, pfx_password_holder: dict):
    """Side-effect function for asyncio.create_subprocess_exec.

    Inspects argv to decide what file (if any) a real certreq/certutil
    invocation would have produced, and writes it so downstream parsing
    (x509 loading, PFX splitting) has real bytes to work with.
    """

    async def _run(*args, cwd=None, **kwargs):
        argv = list(args)
        if argv[0] == "certreq":
            if argv[1] == "-new":
                # request.inf -> request.req; nothing downstream reads the
                # .req contents (certutil -submit is mocked wholesale).
                Path(argv[-1]).write_text("FAKE-CSR")
                return _FakeProc(0)
            if argv[1] == "-submit":
                cer_path = argv[-1]
                Path(cer_path).write_bytes(cert.public_bytes(serialization.Encoding.DER))
                return _FakeProc(0, stdout=b"Certificate issued")
            if argv[1] == "-accept":
                return _FakeProc(0)
        if argv[0] == "certutil":
            if argv[1] == "-exportPFX":
                password = argv[3]
                pfx_password_holder["password"] = password
                pfx_path = argv[-1]
                pfx_bytes = pkcs12.serialize_key_and_certificates(
                    name=b"certmanager",
                    key=key,
                    cert=cert,
                    cas=None,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        password.encode("utf-8")
                    ),
                )
                Path(pfx_path).write_bytes(pfx_bytes)
                return _FakeProc(0)
            if argv[1] == "-delstore":
                return _FakeProc(0)
            if "-revoke" in argv:
                return _FakeProc(0, stdout=b"Revoked")
        raise AssertionError(f"Unexpected subprocess invocation: {argv}")

    return _run


@pytest.fixture
def scanner():
    return ADCSLocalScanner(ca_server="ca01.corp.internal", ca_name="CORP-ROOT-CA")


class TestBuildInf:
    def test_single_san_matching_cn(self, scanner):
        inf = scanner._build_inf("www.example.com", [], "WebServer", exportable=False)
        assert 'Subject = "CN=www.example.com"' in inf
        assert "Exportable = FALSE" in inf
        assert 'CertificateTemplate = "WebServer"' in inf
        assert "[Extensions]" in inf
        assert '2.5.29.17 = "{text}"' in inf
        assert '_continue_ = "dns=www.example.com"' in inf

    def test_multiple_sans_use_continuation_syntax(self, scanner):
        inf = scanner._build_inf(
            "www.example.com", ["api.example.com", "admin.example.com"], "WebServer", True
        )
        lines = inf.splitlines()
        continue_lines = [ln for ln in lines if ln.startswith("_continue_")]
        assert continue_lines == [
            '_continue_ = "dns=www.example.com&"',
            '_continue_ = "dns=api.example.com&"',
            '_continue_ = "dns=admin.example.com"',
        ]
        assert "Exportable = TRUE" in inf

    def test_duplicate_san_equal_to_cn_not_repeated(self, scanner):
        inf = scanner._build_inf("www.example.com", ["www.example.com"], "WebServer", False)
        assert inf.count("dns=www.example.com") == 1

    def test_quotes_and_newlines_stripped_from_injected_values(self, scanner):
        malicious_cn = 'evil" \ninjected'
        escaped = scanner._inf_escape(malicious_cn)
        assert '"' not in escaped
        assert "\n" not in escaped

        inf = scanner._build_inf(malicious_cn, [], "WebServer", False)
        subject_line = next(ln for ln in inf.splitlines() if ln.startswith("Subject"))
        # Exactly the two quotes this line is supposed to have — the
        # injected quote/newline can't break out of the Subject value.
        assert subject_line.count('"') == 2


class TestIssue:
    async def test_issue_store_only_no_key_leaves_agent(self, scanner, tmp_path):
        key, cert = _make_self_signed_cert("www.example.com", ["www.example.com"])
        password_holder: dict = {}

        with patch("certmanager.agent.scanners.adcs_scanner.tempfile.mkdtemp", return_value=str(tmp_path)):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=_subprocess_mock(tmp_path, key, cert, password_holder),
            ):
                result = await scanner.issue(
                    {
                        "common_name": "www.example.com",
                        "template": "WebServer",
                        "deployment_target": "store",
                        "deliver_key_to_central": False,
                    }
                )

        assert result.total_errors == 0
        assert len(result.certificates) == 1
        issued = result.certificates[0]
        assert issued["common_name"] == "www.example.com"
        assert issued["source"] == "adcs"
        assert "private_key_pem" not in issued
        # No PFX export at all when neither file deployment nor central
        # delivery is requested — the key never leaves the store.
        assert "password" not in password_holder

    async def test_issue_with_deliver_key_to_central_includes_private_key(self, scanner, tmp_path):
        key, cert = _make_self_signed_cert("www.example.com")
        password_holder: dict = {}

        with patch("certmanager.agent.scanners.adcs_scanner.tempfile.mkdtemp", return_value=str(tmp_path)):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=_subprocess_mock(tmp_path, key, cert, password_holder),
            ):
                result = await scanner.issue(
                    {
                        "common_name": "www.example.com",
                        "template": "WebServer",
                        "deployment_target": "store",
                        "deliver_key_to_central": True,
                    }
                )

        assert result.total_errors == 0
        issued = result.certificates[0]
        assert "BEGIN PRIVATE KEY" in issued["private_key_pem"]
        assert "BEGIN CERTIFICATE" in issued["cert_pem"]
        assert password_holder["password"], "a random PFX password was generated"

    async def test_issue_file_deployment_writes_files_and_cleans_store(self, scanner, tmp_path):
        key, cert = _make_self_signed_cert("www.example.com")
        password_holder: dict = {}
        # Distinct from the scanner's own tmpdir below — that one gets
        # rmtree'd in a finally block, and must not take the deployment
        # output down with it.
        agent_tmpdir = tmp_path / "agent_tmp"
        agent_tmpdir.mkdir()
        deploy_base = tmp_path / "deployed" / "mysite"

        calls = []

        async def _run_with_tracking(*args, **kwargs):
            calls.append(list(args))
            return await _subprocess_mock(agent_tmpdir, key, cert, password_holder)(*args, **kwargs)

        with patch(
            "certmanager.agent.scanners.adcs_scanner.tempfile.mkdtemp", return_value=str(agent_tmpdir)
        ):
            with patch("asyncio.create_subprocess_exec", side_effect=_run_with_tracking):
                result = await scanner.issue(
                    {
                        "common_name": "www.example.com",
                        "template": "WebServer",
                        "deployment_target": "file",
                        "deployment_path": str(deploy_base),
                        "deliver_key_to_central": False,
                    }
                )

        assert result.total_errors == 0
        assert (deploy_base.parent / "mysite.key.pem").exists()
        assert "BEGIN PRIVATE KEY" in (deploy_base.parent / "mysite.key.pem").read_text()
        assert (deploy_base.parent / "mysite.fullchain.pem").exists()
        # The transient store copy must be removed after a file export.
        assert any(c[0] == "certutil" and c[1] == "-delstore" for c in calls)
        # Result sent to central carries no key — file delivery, not opt-in.
        assert "private_key_pem" not in result.certificates[0]

    async def test_issue_missing_template_fails_without_subprocess_calls(self, scanner):
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            result = await scanner.issue({"common_name": "www.example.com", "template": ""})
        mock_exec.assert_not_called()
        assert result.total_errors == 1
        assert "template is required" in result.errors[0]

    async def test_issue_pending_template_is_a_clear_failure(self, scanner, tmp_path):
        async def _run(*args, cwd=None, **kwargs):
            argv = list(args)
            if argv[0] == "certreq" and argv[1] == "-new":
                Path(argv[-1]).write_text("FAKE-CSR")
                return _FakeProc(0)
            if argv[0] == "certreq" and argv[1] == "-submit":
                # No .cer file written — simulates a pending RequestID.
                return _FakeProc(0, stdout=b"RequestId: 42, Certificate Pending")
            raise AssertionError(f"Unexpected call: {argv}")

        with patch("certmanager.agent.scanners.adcs_scanner.tempfile.mkdtemp", return_value=str(tmp_path)):
            with patch("asyncio.create_subprocess_exec", side_effect=_run):
                result = await scanner.issue(
                    {"common_name": "www.example.com", "template": "ManualApprovalTemplate"}
                )

        assert result.total_errors == 1
        assert "manual approval" in result.errors[0].lower()

    async def test_issue_certreq_failure_is_captured(self, scanner, tmp_path):
        async def _run(*args, cwd=None, **kwargs):
            return _FakeProc(1, stderr=b"Denied by policy module")

        with patch("certmanager.agent.scanners.adcs_scanner.tempfile.mkdtemp", return_value=str(tmp_path)):
            with patch("asyncio.create_subprocess_exec", side_effect=_run):
                result = await scanner.issue(
                    {"common_name": "www.example.com", "template": "WebServer"}
                )

        assert result.total_errors == 1
        assert "Denied by policy module" in result.errors[0]

    async def test_renew_behaves_like_issue(self, scanner, tmp_path):
        key, cert = _make_self_signed_cert("www.example.com")
        password_holder: dict = {}

        with patch("certmanager.agent.scanners.adcs_scanner.tempfile.mkdtemp", return_value=str(tmp_path)):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=_subprocess_mock(tmp_path, key, cert, password_holder),
            ):
                result = await scanner.renew(
                    {
                        "common_name": "www.example.com",
                        "template": "WebServer",
                        "deployment_target": "store",
                    }
                )

        assert result.total_errors == 0
        assert result.metadata["operation"] == "renew"


class TestRevoke:
    async def test_revoke_success(self, scanner, tmp_path):
        async def _run(*args, **kwargs):
            assert "-revoke" in args
            return _FakeProc(0, stdout=b"Revoked")

        with patch("certmanager.agent.scanners.adcs_scanner.tempfile.mkdtemp", return_value=str(tmp_path)):
            with patch("asyncio.create_subprocess_exec", side_effect=_run):
                result = await scanner.revoke({"serial_number": "aabbcc", "reason_code": 0})

        assert result.total_errors == 0
        assert result.metadata["serial_number"] == "aabbcc"

    async def test_revoke_missing_serial_fails_fast(self, scanner):
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            result = await scanner.revoke({"serial_number": ""})
        mock_exec.assert_not_called()
        assert result.total_errors == 1
        assert "serial_number is required" in result.errors[0]

    async def test_revoke_certutil_failure_is_captured(self, scanner, tmp_path):
        async def _run(*args, **kwargs):
            return _FakeProc(1, stderr=b"Access denied")

        with patch("certmanager.agent.scanners.adcs_scanner.tempfile.mkdtemp", return_value=str(tmp_path)):
            with patch("asyncio.create_subprocess_exec", side_effect=_run):
                result = await scanner.revoke({"serial_number": "aabbcc"})

        assert result.total_errors == 1
        assert "Access denied" in result.errors[0]


class TestRunCmdTimeout:
    async def test_timeout_raises_adcs_command_error(self, scanner, tmp_path):
        class _HangingProc(_FakeProc):
            async def communicate(self):
                import asyncio

                await asyncio.sleep(10)
                return b"", b""

        async def _run(*args, **kwargs):
            return _HangingProc(0)

        with patch("asyncio.create_subprocess_exec", side_effect=_run):
            with pytest.raises(_AdcsCommandError, match="timed out"):
                await scanner._run_cmd(["certreq", "-new"], cwd=str(tmp_path), timeout=0.01)
