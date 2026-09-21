"""Linux systemd service installer for the datacenter agent.

Usage (as root):
    certmanager agent install-service --config-path /opt/certmanager-agent/agent_config.json

Creates a dedicated system user, writes the systemd unit, and enables +
starts the service. Idempotent — safe to re-run after config changes.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

SERVICE_NAME = "certmanager-agent"
UNIT_PATH = Path("/etc/systemd/system") / f"{SERVICE_NAME}.service"

# Unit template. Placeholders:
#   {description} — unit Description line
#   {user}        — service user
#   {working_dir} — WorkingDirectory
#   {exec_start}  — full ExecStart command line
#   {config_path} — ReadOnlyPaths entry
#   {data_dir}    — ReadWritePaths entry
UNIT_TEMPLATE = """[Unit]
Description={description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={user}
EnvironmentFile=-{working_dir}/agent.env
WorkingDirectory={working_dir}
ExecStart={exec_start}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=certmanager-agent

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={data_dir}
ReadOnlyPaths={config_path}

# Limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""


def build_unit_content(
    exec_start: str,
    config_path: str,
    data_dir: str,
    user: str = "certmgr",
    working_dir: str | None = None,
    description: str = "CertManager Datacenter Agent",
) -> str:
    """Render the systemd unit for the given paths (pure — unit-testable)."""
    return UNIT_TEMPLATE.format(
        description=description,
        user=user,
        working_dir=working_dir or os.path.dirname(config_path),
        exec_start=exec_start,
        config_path=config_path,
        data_dir=data_dir,
    )


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def install_systemd_service(
    config_path: str,
    user: str = "certmgr",
    start: bool = True,
) -> str:
    """Install the agent as a systemd service. Returns the unit file path.

    Raises:
        RuntimeError: if not running as root.
    """
    if os.name != "posix" or not Path("/run/systemd/system").exists():
        raise RuntimeError("install-service is only supported on Linux with systemd")
    if os.geteuid() != 0:
        raise RuntimeError(
            "install-service must run as root: sudo certmanager agent install-service "
            f"--config-path {config_path}"
        )

    config = Path(config_path).resolve()
    if not config.is_file():
        raise FileNotFoundError(f"Agent config not found: {config} — run 'agent init' first")

    install_dir = config.parent
    data_dir = install_dir / "agent_data"

    # Dedicated service user (idempotent)
    if shutil.which("useradd") and subprocess.run(
        ["id", "-u", user], capture_output=True
    ).returncode != 0:
        _run([
            "useradd", "--system", f"--home", str(install_dir),
            "--shell", "/usr/sbin/nologin", user,
        ])

    # Directories + ownership
    data_dir.mkdir(parents=True, exist_ok=True)
    config.chmod(0o600)
    _run(["chown", "-R", f"{user}:{user}", str(install_dir)])

    # ExecStart uses the interpreter that is running THIS command — the
    # console script may be anywhere, but `python -m certmanager.cli` always
    # resolves inside the venv the wheel was installed into.
    python = shlex.quote(sys.executable)
    exec_start = (
        f"{python} -m certmanager.cli agent run "
        f"--config {shlex.quote(str(config))} --data-dir {shlex.quote(str(data_dir))}"
    )

    unit_content = build_unit_content(
        exec_start=exec_start,
        config_path=str(config),
        data_dir=str(data_dir),
        user=user,
    )
    UNIT_PATH.write_text(unit_content)

    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", SERVICE_NAME])
    if start:
        is_active = subprocess.run(
            ["systemctl", "is-active", "--quiet", SERVICE_NAME]
        ).returncode == 0
        _run(["systemctl", "restart" if is_active else "start", SERVICE_NAME])

    return str(UNIT_PATH)
