"""Unit tests for the systemd installer (pure unit-rendering path)."""

from __future__ import annotations

from certmanager.agent.install import build_unit_content


class TestBuildUnitContent:
    def test_renders_core_fields(self):
        content = build_unit_content(
            exec_start="/venv/bin/python -m certmanager.cli agent run "
            "--config /opt/cm/agent_config.json --data-dir /opt/cm/agent_data",
            config_path="/opt/cm/agent_config.json",
            data_dir="/opt/cm/agent_data",
        )
        assert "Description=CertManager Datacenter Agent" in content
        assert "User=certmgr" in content
        assert "Group=certmgr" in content
        assert "Restart=always" in content
        assert "WantedBy=multi-user.target" in content

    def test_execstart_preserved_verbatim(self):
        exec_line = "/opt/agent/.venv/bin/python -m certmanager.cli agent run --config '/opt/agent/agent_config.json'"
        content = build_unit_content(
            exec_start=exec_line,
            config_path="/opt/agent/agent_config.json",
            data_dir="/opt/agent/agent_data",
        )
        assert f"ExecStart={exec_line}" in content

    def test_paths_in_security_directives(self):
        content = build_unit_content(
            exec_start="python -m certmanager.cli agent run --config c --data-dir d",
            config_path="/etc/cm/agent_config.json",
            data_dir="/var/lib/cm",
        )
        assert "ReadOnlyPaths=/etc/cm/agent_config.json" in content
        assert "ReadWritePaths=/var/lib/cm" in content
        assert "ProtectSystem=strict" in content

    def test_custom_user_and_description(self):
        content = build_unit_content(
            exec_start="x",
            config_path="/c/agent_config.json",
            data_dir="/c/data",
            user="certops",
            description="CertManager Agent (site-2)",
        )
        assert "User=certops" in content
        assert "Description=CertManager Agent (site-2)" in content

    def test_working_dir_defaults_to_config_parent(self):
        content = build_unit_content(
            exec_start="x",
            config_path="/opt/cm/agent_config.json",
            data_dir="/opt/cm/agent_data",
        )
        assert "WorkingDirectory=/opt/cm" in content
