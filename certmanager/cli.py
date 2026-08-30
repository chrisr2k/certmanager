"""CertManager CLI — Typer-based command-line interface for operators.

Pattern follows entra-pentest's CLI structure:
- Subcommand groups for each resource type
- Rich output formatting
- Async commands via asyncio
"""

from __future__ import annotations

import asyncio
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from certmanager import __version__

app = typer.Typer(
    name="certmanager",
    help="Enterprise Certificate Management Platform CLI",
    no_args_is_help=True,
)

console = Console()


# ---------------------------------------------------------------------------
# Top-level commands
# ---------------------------------------------------------------------------
@app.callback()
def callback():
    """CertManager — multi-datacenter certificate lifecycle management."""


@app.command()
def version():
    """Show the CertManager version."""
    console.print(f"[bold green]CertManager[/] v{__version__}")


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host to bind"),
    port: int = typer.Option(8000, help="Port to bind"),
    reload: bool = typer.Option(False, help="Enable auto-reload (development)"),
):
    """Start the CertManager API server."""
    import uvicorn

    console.print(f"[bold]Starting CertManager API on {host}:{port}[/]")
    uvicorn.run(
        "certmanager.api.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@app.command()
def seed(
    admin_email: str = typer.Option("admin@certmanager.local", help="Admin email"),
    admin_password: str = typer.Option("changeme123", help="Admin password"),
):
    """Seed the database with RBAC roles, permissions, and admin user."""
    from certmanager.core.database import get_session_factory
    from certmanager.core.seed import seed_all

    async def _seed():
        factory = get_session_factory()
        async with factory() as session:
            result = await seed_all(session, admin_email=admin_email, admin_password=admin_password)
            console.print("[bold green]Seed complete![/]")
            console.print(f"  Roles: {', '.join(result['roles_created'])}")
            console.print(f"  Admin user: {result['admin_user']}")
            console.print(f"  Permissions: {result['permissions_total']}")
            console.print("\n[bold yellow]Change the admin password immediately![/]")

    asyncio.run(_seed())


@app.command()
def migrate(
    revision: str = typer.Option("head", help="Target revision"),
):
    """Run database migrations."""
    from alembic import command
    from alembic.config import Config

    alembic_cfg = Config("alembic/alembic.ini")
    command.upgrade(alembic_cfg, revision)
    console.print(f"[bold green]Migrations complete[/] — target: {revision}")


@app.command()
def createsuperuser(
    email: str = typer.Option(..., prompt=True, help="Admin email"),
    password: str = typer.Option(..., prompt=True, hide_input=True, help="Admin password"),
):
    """Create a superuser interactively."""
    from certmanager.core.database import get_session_factory
    from certmanager.core.seed import seed_admin_user

    async def _create():
        factory = get_session_factory()
        async with factory() as session:
            await seed_admin_user(session, email=email, password=password)
            await session.commit()
            console.print(f"[bold green]Superuser created:[/] {email}")

    asyncio.run(_create())


# ---------------------------------------------------------------------------
# Certificate commands
# ---------------------------------------------------------------------------
certs_app = typer.Typer(help="Certificate operations", no_args_is_help=True)
app.add_typer(certs_app, name="certs")


@certs_app.command("list")
def certs_list(
    status: Optional[str] = typer.Option(None, help="Filter by status"),
    expiring_in: Optional[int] = typer.Option(None, help="Expiring in N days"),
    dc: Optional[str] = typer.Option(None, help="Filter by datacenter code"),
    limit: int = typer.Option(50, help="Max results"),
):
    """List certificates."""
    console.print("[yellow]CLI certificate listing requires a running API server.[/]")
    console.print("Use the REST API at GET /api/v1/certificates or the web dashboard.")


@certs_app.command("show")
def certs_show(cert_id: str):
    """Show certificate details."""
    console.print(f"[yellow]Use: GET /api/v1/certificates/{cert_id}[/]")


# ---------------------------------------------------------------------------
# CA Authority commands
# ---------------------------------------------------------------------------
ca_app = typer.Typer(help="Certificate Authority operations", no_args_is_help=True)
app.add_typer(ca_app, name="ca")


@ca_app.command("list")
def ca_list():
    """List certificate authorities."""
    console.print("[yellow]Use: GET /api/v1/authorities or check the web dashboard.[/]")


@ca_app.command("test")
def ca_test(name: str = typer.Argument(..., help="CA name")):
    """Test connectivity to a CA."""
    console.print(f"[yellow]CA '{name}' connectivity test will be available in Phase 2.[/]")


# ---------------------------------------------------------------------------
# Scan commands
# ---------------------------------------------------------------------------
scan_app = typer.Typer(help="Discovery scan operations", no_args_is_help=True)
app.add_typer(scan_app, name="scan")


@scan_app.command("run")
def scan_run(
    scan_type: str = typer.Option("full_discovery", help="Scan type"),
):
    """Run a discovery scan."""
    console.print("[yellow]Use: POST /api/v1/scans to trigger a scan.[/]")


# ---------------------------------------------------------------------------
# Agent commands
# ---------------------------------------------------------------------------
agent_app = typer.Typer(help="Datacenter agent operations", no_args_is_help=True)
app.add_typer(agent_app, name="agent")


@agent_app.command("init")
def agent_init(
    url: str = typer.Option(..., help="Central CertManager API URL", prompt=True),
    psk: str = typer.Option(..., help="Pre-shared key for agent registration", prompt=True),
    agent_type: str = typer.Option("adcs", help="Agent type: adcs, tls_scanner, generic"),
    datacenter_code: str = typer.Option("", help="Datacenter code this agent belongs to"),
    name: str = typer.Option("", help="Agent name (defaults to hostname)"),
    config_path: str = typer.Option("agent_config.json", help="Config file path"),
):
    """Initialize agent configuration. Run once before starting the agent."""
    from certmanager.agent.config import AgentSettings, save_agent_config
    import socket

    settings = AgentSettings(
        api_url=url.rstrip("/"),
        psk=psk,
        agent_type=agent_type,
        datacenter_code=datacenter_code,
        agent_name=name or socket.gethostname(),
    )
    save_agent_config(settings, config_path)

    console.print(f"[green]Agent configuration written to {config_path}[/]")
    console.print(f"  Name: {settings.agent_name}")
    console.print(f"  Type: {settings.agent_type}")
    console.print(f"  API:  {settings.api_url}")
    console.print(f"  DC:   {settings.datacenter_code or '(not set)'}")
    # Auto-detect platform and show install instructions
    import platform
    system = platform.system()

    console.print()
    console.print("[bold]Next steps:[/]")

    if system == "Windows":
        console.print("  [bold]Windows Service:[/] deploy\\agent\\install.ps1 -ConfigPath agent_config.json")
        console.print("  [bold]Or run directly:[/] certmanager agent run")
    elif system == "Linux":
        console.print("  [bold]systemd:[/] sudo cp deploy/agent/certmanager-agent.service /etc/systemd/system/")
        console.print("  [bold]Docker:[/] docker run -v ./agent_config.json:/app/agent_config.json certmanager-agent")
        console.print("  [bold]Or run directly:[/] certmanager agent run")
    else:
        console.print("  [bold]Run directly:[/] certmanager agent run")
        console.print("  [bold]Docker:[/] docker run -v ./agent_config.json:/app/agent_config.json certmanager-agent")

    console.print("  [bold]Air-gap:[/] certmanager agent run-job <job-file>")


@agent_app.command("run")
def agent_run():
    """Run the agent main loop (polling mode)."""
    import asyncio
    from certmanager.agent.config import load_agent_config
    from certmanager.agent.agent import run_agent

    settings = load_agent_config()

    console.print(f"[bold]Starting CertManager Agent[/]")
    console.print(f"  Name: {settings.agent_name}")
    console.print(f"  Type: {settings.agent_type}")
    console.print(f"  API:  {settings.api_url}")
    console.print(f"  DC:   {settings.datacenter_code or '(not set)'}")

    exit_code = asyncio.run(run_agent(settings))
    raise typer.Exit(exit_code)


@agent_app.command("export")
def agent_export(
    output: str = typer.Option("agent_results.json", help="Output file path"),
):
    """Export buffered results for air-gap transfer."""
    from certmanager.agent.config import load_agent_config
    from certmanager.agent.local_db import LocalDB

    settings = load_agent_config()
    db = LocalDB(settings.local_db_path)

    pending = db.get_pending_results(limit=1000)

    if not pending:
        console.print("[yellow]No buffered results to export.[/]")
        return

    from certmanager.agent.api_client import AgentAPIClient

    path = AgentAPIClient.export_results(
        results=[p["result"] for p in pending],
        output_path=output,
        agent_name=settings.agent_name,
        secret=settings.psk,
    )

    console.print(f"[green]Exported {len(pending)} results to {path}[/]")
    console.print("[bold]Transfer this file to a machine with central API access and run:[/]")
    console.print(f"  certmanager import {path}")


@agent_app.command("run-job")
def agent_run_job(
    job_file: str = typer.Argument(..., help="Path to job definition JSON"),
    output: str = typer.Option("job_result.json", help="Output file for results"),
):
    """Run a job from a JSON file and export results (air-gap mode)."""
    import asyncio
    from pathlib import Path
    from certmanager.agent.config import load_agent_config
    from certmanager.agent.api_client import AgentAPIClient

    if not Path(job_file).exists():
        console.print(f"[red]Job file not found: {job_file}[/]")
        raise typer.Exit(1)

    settings = load_agent_config()
    job = AgentAPIClient.import_job_file(job_file)

    console.print(f"[bold]Running job from file:[/] {job_file}")
    console.print(f"  Job type: {job.get('job_type', 'unknown')}")

    async def _execute():
        from certmanager.agent.agent import CertManagerAgent

        agent_inst = CertManagerAgent(settings)
        agent_inst._local_db = None  # Don't buffer locally — we export manually
        agent_inst._api_client = AgentAPIClient(
            api_url=settings.api_url,
            agent_name=settings.agent_name,
            psk=settings.psk,
        )
        agent_inst._load_scanners()

        all_results = []
        for scanner in agent_inst._scanners:
            scope = job.get("scope_config", {})
            result = await scanner.scan(scope)
            all_results.append(result.to_api_result())

        # Export results
        AgentAPIClient.export_results(
            results=all_results,
            output_path=output,
            agent_name=settings.agent_name,
            secret=settings.psk,
        )
        console.print(f"[green]Job complete. Results exported to: {output}[/]")
        return all_results

    asyncio.run(_execute())


# ---------------------------------------------------------------------------
# Import command (for air-gap and manual imports)
# ---------------------------------------------------------------------------
@app.command()
def import_data(
    file: str = typer.Argument(..., help="JSON file of agent results to import"),
    api_url: str = typer.Option(None, help="Central API URL (uses config default if not set)"),
):
    """Import agent results into the central CertManager API."""
    from pathlib import Path
    from certmanager.agent.api_client import AgentAPIClient
    from certmanager.core.config import get_settings

    if not Path(file).exists():
        console.print(f"[red]File not found: {file}[/]")
        raise typer.Exit(1)

    settings = get_settings()

    # Verify integrity
    payload = AgentAPIClient.verify_export(file, secret=settings.agent.psk)
    if payload is None:
        console.print("[red]Export file verification FAILED — file may be tampered.[/]")
        raise typer.Exit(1)

    console.print(f"[green]Export file verified.[/]")
    console.print(f"  Agent: {payload.get('agent_name')}")
    console.print(f"  Exported: {payload.get('exported_at')}")
    console.print(f"  Results: {len(payload.get('results', []))}")

    # Submit each result to the central API via HTTP
    import asyncio
    import aiohttp

    api_base = api_url or f"http://localhost:{settings.api_port}"

    async def _submit():
        submitted = 0
        failed = 0

        async with aiohttp.ClientSession() as session:
            for result in payload.get("results", []):
                # Find the appropriate endpoint — for air-gap we POST directly
                # to the certificates import endpoint
                try:
                    # First, create a scan job to associate with
                    async with session.post(
                        f"{api_base}/api/v1/scans",
                        json={
                            "job_type": "manual_import",
                            "scope_config": {},
                        },
                        headers={"Content-Type": "application/json"},
                    ) as resp:
                        if resp.status == 201:
                            resp_data = await resp.json()
                            scan_job_id = resp_data.get("data", {}).get("scan_job_id")
                        else:
                            scan_job_id = None

                    # Submit certificates
                    certs = result.get("certificates", [])
                    for cert in certs:
                        try:
                            async with session.post(
                                f"{api_base}/api/v1/certificates",
                                json={
                                    "common_name": cert.get("common_name"),
                                    "subject": cert.get("subject"),
                                    "issuer": cert.get("issuer"),
                                    "serial_number": cert.get("serial_number"),
                                    "thumbprint_sha256": cert.get("thumbprint"),
                                    "not_before": cert.get("not_before"),
                                    "not_after": cert.get("not_after"),
                                    "validity_days": 365,
                                    "cert_type": cert.get("cert_type", "server"),
                                    "key_algorithm": cert.get("key_algorithm"),
                                    "signature_algorithm": cert.get("signature_algorithm"),
                                    "sans": cert.get("sans", []),
                                    "source_type": cert.get("source", "tls_scan"),
                                    "source_detail": cert.get("source_detail", {}),
                                },
                                headers={"Content-Type": "application/json"},
                            ) as cert_resp:
                                if cert_resp.status == 201:
                                    submitted += 1
                                else:
                                    failed += 1
                        except Exception:
                            failed += 1

                except Exception as e:
                    console.print(f"[red]API connection error: {e}[/]")
                    failed += len(result.get("certificates", []))
                    break

        console.print(f"\n[bold]Import complete:[/] {submitted} succeeded, {failed} failed")

    asyncio.run(_submit())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
