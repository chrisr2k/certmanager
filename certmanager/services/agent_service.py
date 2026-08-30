"""Agent service — manages agent lifecycle, scan target config, and job dispatch.

Handles:
- Agent registration approval
- TLS scan target management (CIDR ranges stored centrally)
- Job creation for TLS scans
- Agent heartbeat processing and target sync
"""

from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.core.models import Agent, ScanJob

logger = structlog.get_logger()


class AgentService:
    """Manages agent configuration and scan target dispatch."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_scan_targets(self, agent_id: str) -> dict:
        """Get the scan target configuration for an agent.

        Returns:
            Dict with cidr_ranges, ports, and schedule info.
        """
        result = await self.db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()

        if not agent:
            raise ValueError(f"Agent {agent_id} not found")

        config = agent.config or {}

        return {
            "cidr_ranges": config.get("tls_cidr_ranges", []),
            "ports": config.get("tls_ports", [443, 8443, 636, 993, 995, 465, 3389]),
            "exclude_cidrs": config.get("tls_exclude_cidrs", []),
            "max_concurrency": config.get("tls_max_concurrency", 50),
            "timeout_seconds": config.get("tls_timeout_seconds", 5.0),
            "scan_schedule": config.get("tls_scan_schedule", "weekly"),  # daily, weekly, monthly
            "last_scan_at": config.get("tls_last_scan_at"),
        }

    async def update_scan_targets(
        self,
        agent_id: str,
        cidr_ranges: list[str] | None = None,
        ports: list[int] | None = None,
        exclude_cidrs: list[str] | None = None,
        scan_schedule: str | None = None,
    ) -> dict:
        """Update TLS scan target configuration for an agent.

        Args:
            agent_id: UUID of the agent.
            cidr_ranges: List of CIDR ranges to scan.
            ports: TCP ports to check for TLS.
            exclude_cidrs: CIDR ranges to exclude.
            scan_schedule: daily, weekly, monthly.

        Returns:
            Updated scan target dict.
        """
        result = await self.db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()

        if not agent:
            raise ValueError(f"Agent {agent_id} not found")

        config = dict(agent.config or {})

        if cidr_ranges is not None:
            config["tls_cidr_ranges"] = cidr_ranges
        if ports is not None:
            config["tls_ports"] = ports
        if exclude_cidrs is not None:
            config["tls_exclude_cidrs"] = exclude_cidrs
        if scan_schedule is not None:
            config["tls_scan_schedule"] = scan_schedule

        agent.config = config
        await self.db.flush()

        logger.info(
            "scan_targets_updated",
            agent_id=agent_id,
            agent_name=agent.name,
            cidr_count=len(config.get("tls_cidr_ranges", [])),
        )

        return await self.get_scan_targets(agent_id)

    async def create_tls_scan_job(
        self,
        agent_id: str,
        cidr_ranges: list[str] | None = None,
        ports: list[int] | None = None,
        triggered_by: str = "manual",
        triggered_by_user: str | None = None,
    ) -> str:
        """Create a TLS scan job and assign it to an agent.

        The agent will pick this up on its next poll cycle.

        Args:
            agent_id: UUID of the agent to execute the scan.
            cidr_ranges: CIDR ranges to scan (overrides agent defaults).
            ports: Ports to scan (overrides agent defaults).
            triggered_by: manual, schedule, api.
            triggered_by_user: User UUID if triggered manually.

        Returns:
            UUID of the created ScanJob.
        """
        targets = await self.get_scan_targets(agent_id)

        scope = {
            "agent_id": agent_id,
            "cidr_ranges": cidr_ranges or targets["cidr_ranges"],
            "ports": ports or targets["ports"],
        }

        job = ScanJob(
            job_type="tls_scan",
            status="pending",
            triggered_by=triggered_by,
            triggered_by_user=triggered_by_user,
            scope_config=scope,
        )
        self.db.add(job)
        await self.db.flush()
        await self.db.refresh(job)

        logger.info(
            "tls_scan_job_created",
            job_id=str(job.id),
            agent_id=agent_id,
            cidr_count=len(scope["cidr_ranges"]),
        )

        return str(job.id)

    async def get_tls_capable_agents(self) -> list[dict]:
        """Get all agents that support TLS scanning.

        Returns:
            List of agent dicts with their scan targets.
        """
        result = await self.db.execute(
            select(Agent).where(
                Agent.agent_type.in_(["tls_scanner", "generic"]),
                Agent.is_approved,
                Agent.status == "online",
            )
        )
        agents = result.scalars().all()

        return [
            {
                "id": str(a.id),
                "name": a.name,
                "datacenter_id": str(a.datacenter_id) if a.datacenter_id else None,
                "scan_targets": await self.get_scan_targets(str(a.id)),
            }
            for a in agents
        ]
