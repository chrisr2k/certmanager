"""Dashboard aggregation router — topology, health overview, multi-DC summary.

Provides aggregated views that span certificates, authorities, datacenters,
and agents. Used by the frontend dashboard and topology views.
"""

from __future__ import annotations

from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.core.models import (
    Agent,
    Certificate,
    CertificateAuthority,
    Datacenter,
    ScanJob,
    User,
)

router = APIRouter()


@router.get("/topology")
async def get_topology(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get the full multi-datacenter topology with health status.

    Returns datacenters, their CAs with health, agents with status,
    and certificate counts. Used by the topology view and dashboard.
    """
    # Load all datacenters with relationships
    dc_result = await db.execute(
        select(Datacenter)
        .where(Datacenter.is_active == True)
        .order_by(Datacenter.name)
    )
    datacenters = dc_result.scalars().all()

    # Aggregate certificate counts per DC
    cert_counts = await db.execute(
        select(
            Certificate.datacenter_id,
            Certificate.status,
            func.count(Certificate.id),
        )
        .where(Certificate.datacenter_id.isnot(None))
        .group_by(Certificate.datacenter_id, Certificate.status)
    )
    cert_by_dc: dict[str, dict[str, int]] = {}
    for dc_id, status, count in cert_counts.all():
        dc_id_str = str(dc_id)
        if dc_id_str not in cert_by_dc:
            cert_by_dc[dc_id_str] = {"active": 0, "expired": 0, "revoked": 0, "total": 0}
        cert_by_dc[dc_id_str][status] = count
        cert_by_dc[dc_id_str]["total"] += count

    # Load all CAs with health
    ca_result = await db.execute(
        select(CertificateAuthority)
        .where(CertificateAuthority.is_active == True)
        .order_by(CertificateAuthority.name)
    )
    all_cas = ca_result.scalars().all()

    # Load all agents
    agent_result = await db.execute(
        select(Agent).order_by(Agent.name)
    )
    all_agents = agent_result.scalars().all()

    # Build topology tree: DC → CAs + Agents
    topology = []
    for dc in datacenters:
        dc_id = str(dc.id)
        dc_cas = [ca for ca in all_cas if str(ca.datacenter_id) == dc_id]
        dc_agents = [a for a in all_agents if str(a.datacenter_id) == dc_id]
        cert_stats = cert_by_dc.get(dc_id, {"active": 0, "expired": 0, "revoked": 0, "total": 0})

        topology.append({
            "id": dc_id,
            "name": dc.name,
            "code": dc.code,
            "location": dc.location,
            "timezone": dc.timezone,
            "is_active": dc.is_active,
            "certificate_counts": cert_stats,
            "authorities": [
                {
                    "id": str(ca.id),
                    "name": ca.name,
                    "ca_type": ca.ca_type,
                    "health_status": ca.health_status,
                    "last_scan_at": ca.last_scan_at.isoformat() if ca.last_scan_at else None,
                    "last_scan_status": ca.last_scan_status,
                    "last_error": ca.last_error,
                }
                for ca in dc_cas
            ],
            "agents": [
                {
                    "id": str(a.id),
                    "name": a.name,
                    "agent_type": a.agent_type,
                    "status": a.status,
                    "is_approved": a.is_approved,
                    "hostname": a.hostname,
                    "last_heartbeat_at": a.last_heartbeat_at.isoformat() if a.last_heartbeat_at else None,
                }
                for a in dc_agents
            ],
        })

    # Unassigned CAs and agents
    unassigned_cas = [
        {
            "id": str(ca.id),
            "name": ca.name,
            "ca_type": ca.ca_type,
            "health_status": ca.health_status,
            "last_scan_at": ca.last_scan_at.isoformat() if ca.last_scan_at else None,
        }
        for ca in all_cas if ca.datacenter_id is None
    ]
    unassigned_agents = [
        {
            "id": str(a.id),
            "name": a.name,
            "agent_type": a.agent_type,
            "status": a.status,
            "last_heartbeat_at": a.last_heartbeat_at.isoformat() if a.last_heartbeat_at else None,
        }
        for a in all_agents if a.datacenter_id is None
    ]

    return {
        "data": {
            "datacenters": topology,
            "unassigned": {
                "authorities": unassigned_cas,
                "agents": unassigned_agents,
            },
            "summary": {
                "total_datacenters": len(topology),
                "total_authorities": len(all_cas),
                "total_agents": len(all_agents),
                "healthy_cas": sum(1 for ca in all_cas if ca.health_status == "healthy"),
                "unhealthy_cas": sum(1 for ca in all_cas if ca.health_status == "unhealthy"),
                "degraded_cas": sum(1 for ca in all_cas if ca.health_status == "degraded"),
                "online_agents": sum(1 for a in all_agents if a.status == "online"),
                "offline_agents": sum(1 for a in all_agents if a.status == "offline"),
            },
        }
    }


@router.get("/health")
async def get_health_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get aggregated CA health overview with recent scan history.

    Returns per-CA health details plus overall health summary for dashboard cards.
    """
    ca_result = await db.execute(
        select(CertificateAuthority)
        .where(CertificateAuthority.is_active == True)
        .order_by(CertificateAuthority.name)
    )
    authorities = ca_result.scalars().all()

    # Get recent scan jobs for health trends
    now = datetime.now(UTC)
    since = now - timedelta(hours=24)
    scans_result = await db.execute(
        select(ScanJob)
        .where(
            ScanJob.created_at >= since,
            ScanJob.job_type.in_(["ca_sync", "full_discovery"]),
        )
        .order_by(ScanJob.created_at.desc())
        .limit(50)
    )
    recent_scans = scans_result.scalars().all()

    # Group scans by hour for a timeline
    scan_timeline: dict[str, dict[str, int]] = {}
    for scan in recent_scans:
        hour_key = scan.created_at.strftime("%Y-%m-%dT%H:00")
        if hour_key not in scan_timeline:
            scan_timeline[hour_key] = {"success": 0, "failed": 0, "running": 0}
        if scan.status == "completed":
            scan_timeline[hour_key]["success"] += 1
        elif scan.status in ("failed",):
            scan_timeline[hour_key]["failed"] += 1
        else:
            scan_timeline[hour_key]["running"] += 1

    # Build CA health details
    ca_details = []
    for ca in authorities:
        # Count certs for this CA
        cert_count = (
            await db.execute(
                select(func.count(Certificate.id)).where(
                    Certificate.source_ca_id == str(ca.id)
                )
            )
        ).scalar() or 0

        # Get most recent scan for this CA
        latest_scan = None
        for scan in recent_scans:
            scope = scan.scope_config or {}
            ca_ids = scope.get("ca_ids", [])
            if str(ca.id) in ca_ids:
                latest_scan = {
                    "id": str(scan.id),
                    "status": scan.status,
                    "created_at": scan.created_at.isoformat(),
                    "total_checked": scan.total_checked,
                    "total_new": scan.total_new,
                    "total_errors": scan.total_errors,
                }
                break

        ca_details.append({
            "id": str(ca.id),
            "name": ca.name,
            "ca_type": ca.ca_type,
            "datacenter_id": str(ca.datacenter_id) if ca.datacenter_id else None,
            "health_status": ca.health_status,
            "last_scan_at": ca.last_scan_at.isoformat() if ca.last_scan_at else None,
            "last_scan_status": ca.last_scan_status,
            "last_error": ca.last_error,
            "certificate_count": cert_count,
            "latest_scan": latest_scan,
        })

    # Health timeline (last 24h, hourly buckets)
    timeline = [
        {
            "time": hour,
            "success": counts["success"],
            "failed": counts["failed"],
            "running": counts["running"],
        }
        for hour, counts in sorted(scan_timeline.items())
    ]

    return {
        "data": {
            "authorities": ca_details,
            "scan_timeline": timeline,
            "summary": {
                "total": len(ca_details),
                "healthy": sum(1 for c in ca_details if c["health_status"] == "healthy"),
                "unhealthy": sum(1 for c in ca_details if c["health_status"] == "unhealthy"),
                "degraded": sum(1 for c in ca_details if c["health_status"] == "degraded"),
                "unknown": sum(1 for c in ca_details if c["health_status"] == "unknown"),
                "total_certificates": sum(c["certificate_count"] for c in ca_details),
                "scans_last_24h": len(recent_scans),
            },
        }
    }
