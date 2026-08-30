"""Audit log viewer router (read-only, auditor role)."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.core.exceptions import NotFoundError
from certmanager.core.models import AuditLog, User

router = APIRouter()


@router.get("")
async def list_audit_logs(
    actor_id: Optional[str] = Query(default=None),
    resource_type: Optional[str] = Query(default=None),
    resource_id: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    from_date: Optional[datetime] = Query(default=None),
    to_date: Optional[datetime] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Query audit log entries with rich filtering."""
    query = select(AuditLog)

    if actor_id:
        query = query.where(AuditLog.actor_id == actor_id)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    if resource_id:
        query = query.where(AuditLog.resource_id == resource_id)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    if from_date:
        query = query.where(AuditLog.created_at >= from_date)
    if to_date:
        query = query.where(AuditLog.created_at <= to_date)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    offset = (page - 1) * page_size
    query = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(page_size)

    result = await db.execute(query)
    logs = result.scalars().all()

    return {
        "data": [
            {
                "id": log.id,
                "event_type": log.event_type,
                "actor_type": log.actor_type,
                "actor_id": log.actor_id,
                "actor_email": log.actor_email,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "action": log.action,
                "details": log.details,
                "ip_address": log.ip_address,
                "correlation_id": log.correlation_id,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.get("/{log_id}")
async def get_audit_log(
    log_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a single audit log entry."""
    result = await db.execute(select(AuditLog).where(AuditLog.id == log_id))
    log = result.scalar_one_or_none()
    if not log:
        raise NotFoundError(f"Audit log entry {log_id} not found")

    return {
        "data": {
            "id": log.id,
            "event_type": log.event_type,
            "actor_type": log.actor_type,
            "actor_id": log.actor_id,
            "actor_email": log.actor_email,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "action": log.action,
            "details": log.details,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "correlation_id": log.correlation_id,
            "created_at": log.created_at.isoformat(),
        }
    }
