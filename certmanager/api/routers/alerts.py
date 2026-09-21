"""Alerts router: rules, events, notification channels."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.core.exceptions import NotFoundError
from certmanager.core.models import (
    AlertEvent,
    AlertRule,
    AlertRuleChannel,
    NotificationChannel,
    User,
)

router = APIRouter()


class AlertRuleCreate(BaseModel):
    """Body for creating an alert rule."""

    name: str
    condition_type: str
    condition_config: dict
    severity: str = "warning"
    description: str | None = None
    scope_filter: dict | None = None
    cooldown_minutes: int = 60
    is_enabled: bool = True
    channel_ids: list[str] | None = None


class AlertRuleUpdate(BaseModel):
    """Body for updating an alert rule — all fields optional."""

    name: str | None = None
    description: str | None = None
    is_enabled: bool | None = None
    condition_config: dict | None = None
    severity: str | None = None
    cooldown_minutes: int | None = None
    scope_filter: dict | None = None
    channel_ids: list[str] | None = None


class ChannelCreate(BaseModel):
    """Body for creating a notification channel."""

    name: str
    channel_type: str
    config: dict = Field(default_factory=dict)


# --- Alert Rules ---


@router.get("/rules")
async def list_alert_rules(
    is_enabled: bool | None = Query(default=None),
    severity: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List configured alert rules."""
    query = select(AlertRule)
    if is_enabled is not None:
        query = query.where(AlertRule.is_enabled == is_enabled)
    if severity:
        query = query.where(AlertRule.severity == severity)

    result = await db.execute(query.order_by(AlertRule.created_at.desc()))
    rules = result.scalars().all()

    # Attached notification channels, grouped by rule
    link_result = await db.execute(
        select(AlertRuleChannel).where(
            AlertRuleChannel.alert_rule_id.in_([r.id for r in rules])
        )
    )
    channel_ids_by_rule: dict[str, list[str]] = {}
    for link in link_result.scalars().all():
        nc_id = (link.channel_config or {}).get("notification_channel_id")
        if nc_id:
            channel_ids_by_rule.setdefault(link.alert_rule_id, []).append(nc_id)

    return {
        "data": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "is_enabled": r.is_enabled,
                "condition_type": r.condition_type,
                "condition_config": r.condition_config,
                "scope_filter": r.scope_filter,
                "severity": r.severity,
                "cooldown_minutes": r.cooldown_minutes,
                "channel_ids": channel_ids_by_rule.get(r.id, []),
                "created_at": r.created_at.isoformat(),
            }
            for r in rules
        ],
        "total": len(rules),
    }


@router.post("/rules", status_code=201)
async def create_alert_rule(
    body: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Create a new alert rule with optional notification channels."""
    rule = AlertRule(
        name=body.name,
        description=body.description,
        condition_type=body.condition_type,
        condition_config=body.condition_config,
        severity=body.severity,
        scope_filter=body.scope_filter or {},
        cooldown_minutes=body.cooldown_minutes,
        is_enabled=body.is_enabled,
        created_by=current_user.id,
    )
    db.add(rule)
    await db.flush()

    # Attach notification channels if specified
    if body.channel_ids:
        for ch_id in body.channel_ids:
            ch = AlertRuleChannel(
                alert_rule_id=rule.id,
                channel_type="notification_channel",  # will need to resolve from channel
                channel_config={"notification_channel_id": ch_id},
            )
            db.add(ch)

    await db.flush()
    await db.refresh(rule)
    return {"data": {"id": rule.id, "name": rule.name, "status": "created"}}


@router.patch("/rules/{rule_id}")
async def update_alert_rule(
    rule_id: str,
    body: AlertRuleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update an alert rule."""
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise NotFoundError(f"Alert rule {rule_id} not found")

    for field in (
        "name",
        "description",
        "is_enabled",
        "condition_config",
        "severity",
        "cooldown_minutes",
        "scope_filter",
    ):
        value = getattr(body, field)
        if value is not None:
            setattr(rule, field, value)

    # Replace the channel associations when channel_ids is provided
    if body.channel_ids is not None:
        existing = await db.execute(
            select(AlertRuleChannel).where(AlertRuleChannel.alert_rule_id == rule.id)
        )
        for link in existing.scalars().all():
            await db.delete(link)
        for ch_id in body.channel_ids:
            db.add(
                AlertRuleChannel(
                    alert_rule_id=rule.id,
                    channel_type="notification_channel",
                    channel_config={"notification_channel_id": ch_id},
                )
            )

    await db.flush()
    return {"data": {"id": rule.id, "updated": True}}


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_alert_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Delete an alert rule and its associated channels."""
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise NotFoundError(f"Alert rule {rule_id} not found")
    await db.delete(rule)
    await db.flush()


# --- Alert Events ---


@router.get("/events")
async def list_alert_events(
    rule_id: str | None = Query(default=None),
    cert_id: str | None = Query(default=None),
    is_acknowledged: bool | None = Query(default=None),
    severity: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List alert events with filtering and pagination."""
    query = select(AlertEvent)
    if rule_id:
        query = query.where(AlertEvent.alert_rule_id == rule_id)
    if cert_id:
        query = query.where(AlertEvent.cert_id == cert_id)
    if is_acknowledged is not None:
        query = query.where(AlertEvent.is_acknowledged == is_acknowledged)
    if severity:
        query = query.where(AlertEvent.severity == severity)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    offset = (page - 1) * page_size
    query = query.order_by(AlertEvent.created_at.desc()).offset(offset).limit(page_size)

    result = await db.execute(query)
    events = result.scalars().all()

    return {
        "data": [
            {
                "id": e.id,
                "alert_rule_id": e.alert_rule_id,
                "cert_id": e.cert_id,
                "event_type": e.event_type,
                "severity": e.severity,
                "title": e.title,
                "description": e.description,
                "is_acknowledged": e.is_acknowledged,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.patch("/events/{event_id}/acknowledge")
async def acknowledge_alert(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Acknowledge an alert event."""
    result = await db.execute(select(AlertEvent).where(AlertEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise NotFoundError(f"Alert event {event_id} not found")

    event.is_acknowledged = True
    event.acknowledged_by = current_user.id
    event.acknowledged_at = datetime.now(UTC)
    await db.flush()

    return {"data": {"id": event.id, "acknowledged": True}}


# --- Notification Channels ---


@router.get("/channels")
async def list_channels(
    channel_type: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List notification channels."""
    query = select(NotificationChannel)
    if channel_type:
        query = query.where(NotificationChannel.channel_type == channel_type)

    result = await db.execute(query)
    channels = result.scalars().all()

    return {
        "data": [
            {
                "id": c.id,
                "name": c.name,
                "channel_type": c.channel_type,
                "is_verified": c.is_verified,
            }
            for c in channels
        ]
    }


@router.post("/channels", status_code=201)
async def create_channel(
    body: ChannelCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Create a notification channel."""
    channel = NotificationChannel(
        name=body.name,
        channel_type=body.channel_type,
        config=body.config,
    )
    db.add(channel)
    await db.flush()
    await db.refresh(channel)
    return {"data": {"id": channel.id, "name": channel.name, "channel_type": channel.channel_type}}


@router.post("/channels/{channel_id}/test")
async def test_channel(
    channel_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Send a test notification through a channel."""
    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise NotFoundError(f"Channel {channel_id} not found")

    from certmanager.notifications.base import get_dispatcher

    dispatcher = get_dispatcher()
    backend = dispatcher.get_backend(channel.channel_type)

    if not backend:
        return {
            "data": {
                "status": "error",
                "message": f"No backend registered for channel type: {channel.channel_type}",
            }
        }

    success, msg = await backend.test(channel.config or {})

    return {
        "data": {
            "status": "success" if success else "failed",
            "message": msg,
        }
    }
