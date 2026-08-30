"""Alerting service — evaluates alert rules against the certificate inventory.

Condition types:
- expiry_days: Fire when certificate expires within N days
- issuer_match: Fire when certificate issuer matches a pattern
- status_change: Fire when a certificate becomes expired/revoked
- ct_new_cert: Fire when a new CT log entry is found for managed domains
- ca_health: Fire when a CA becomes unhealthy or degraded

Features:
- Deduplication: cooldown windows per rule prevent alert storms
- Severity levels: info, warning, critical
- Multi-channel dispatch: email, Slack, Teams, webhook
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.core.models import (
    AlertEvent,
    AlertRule,
    AlertRuleChannel,
    Certificate,
    CertificateAuthority,
    NotificationChannel,
)
from certmanager.notifications.base import (
    NotificationMessage,
    get_dispatcher,
)

logger = structlog.get_logger()


class AlertingService:
    """Evaluates alert rules and dispatches notifications."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.dispatcher = get_dispatcher()

    async def evaluate_all_rules(self) -> dict:
        """Evaluate all enabled alert rules.

        Called by the Celery alert worker on its schedule (every 5 min).

        Returns:
            Dict with {evaluated, triggered, errors} counts.
        """
        result = await self.db.execute(select(AlertRule).where(AlertRule.is_enabled))
        rules = result.scalars().all()

        stats = {"evaluated": 0, "triggered": 0, "errors": 0}

        for rule in rules:
            try:
                triggered = await self.evaluate_rule(rule)
                stats["evaluated"] += 1
                if triggered:
                    stats["triggered"] += 1
            except Exception as e:
                logger.error(
                    "rule_evaluation_error",
                    rule_id=str(rule.id),
                    rule_name=rule.name,
                    error=str(e),
                )
                stats["errors"] += 1

        logger.info("alert_evaluation_complete", **stats)
        return stats

    async def evaluate_rule(self, rule: AlertRule) -> bool:
        """Evaluate a single alert rule.

        Returns:
            True if the rule triggered and an alert event was created.
        """
        # Check cooldown: has this rule fired recently?
        if not self._check_cooldown(rule):
            return False

        # Evaluate condition
        matches = []
        condition_type = rule.condition_type
        condition_config = rule.condition_config or {}

        if condition_type == "expiry_days":
            matches = await self._check_expiry_days(condition_config, rule.scope_filter)
        elif condition_type == "issuer_match":
            matches = await self._check_issuer_match(condition_config, rule.scope_filter)
        elif condition_type == "status_change":
            matches = await self._check_status_change(condition_config, rule.scope_filter)
        elif condition_type == "ca_health":
            matches = await self._check_ca_health(condition_config, rule.scope_filter)
        elif condition_type == "ct_new_cert":
            # CT monitoring is handled separately by the CT worker
            return False
        else:
            logger.warning("unknown_condition_type", condition_type=condition_type)
            return False

        if not matches:
            return False

        # Create alert events and dispatch notifications
        for match in matches:
            await self._fire_alert(rule, match)

        return True

    # --- Condition checkers ---

    async def _check_expiry_days(self, config: dict, scope_filter: dict) -> list[dict]:
        """Check for certificates expiring within configured days.

        Config: {"days": 30} — fire when cert expires within 30 days.
        """
        days = config.get("days", 30)
        now = datetime.now(UTC)
        cutoff = now + timedelta(days=days)

        query = (
            select(Certificate)
            .where(
                Certificate.not_after >= now,
                Certificate.not_after <= cutoff,
                Certificate.status == "active",
            )
            .order_by(Certificate.not_after.asc())
        )

        query = self._apply_scope_filter(query, scope_filter)
        result = await self.db.execute(query)
        certs = result.scalars().all()

        return [
            {
                "cert_id": str(c.id),
                "common_name": c.common_name or "Unknown",
                "not_after": c.not_after.isoformat(),
                "days_left": (c.not_after - now).days,
                "issuer": c.issuer or "Unknown",
            }
            for c in certs
        ]

    async def _check_issuer_match(self, config: dict, scope_filter: dict) -> list[dict]:
        """Check for certificates matching an issuer pattern.

        Config: {"issuer_pattern": "CN=Test CA.*"} — regex pattern (can also be simple substring).
        """
        pattern = config.get("issuer_pattern", "")
        if not pattern:
            return []

        query = select(Certificate).where(Certificate.status == "active")

        # Try as regex first, fall back to LIKE
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            # Fetch and filter in Python (PostgreSQL ~ operator would be faster)
            result = await self.db.execute(query)
            certs = [c for c in result.scalars().all() if regex.search(c.issuer or "")]
        except re.error:
            # Use SQL LIKE
            query = query.where(Certificate.issuer.ilike(f"%{pattern}%"))
            result = await self.db.execute(query)
            certs = result.scalars().all()

        return [
            {
                "cert_id": str(c.id),
                "common_name": c.common_name or "Unknown",
                "issuer": c.issuer or "Unknown",
                "not_after": c.not_after.isoformat(),
            }
            for c in certs
        ]

    async def _check_status_change(self, config: dict, scope_filter: dict) -> list[dict]:
        """Check for certificates that recently changed to a specified status.

        Config: {"status": "expired", "within_hours": 24}
        """
        target_status = config.get("status", "expired")
        within_hours = config.get("within_hours", 24)
        since = datetime.now(UTC) - timedelta(hours=within_hours)

        query = (
            select(Certificate)
            .where(
                Certificate.status == target_status,
                Certificate.updated_at >= since,
            )
            .order_by(Certificate.updated_at.desc())
        )

        query = self._apply_scope_filter(query, scope_filter)
        result = await self.db.execute(query)
        certs = result.scalars().all()

        return [
            {
                "cert_id": str(c.id),
                "common_name": c.common_name or "Unknown",
                "status": c.status,
                "not_after": c.not_after.isoformat(),
            }
            for c in certs
        ]

    async def _check_ca_health(self, config: dict, scope_filter: dict) -> list[dict]:
        """Check for CAs that have become unhealthy or degraded.

        Config: {"health_status": "unhealthy"} or {"health_status": "degraded"}
        """
        target = config.get("health_status", "unhealthy")

        query = select(CertificateAuthority).where(
            CertificateAuthority.is_active,
            CertificateAuthority.health_status == target,
        )

        result = await self.db.execute(query)
        cas = result.scalars().all()

        return [
            {
                "ca_id": str(ca.id),
                "ca_name": ca.name,
                "ca_type": ca.ca_type,
                "health_status": ca.health_status,
                "last_error": ca.last_error,
            }
            for ca in cas
        ]

    def _apply_scope_filter(self, query, scope_filter: dict):
        """Apply scope filtering to a certificate query.

        Scope filter can restrict to specific datacenters, CA types, or cert types.
        """
        if not scope_filter:
            return query

        dc_ids = scope_filter.get("datacenter_ids", [])
        if dc_ids:
            query = query.where(Certificate.datacenter_id.in_(dc_ids))

        ca_ids = scope_filter.get("ca_ids", [])
        if ca_ids:
            query = query.where(Certificate.source_ca_id.in_(ca_ids))

        cert_types = scope_filter.get("cert_types", [])
        if cert_types:
            query = query.where(Certificate.cert_type.in_(cert_types))

        return query

    # --- Alert firing ---

    def _check_cooldown(self, rule: AlertRule) -> bool:
        """Check if the rule is still in its cooldown window.

        Cooldown prevents alert storms — if the rule fired recently,
        we skip evaluation until the cooldown expires.

        Returns:
            True if the rule is ready to evaluate (cooldown expired).
        """
        if not rule.cooldown_minutes:
            return True

        # Check most recent alert event for this rule
        # This is async but we need it sync here — use a simple approach
        return True  # Cooldown check done at event creation time

    async def _check_cooldown_async(self, rule: AlertRule) -> bool:
        """Async cooldown check — queries the database."""
        since = datetime.now(UTC) - timedelta(minutes=rule.cooldown_minutes)

        result = await self.db.execute(
            select(AlertEvent)
            .where(
                AlertEvent.alert_rule_id == str(rule.id),
                AlertEvent.created_at >= since,
            )
            .limit(1)
        )
        recent = result.scalar_one_or_none()

        return recent is None

    async def _fire_alert(self, rule: AlertRule, match: dict) -> None:
        """Create an alert event and dispatch notifications.

        Args:
            rule: The AlertRule that matched.
            match: Dict with matched entity details (cert or CA info).
        """
        # Cooldown check at fire time
        if not await self._check_cooldown_async(rule):
            logger.debug(
                "alert_cooldown_active",
                rule_name=rule.name,
                cooldown_minutes=rule.cooldown_minutes,
            )
            return

        # Build event message
        condition_type = rule.condition_type
        severity = rule.severity
        title, description = self._build_alert_message(rule, match)

        # Create alert event
        cert_id = match.get("cert_id")
        event = AlertEvent(
            alert_rule_id=str(rule.id),
            cert_id=cert_id,
            event_type=condition_type,
            severity=severity,
            title=title,
            description=description,
            context={
                "match": match,
                "rule_name": rule.name,
                "condition_type": condition_type,
                "condition_config": rule.condition_config,
            },
        )
        self.db.add(event)
        await self.db.flush()
        await self.db.refresh(event)

        # Build notification message
        action_url = None
        if cert_id:
            action_url = f"/certificates/{cert_id}"

        message = NotificationMessage(
            title=title,
            body=description,
            severity=severity,
            alert_event_id=str(event.id),
            cert_id=cert_id,
            cert_common_name=match.get("common_name"),
            action_url=action_url,
            metadata={"timestamp": datetime.now(UTC).isoformat()},
        )

        # Get channels for this rule
        channels_result = await self.db.execute(
            select(AlertRuleChannel).where(AlertRuleChannel.alert_rule_id == str(rule.id))
        )
        rule_channels = channels_result.scalars().all()

        if not rule_channels:
            logger.info(
                "alert_no_channels",
                rule_name=rule.name,
                event_id=str(event.id),
            )
            return

        # Dispatch to each channel
        for rule_channel in rule_channels:
            # Resolve notification channel config
            channel_config = rule_channel.channel_config or {}

            # If this references a NotificationChannel, load its config
            nc_id = channel_config.get("notification_channel_id")
            if nc_id:
                nc_result = await self.db.execute(
                    select(NotificationChannel).where(NotificationChannel.id == nc_id)
                )
                nc = nc_result.scalar_one_or_none()
                if nc:
                    channel_type = nc.channel_type
                    channel_config = {**nc.config, **channel_config}
                else:
                    channel_type = rule_channel.channel_type
            else:
                channel_type = rule_channel.channel_type

            # Send via dispatcher
            results = await self.dispatcher.dispatch(
                message,
                [{"channel_type": channel_type, "channel_config": channel_config}],
            )

            success = results.get(channel_type, False)
            logger.info(
                "alert_dispatched",
                rule_name=rule.name,
                channel_type=channel_type,
                success=success,
                event_id=str(event.id),
            )

    def _build_alert_message(self, rule: AlertRule, match: dict) -> tuple[str, str]:
        """Build a human-readable alert title and description from a match.

        Returns:
            Tuple of (title, description).
        """
        condition_type = rule.condition_type

        if condition_type == "expiry_days":
            cn = match.get("common_name", "Unknown")
            days = match.get("days_left", "?")
            title = f"Certificate expiring in {days} days: {cn}"
            description = (
                f"The certificate **{cn}** will expire on "
                f"**{match.get('not_after', 'unknown')}** ({days} days remaining).\n\n"
                f"Issuer: {match.get('issuer', 'Unknown')}\n"
                f"Rule: {rule.name}"
            )

        elif condition_type == "issuer_match":
            cn = match.get("common_name", "Unknown")
            issuer = match.get("issuer", "Unknown")
            title = f"Certificate issued by matched issuer: {cn}"
            description = (
                f"The certificate **{cn}** was issued by **{issuer}**, "
                f"which matches the pattern configured in rule '{rule.name}'."
            )

        elif condition_type == "status_change":
            cn = match.get("common_name", "Unknown")
            status = match.get("status", "unknown")
            title = f"Certificate status changed to {status}: {cn}"
            description = (
                f"The certificate **{cn}** has changed status to **{status}**.\n\n"
                f"Expiry: {match.get('not_after', 'unknown')}\n"
                f"Rule: {rule.name}"
            )

        elif condition_type == "ca_health":
            ca_name = match.get("ca_name", "Unknown")
            health = match.get("health_status", "unhealthy")
            error = match.get("last_error", "No error details")
            title = f"CA {health}: {ca_name}"
            description = (
                f"The certificate authority **{ca_name}** is reporting "
                f"health status **{health}**.\n\n"
                f"Error: {error}\n"
                f"Rule: {rule.name}"
            )

        else:
            title = f"Alert: {rule.name}"
            description = f"Alert rule '{rule.name}' triggered with match: {match}"

        return title, description
