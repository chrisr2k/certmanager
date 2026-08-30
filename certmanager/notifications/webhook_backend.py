"""Generic webhook notification backend."""

from __future__ import annotations

import structlog
from certmanager.notifications.base import NotificationBackend, NotificationMessage

logger = structlog.get_logger()


class WebhookBackend(NotificationBackend):
    """Sends notifications to a generic HTTP webhook endpoint.

    POSTs JSON payloads. Supports custom headers for authentication.
    """

    channel_type = "webhook"

    async def send(self, message: NotificationMessage, config: dict) -> bool:
        """Send a notification to a webhook endpoint.

        Config expects:
            url: str — Webhook URL
            method: str (optional) — HTTP method (default POST)
            headers: dict (optional) — Custom HTTP headers
            template: str (optional) — "default" or "custom"
            custom_payload: dict (optional) — Custom JSON payload template
        """
        try:
            import aiohttp

            url = config.get("url", "")

            if not url:
                logger.warning("webhook_no_url", title=message.title)
                return False

            method = config.get("method", "POST").upper()
            headers = config.get("headers", {})
            headers.setdefault("Content-Type", "application/json")

            # Build payload
            if config.get("template") == "custom" and config.get("custom_payload"):
                import json
                payload = json.loads(
                    json.dumps(config["custom_payload"])
                    .replace("{{title}}", message.title)
                    .replace("{{body}}", message.body)
                    .replace("{{severity}}", message.severity)
                )
            else:
                # Default webhook payload format
                payload = {
                    "event": "certmanager.alert",
                    "title": message.title,
                    "body": message.body,
                    "severity": message.severity,
                    "alert_event_id": message.alert_event_id,
                    "cert_id": message.cert_id,
                    "cert_common_name": message.cert_common_name,
                    "timestamp": message.metadata.get("timestamp"),
                }
                # Remove None values
                payload = {k: v for k, v in payload.items() if v is not None}

            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method, url, json=payload, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status < 500:
                        logger.info("webhook_sent", url=url, status=resp.status, title=message.title)
                        return True
                    else:
                        body = await resp.text()
                        logger.error("webhook_failed", url=url, status=resp.status, body=body[:200])
                        return False

        except Exception as e:
            logger.error("webhook_error", error=str(e), title=message.title)
            return False

    async def test(self, config: dict) -> tuple[bool, str]:
        """Send a test notification to the webhook."""
        message = NotificationMessage(
            title="CertManager Test Notification",
            body="This is a test notification from CertManager. If you received this, your webhook endpoint is configured correctly.",
            severity="info",
        )
        success = await self.send(message, config)
        if success:
            return True, "Test webhook notification sent successfully"
        return False, "Failed to send webhook notification — check URL and connectivity"
