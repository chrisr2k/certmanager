"""Microsoft Teams notification backend using incoming webhooks."""

from __future__ import annotations

import structlog

from certmanager.notifications.base import NotificationBackend, NotificationMessage

logger = structlog.get_logger()


class TeamsBackend(NotificationBackend):
    """Sends notifications to Microsoft Teams via incoming webhooks."""

    channel_type = "teams"

    async def send(self, message: NotificationMessage, config: dict) -> bool:
        """Send a notification to Microsoft Teams.

        Config expects:
            webhook_url: str — Teams incoming webhook URL
        """
        try:
            import aiohttp

            webhook_url = config.get("webhook_url", "")

            if not webhook_url:
                logger.warning("teams_no_webhook_url", title=message.title)
                return False

            # Teams Adaptive Card format
            severity_color = {
                "critical": "attention",
                "warning": "warning",
                "info": "accent",
            }.get(message.severity, "accent")

            facts = [{"name": "Severity", "value": message.severity.upper()}]
            if message.cert_common_name:
                facts.append({"name": "Certificate", "value": message.cert_common_name})

            actions = []
            if message.action_url:
                actions.append(
                    {
                        "type": "Action.OpenUrl",
                        "title": "View in CertManager",
                        "url": message.action_url,
                    }
                )

            payload = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "version": "1.4",
                            "body": [
                                {
                                    "type": "TextBlock",
                                    "size": "Large",
                                    "weight": "Bolder",
                                    "text": message.title,
                                    "color": severity_color,
                                    "wrap": True,
                                },
                                {
                                    "type": "TextBlock",
                                    "text": message.body,
                                    "wrap": True,
                                },
                                {
                                    "type": "FactSet",
                                    "facts": facts,
                                },
                            ],
                            "actions": actions,
                        },
                    }
                ],
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status in (200, 202, 204):
                        logger.info("teams_sent", title=message.title)
                        return True
                    else:
                        body = await resp.text()
                        logger.error("teams_failed", status=resp.status, body=body[:200])
                        return False

        except Exception as e:
            logger.error("teams_error", error=str(e), title=message.title)
            return False

    async def test(self, config: dict) -> tuple[bool, str]:
        """Send a test notification to Teams."""
        message = NotificationMessage(
            title="CertManager Test Notification",
            body="This is a test notification from CertManager. If you can see this, your Microsoft Teams integration is working correctly.",
            severity="info",
        )
        success = await self.send(message, config)
        if success:
            return True, "Test notification sent to Teams"
        return False, "Failed to send Teams notification — check webhook URL"
