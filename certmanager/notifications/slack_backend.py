"""Slack notification backend using incoming webhooks."""

from __future__ import annotations

import structlog

from certmanager.notifications.base import NotificationBackend, NotificationMessage

logger = structlog.get_logger()


class SlackBackend(NotificationBackend):
    """Sends notifications to Slack via incoming webhooks."""

    channel_type = "slack"

    async def send(self, message: NotificationMessage, config: dict) -> bool:
        """Send a notification to Slack.

        Config expects:
            webhook_url: str — Slack incoming webhook URL
            channel: str (optional) — Override the default channel
        """
        try:
            import aiohttp

            webhook_url = config.get("webhook_url", "")

            if not webhook_url:
                logger.warning("slack_no_webhook_url", title=message.title)
                return False

            # Slack message formatting
            severity_color = {
                "critical": "#ff4d4f",
                "warning": "#faad14",
                "info": "#1677ff",
            }.get(message.severity, "#1677ff")

            severity_emoji = {
                "critical": ":red_circle:",
                "warning": ":warning:",
                "info": ":information_source:",
            }.get(message.severity, ":bell:")

            blocks = [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{severity_emoji} {message.title}"},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message.body},
                },
            ]

            if message.cert_common_name:
                blocks.append(
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Certificate:*\n{message.cert_common_name}",
                            },
                            {"type": "mrkdwn", "text": f"*Severity:*\n{message.severity.upper()}"},
                        ],
                    }
                )

            if message.action_url:
                blocks.append(
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "View in CertManager"},
                                "url": message.action_url,
                                "style": "primary",
                            }
                        ],
                    }
                )

            payload = {
                "attachments": [
                    {
                        "color": severity_color,
                        "blocks": blocks,
                    }
                ]
            }

            if config.get("channel"):
                payload["channel"] = config["channel"]

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status in (200, 204):
                        logger.info("slack_sent", title=message.title)
                        return True
                    else:
                        body = await resp.text()
                        logger.error("slack_failed", status=resp.status, body=body[:200])
                        return False

        except Exception as e:
            logger.error("slack_error", error=str(e), title=message.title)
            return False

    async def test(self, config: dict) -> tuple[bool, str]:
        """Send a test notification to Slack."""
        message = NotificationMessage(
            title="CertManager Test Notification",
            body="This is a test notification from CertManager. If you can see this, your Slack integration is working correctly.",
            severity="info",
        )
        success = await self.send(message, config)
        if success:
            return True, "Test notification sent to Slack"
        return False, "Failed to send Slack notification — check webhook URL"
