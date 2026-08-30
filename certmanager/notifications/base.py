"""Notification backend ABC and dispatcher.

Each backend implements a common interface for sending alerts.
The dispatcher routes alert events to the appropriate channel types.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NotificationMessage:
    """A notification to be delivered through one or more channels."""

    title: str
    body: str
    severity: str  # info | warning | critical
    alert_event_id: Optional[str] = None
    cert_id: Optional[str] = None
    cert_common_name: Optional[str] = None
    action_url: Optional[str] = None
    metadata: dict = field(default_factory=dict)


class NotificationBackend(ABC):
    """Abstract Base Class for notification delivery backends."""

    channel_type: str = "base"

    @abstractmethod
    async def send(self, message: NotificationMessage, config: dict) -> bool:
        """Send a notification.

        Args:
            message: The notification to deliver.
            config: Channel-specific configuration dict.

        Returns:
            True if delivery was successful.
        """

    @abstractmethod
    async def test(self, config: dict) -> tuple[bool, str]:
        """Send a test notification to verify the channel configuration.

        Returns:
            Tuple of (success, message).
        """


class NotificationDispatcher:
    """Routes notifications to configured backends.

    Usage:
        dispatcher = NotificationDispatcher()
        dispatcher.register_backend(EmailBackend())
        await dispatcher.dispatch(message, channels)
    """

    def __init__(self):
        self._backends: dict[str, NotificationBackend] = {}

    def register_backend(self, backend: NotificationBackend) -> None:
        """Register a notification backend."""
        self._backends[backend.channel_type] = backend

    def get_backend(self, channel_type: str) -> Optional[NotificationBackend]:
        """Get a registered backend by channel type."""
        return self._backends.get(channel_type)

    async def dispatch(
        self, message: NotificationMessage, channels: list[dict]
    ) -> dict[str, bool]:
        """Send a notification through multiple channels.

        Args:
            message: The notification to deliver.
            channels: List of channel dicts with 'channel_type' and 'channel_config'.

        Returns:
            Dict mapping channel_type to delivery success.
        """
        results = {}

        for channel in channels:
            channel_type = channel.get("channel_type", "")
            channel_config = channel.get("channel_config", {})
            backend = self._backends.get(channel_type)

            if backend is None:
                results[channel_type] = False
                continue

            try:
                success = await backend.send(message, channel_config)
                results[channel_type] = success
            except Exception:
                results[channel_type] = False

        return results


# Global dispatcher singleton
_dispatcher: Optional[NotificationDispatcher] = None


def get_dispatcher() -> NotificationDispatcher:
    """Get or create the global notification dispatcher with all backends registered."""
    global _dispatcher

    if _dispatcher is None:
        _dispatcher = NotificationDispatcher()

        # Lazy import to avoid circular deps
        from certmanager.notifications.email_backend import EmailBackend
        from certmanager.notifications.slack_backend import SlackBackend
        from certmanager.notifications.teams_backend import TeamsBackend
        from certmanager.notifications.webhook_backend import WebhookBackend

        _dispatcher.register_backend(EmailBackend())
        _dispatcher.register_backend(SlackBackend())
        _dispatcher.register_backend(TeamsBackend())
        _dispatcher.register_backend(WebhookBackend())

    return _dispatcher
