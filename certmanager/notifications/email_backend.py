"""Email notification backend using SMTP."""

from __future__ import annotations

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import structlog
from certmanager.notifications.base import NotificationBackend, NotificationMessage

logger = structlog.get_logger()


class EmailBackend(NotificationBackend):
    """Sends notifications via SMTP email."""

    channel_type = "email"

    async def send(self, message: NotificationMessage, config: dict) -> bool:
        """Send a notification email.

        Config expects:
            to: list[str] — recipient email addresses
            smtp_host: str — SMTP server (default from global settings)
            smtp_port: int — SMTP port (default 587)
            smtp_user: str — SMTP username
            smtp_password: str — SMTP password
            from_address: str — sender address
        """
        try:
            from certmanager.core.config import get_settings

            settings = get_settings()

            to_addrs = config.get("to", [])
            if isinstance(to_addrs, str):
                to_addrs = [to_addrs]

            if not to_addrs:
                logger.warning("email_no_recipients", title=message.title)
                return False

            smtp_host = config.get("smtp_host", settings.smtp.host)
            smtp_port = config.get("smtp_port", settings.smtp.port)
            smtp_user = config.get("smtp_user", settings.smtp.user)
            smtp_password = config.get("smtp_password", settings.smtp.password)
            from_addr = config.get("from_address", settings.smtp.from_address)

            # Build email
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[CertManager - {message.severity.upper()}] {message.title}"
            msg["From"] = from_addr
            msg["To"] = ", ".join(to_addrs)

            # HTML body
            severity_color = {
                "critical": "#ff4d4f",
                "warning": "#faad14",
                "info": "#1677ff",
            }.get(message.severity, "#1677ff")

            html_body = f"""\
<html><body style="font-family: Arial, sans-serif; padding: 20px;">
  <div style="border-left: 4px solid {severity_color}; padding-left: 12px; margin-bottom: 16px;">
    <h2 style="color: {severity_color}; margin: 0;">{message.title}</h2>
    <p style="color: #666; font-size: 13px;">Severity: {message.severity.upper()}</p>
  </div>
  <p>{message.body}</p>
  {f'<p><strong>Certificate:</strong> {message.cert_common_name}</p>' if message.cert_common_name else ''}
  {f'<p><a href="{message.action_url}" style="color: #1677ff;">View in CertManager →</a></p>' if message.action_url else ''}
  <hr style="border: none; border-top: 1px solid #eee; margin-top: 24px;" />
  <p style="font-size: 11px; color: #999;">This is an automated notification from CertManager.</p>
</body></html>"""

            msg.attach(MIMEText(html_body, "html"))

            # Send via SMTP
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                server.sendmail(from_addr, to_addrs, msg.as_string())

            logger.info(
                "email_sent",
                to=to_addrs,
                title=message.title,
                severity=message.severity,
            )
            return True

        except Exception as e:
            logger.error("email_failed", error=str(e), title=message.title)
            return False

    async def test(self, config: dict) -> tuple[bool, str]:
        """Send a test email."""
        message = NotificationMessage(
            title="CertManager Test Notification",
            body="This is a test notification from CertManager. If you received this, your email channel is configured correctly.",
            severity="info",
        )
        success = await self.send(message, config)
        if success:
            return True, "Test email sent successfully"
        return False, "Failed to send test email — check SMTP configuration"
