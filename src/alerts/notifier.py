"""
Email Notification Module
Sends email alerts for Critical and High severity events.
Rate-limited to avoid flooding the recipient.
"""

import logging
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


class EmailNotifier:
    """Sends email notifications for high-severity alerts"""

    def __init__(self, config):
        """
        Initialize email notifier from config.

        Expected config keys under 'notifications.email':
            enabled: bool
            smtp_server: str
            smtp_port: int (default 587)
            use_tls: bool (default True)
            username: str
            password: str
            from_addr: str
            recipients: list[str]
            min_severity: str (default 'high')
            cooldown_seconds: int (default 300)
        """
        email_cfg = config.get('notifications', {}).get('email', {})
        self.enabled = email_cfg.get('enabled', False)
        self.smtp_server = email_cfg.get('smtp_server', '')
        self.smtp_port = email_cfg.get('smtp_port', 587)
        self.use_tls = email_cfg.get('use_tls', True)
        self.username = email_cfg.get('username', '')
        self.password = email_cfg.get('password', '')
        self.from_addr = email_cfg.get('from_addr', '')
        self.recipients = email_cfg.get('recipients', [])
        self.min_severity = email_cfg.get('min_severity', 'high')
        self.cooldown_seconds = email_cfg.get('cooldown_seconds', 300)

        self._severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        self._last_sent = {}  # (type, src_ip) -> datetime
        self._lock = threading.Lock()

    def should_notify(self, alert_data):
        """Check if this alert warrants an email"""
        if not self.enabled:
            return False

        severity = alert_data.get('severity', 'medium')
        min_rank = self._severity_rank.get(self.min_severity, 1)
        alert_rank = self._severity_rank.get(severity, 2)

        if alert_rank > min_rank:
            return False

        # Rate limit per (type, src_ip)
        key = (alert_data.get('type'), alert_data.get('src_ip'))
        now = datetime.now()
        with self._lock:
            last = self._last_sent.get(key)
            if last and (now - last).total_seconds() < self.cooldown_seconds:
                return False
            self._last_sent[key] = now

        return True

    def notify(self, alert_data):
        """Send email notification for an alert (runs in background thread)"""
        if not self.should_notify(alert_data):
            return

        thread = threading.Thread(target=self._send_email, args=(alert_data,),
                                  daemon=True)
        thread.start()

    def _send_email(self, alert_data):
        """Actually send the email"""
        subject = f"[NIDS {alert_data.get('severity', '').upper()}] {alert_data.get('type', 'alert')}"
        body = self._format_body(alert_data)

        msg = MIMEText(body, 'plain')
        msg['Subject'] = subject
        msg['From'] = self.from_addr
        msg['To'] = ', '.join(self.recipients)

        try:
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)

            if self.username and self.password:
                server.login(self.username, self.password)

            server.sendmail(self.from_addr, self.recipients, msg.as_string())
            server.quit()
            logger.info("Email notification sent for %s alert", alert_data.get('type'))
        except Exception as e:
            logger.error("Failed to send email notification: %s", e)

    def _format_body(self, alert_data):
        """Format the alert into an email body"""
        ts = alert_data.get('timestamp', '')
        if hasattr(ts, 'strftime'):
            ts = ts.strftime('%Y-%m-%d %H:%M:%S')

        lines = [
            "NIDS Security Alert",
            "=" * 40,
            f"Severity:    {alert_data.get('severity', 'unknown').upper()}",
            f"Type:        {alert_data.get('type', 'unknown')}",
            f"Time:        {ts}",
            f"Source IP:   {alert_data.get('src_ip', 'N/A')}",
            f"Dest IP:     {alert_data.get('dst_ip', 'N/A')}",
            f"Description: {alert_data.get('description', 'N/A')}",
        ]

        details = alert_data.get('details', {})
        if details:
            lines.append("\nDetails:")
            for k, v in details.items():
                lines.append(f"  {k}: {v}")

        return "\n".join(lines)
