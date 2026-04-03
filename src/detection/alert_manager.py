"""
Alert Manager - Handles email and WebSocket alert notifications.

Alert Levels:
- CRITICAL (ThreatLevel.ALERT): Confirmed brute-force attack
- WARNING (ThreatLevel.EARLY_WARNING): Early prediction, suspicious activity
- INFO: System status updates
"""

import json
import logging
import smtplib
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional, List, Dict, Set
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """Structured alert object."""
    id: str
    timestamp: str
    source_ip: str
    threat_level: str  # 'critical', 'warning', 'info'
    anomaly_score: float
    ewma_score: float
    message: str
    action_taken: str = ""
    acknowledged: bool = False

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict())


class AlertManager:
    """Manages alert creation, storage, and notification delivery."""

    def __init__(
        self,
        smtp_host: str = 'smtp.gmail.com',
        smtp_port: int = 587,
        smtp_user: str = '',
        smtp_password: str = '',
        alert_email_to: str = '',
        use_tls: bool = True,
        max_history: int = 1000,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.alert_email_to = alert_email_to
        self.use_tls = use_tls

        self._alert_history: List[Alert] = []
        self._max_history = max_history
        self._alert_counter = 0
        self._websocket_clients: Set = set()

    def create_alert(
        self,
        source_ip: str,
        threat_level: str,
        anomaly_score: float,
        ewma_score: float,
        action_taken: str = "",
    ) -> Alert:
        """Create a new alert."""
        self._alert_counter += 1

        if threat_level == 'critical':
            message = (
                f"CRITICAL: Brute-force attack detected from {source_ip}. "
                f"Anomaly score: {anomaly_score:.4f}, EWMA: {ewma_score:.4f}"
            )
        elif threat_level == 'warning':
            message = (
                f"WARNING: Suspicious SSH activity from {source_ip}. "
                f"Early prediction score: {anomaly_score:.4f}, EWMA: {ewma_score:.4f}"
            )
        else:
            message = f"INFO: Activity from {source_ip}, score: {anomaly_score:.4f}"

        alert = Alert(
            id=f"ALT-{self._alert_counter:06d}",
            timestamp=datetime.utcnow().isoformat(),
            source_ip=source_ip,
            threat_level=threat_level,
            anomaly_score=round(anomaly_score, 6),
            ewma_score=round(ewma_score, 6),
            message=message,
            action_taken=action_taken,
        )

        self._alert_history.append(alert)
        if len(self._alert_history) > self._max_history:
            self._alert_history = self._alert_history[-self._max_history:]

        return alert

    async def send_alert(self, alert: Alert):
        """Send alert via all configured channels."""
        tasks = []

        # Email notification for critical alerts
        if alert.threat_level == 'critical' and self.smtp_user:
            tasks.append(self._send_email(alert))

        # WebSocket push to all connected clients
        tasks.append(self._broadcast_websocket(alert))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Alert sent: {alert.id} [{alert.threat_level}] {alert.source_ip}")

    async def _send_email(self, alert: Alert):
        """Send email alert via SMTP."""
        if not self.smtp_user or not self.alert_email_to:
            logger.debug("Email not configured, skipping")
            return

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[SSH-AI] {alert.threat_level.upper()}: {alert.source_ip}"
            msg['From'] = self.smtp_user
            msg['To'] = self.alert_email_to

            # HTML email body
            html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <div style="background: {'#dc3545' if alert.threat_level == 'critical' else '#ffc107'};
                            color: {'white' if alert.threat_level == 'critical' else 'black'};
                            padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                    <h2 style="margin:0;">{alert.threat_level.upper()} Alert</h2>
                </div>
                <table style="border-collapse: collapse; width: 100%;">
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Alert ID</strong></td>
                        <td style="padding: 8px; border: 1px solid #ddd;">{alert.id}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Timestamp</strong></td>
                        <td style="padding: 8px; border: 1px solid #ddd;">{alert.timestamp}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Source IP</strong></td>
                        <td style="padding: 8px; border: 1px solid #ddd;">{alert.source_ip}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Anomaly Score</strong></td>
                        <td style="padding: 8px; border: 1px solid #ddd;">{alert.anomaly_score}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>EWMA Score</strong></td>
                        <td style="padding: 8px; border: 1px solid #ddd;">{alert.ewma_score}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Action</strong></td>
                        <td style="padding: 8px; border: 1px solid #ddd;">{alert.action_taken or 'None'}</td></tr>
                </table>
                <p style="margin-top: 20px; color: #666;">
                    SSH Brute-Force Detection System - AI-Powered Early Prediction
                </p>
            </body>
            </html>
            """

            msg.attach(MIMEText(html, 'html'))

            # Send via SMTP (blocking, run in executor)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._smtp_send, msg)

            logger.info(f"Email sent for alert {alert.id}")

        except Exception as e:
            logger.error(f"Failed to send email: {e}")

    def _smtp_send(self, msg):
        """Synchronous SMTP send."""
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            if self.use_tls:
                server.starttls()
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)

    async def _broadcast_websocket(self, alert: Alert):
        """Broadcast alert to all connected WebSocket clients."""
        if not self._websocket_clients:
            return

        message = alert.to_json()
        disconnected = set()

        for ws in self._websocket_clients:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.add(ws)

        self._websocket_clients -= disconnected

    def register_websocket(self, ws):
        """Register a WebSocket client for real-time alerts."""
        self._websocket_clients.add(ws)

    def unregister_websocket(self, ws):
        """Unregister a WebSocket client."""
        self._websocket_clients.discard(ws)

    def get_alerts(
        self,
        page: int = 1,
        page_size: int = 50,
        threat_level: Optional[str] = None,
    ) -> Dict:
        """Get paginated alert history."""
        alerts = self._alert_history

        if threat_level:
            alerts = [a for a in alerts if a.threat_level == threat_level]

        total = len(alerts)
        start = (page - 1) * page_size
        end = start + page_size

        return {
            'alerts': [a.to_dict() for a in reversed(alerts[start:end])],
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
        }

    def get_stats(self) -> dict:
        """Get alert statistics."""
        return {
            'total_alerts': len(self._alert_history),
            'critical': sum(1 for a in self._alert_history if a.threat_level == 'critical'),
            'warning': sum(1 for a in self._alert_history if a.threat_level == 'warning'),
            'info': sum(1 for a in self._alert_history if a.threat_level == 'info'),
            'connected_clients': len(self._websocket_clients),
        }
