"""
Fail2Ban Integration - Automatically blocks malicious IPs.

Integrates with Fail2Ban via CLI commands:
- CRITICAL alerts: auto-ban IP
- EARLY_WARNING alerts: add to watchlist, manual confirmation option

Custom jail 'sshd-ai' is configured in fail2ban/jail.local
"""

import logging
import subprocess
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Set, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BanRecord:
    """Record of an IP ban action."""
    ip: str
    timestamp: str
    reason: str
    threat_level: str
    anomaly_score: float
    ban_duration: int  # seconds
    is_active: bool = True


class Fail2BanIntegration:
    """Manages IP banning through Fail2Ban."""

    def __init__(
        self,
        jail_name: str = 'sshd-ai',
        ban_time: int = 3600,
        auto_ban_on_critical: bool = True,
        manual_confirm_on_warning: bool = True,
        enabled: bool = True,
    ):
        """
        Args:
            jail_name: Fail2Ban jail name for this system
            ban_time: Default ban duration in seconds
            auto_ban_on_critical: Auto-ban on CRITICAL alerts
            manual_confirm_on_warning: Require confirmation for WARNING bans
            enabled: Enable/disable Fail2Ban integration
        """
        self.jail_name = jail_name
        self.ban_time = ban_time
        self.auto_ban_on_critical = auto_ban_on_critical
        self.manual_confirm_on_warning = manual_confirm_on_warning
        self.enabled = enabled

        self._banned_ips: Dict[str, BanRecord] = {}
        self._watchlist: Dict[str, dict] = {}
        self._ban_history: list = []

    async def handle_alert(self, ip: str, threat_level: str, anomaly_score: float) -> str:
        """Handle an alert by taking appropriate action.

        Args:
            ip: Source IP address
            threat_level: 'critical' or 'warning'
            anomaly_score: Anomaly score from the model

        Returns:
            Action taken as string
        """
        if not self.enabled:
            return "Fail2Ban disabled"

        if ip in self._banned_ips and self._banned_ips[ip].is_active:
            return f"IP {ip} already banned"

        if threat_level == 'critical' and self.auto_ban_on_critical:
            return await self.ban_ip(ip, anomaly_score, "Auto-ban: CRITICAL alert")

        elif threat_level == 'warning':
            self._watchlist[ip] = {
                'timestamp': datetime.utcnow().isoformat(),
                'anomaly_score': anomaly_score,
                'threat_level': threat_level,
            }
            return f"IP {ip} added to watchlist"

        return "No action taken"

    async def ban_ip(self, ip: str, anomaly_score: float = 0.0, reason: str = "") -> str:
        """Ban an IP using Fail2Ban CLI.

        Executes: fail2ban-client set <jail> banip <ip>
        """
        record = BanRecord(
            ip=ip,
            timestamp=datetime.utcnow().isoformat(),
            reason=reason,
            threat_level='critical',
            anomaly_score=anomaly_score,
            ban_duration=self.ban_time,
        )

        try:
            cmd = ['fail2ban-client', 'set', self.jail_name, 'banip', ip]
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
            )

            if result.returncode == 0:
                record.is_active = True
                action = f"IP {ip} banned via Fail2Ban ({self.jail_name})"
                logger.warning(action)
            else:
                record.is_active = False
                action = f"Fail2Ban ban failed for {ip}: {result.stderr}"
                logger.error(action)

        except FileNotFoundError:
            record.is_active = False
            action = f"Fail2Ban not installed. Would ban IP {ip}"
            logger.warning(action)
        except subprocess.TimeoutExpired:
            record.is_active = False
            action = f"Fail2Ban timeout for IP {ip}"
            logger.error(action)
        except Exception as e:
            record.is_active = False
            action = f"Fail2Ban error for {ip}: {e}"
            logger.error(action)

        self._banned_ips[ip] = record
        self._ban_history.append(record)

        # Remove from watchlist if present
        self._watchlist.pop(ip, None)

        return action

    async def unban_ip(self, ip: str) -> str:
        """Unban an IP."""
        try:
            cmd = ['fail2ban-client', 'set', self.jail_name, 'unbanip', ip]
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: subprocess.run(cmd, capture_output=True, timeout=10)
            )
            if ip in self._banned_ips:
                self._banned_ips[ip].is_active = False
            return f"IP {ip} unbanned"
        except Exception as e:
            return f"Unban failed: {e}"

    def get_banned_ips(self) -> list:
        """Get list of currently banned IPs."""
        return [
            {'ip': ip, **vars(record)}
            for ip, record in self._banned_ips.items()
            if record.is_active
        ]

    def get_watchlist(self) -> list:
        """Get current watchlist."""
        return [
            {'ip': ip, **data}
            for ip, data in self._watchlist.items()
        ]

    def get_ban_history(self) -> list:
        """Get complete ban history."""
        return [vars(r) for r in self._ban_history]

    def get_stats(self) -> dict:
        """Get prevention statistics."""
        return {
            'active_bans': sum(1 for r in self._banned_ips.values() if r.is_active),
            'total_bans': len(self._ban_history),
            'watchlist_size': len(self._watchlist),
            'enabled': self.enabled,
        }
