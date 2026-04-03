"""
Data Labeler - Labels SSH log entries as 'normal' or 'attack'.

Rules:
- simulation_auth.log: ALL entries = 'normal' (including minor failed logins = human typos)
- honeypot_auth.log:
    - Accepted password for root from known admin IPs = 'normal'
    - Everything else = 'attack'
"""

from dataclasses import dataclass
from typing import List, Set
from .log_parser import SSHLogParser, ParsedLogEntry, EventType


# Known legitimate admin IPs (from honeypot analysis)
ADMIN_IPS: Set[str] = {
    '27.64.18.8',
    '104.28.156.151',
    '104.28.159.126',
    '116.110.42.131',
    '118.69.182.144',
    '14.169.70.183',
}


@dataclass
class LabeledEntry:
    entry: ParsedLogEntry
    label: str  # 'normal' or 'attack'
    source_file: str  # 'honeypot' or 'simulation'


class DataLabeler:
    """Labels parsed SSH log entries based on source file and rules."""

    def __init__(self, admin_ips: Set[str] = None):
        self.admin_ips = admin_ips or ADMIN_IPS
        self.parser = SSHLogParser()

    def label_simulation(self, filepath: str) -> List[LabeledEntry]:
        """Label all simulation log entries as 'normal'."""
        entries = []
        for entry in self.parser.parse_file(filepath, expand_repeats=True):
            entries.append(LabeledEntry(
                entry=entry,
                label='normal',
                source_file='simulation'
            ))
        return entries

    def label_honeypot(self, filepath: str) -> List[LabeledEntry]:
        """Label honeypot entries: admin root logins = normal, rest = attack."""
        entries = []
        # Track which PIDs belong to accepted admin sessions
        admin_pids: set = set()

        # First pass: identify admin session PIDs
        for entry in self.parser.parse_file(filepath, expand_repeats=True):
            if (entry.event_type == EventType.ACCEPTED_PASSWORD
                    and entry.username == 'root'
                    and entry.source_ip in self.admin_ips):
                admin_pids.add(entry.pid)

        # Second pass: label all entries
        for entry in self.parser.parse_file(filepath, expand_repeats=True):
            if entry.event_type == EventType.CRON_SESSION:
                # CRON jobs are system events, label as normal
                label = 'normal'
            elif entry.pid in admin_pids:
                # All log lines belonging to an admin session
                label = 'normal'
            elif (entry.event_type == EventType.ACCEPTED_PASSWORD
                  and entry.username == 'root'
                  and entry.source_ip in self.admin_ips):
                label = 'normal'
            else:
                label = 'attack'

            entries.append(LabeledEntry(
                entry=entry,
                label=label,
                source_file='honeypot'
            ))

        return entries

    def get_label_stats(self, entries: List[LabeledEntry]) -> dict:
        """Get statistics about labeled data."""
        stats = {
            'total': len(entries),
            'normal': sum(1 for e in entries if e.label == 'normal'),
            'attack': sum(1 for e in entries if e.label == 'attack'),
        }
        stats['normal_pct'] = round(stats['normal'] / max(stats['total'], 1) * 100, 2)
        stats['attack_pct'] = round(stats['attack'] / max(stats['total'], 1) * 100, 2)
        return stats
