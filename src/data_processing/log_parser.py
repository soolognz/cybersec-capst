"""
SSH Log Parser - Parses syslog-format SSH authentication logs.
Handles both honeypot (hostname='mail') and simulation (hostname='if') formats.
Supports ISO8601 timestamps and 'message repeated N times' expansion.
"""

import re
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EventType(str, Enum):
    FAILED_PASSWORD = "failed_password"
    ACCEPTED_PASSWORD = "accepted_password"
    INVALID_USER = "invalid_user"
    CONNECTION_FROM = "connection_from"
    CONNECTION_CLOSED = "connection_closed"
    CONNECTION_RESET = "connection_reset"
    DISCONNECTED = "disconnected"
    RECEIVED_DISCONNECT = "received_disconnect"
    PAM_AUTH_FAILURE = "pam_auth_failure"
    PAM_CHECK_PASS = "pam_check_pass"
    PAM_MORE_FAILURES = "pam_more_failures"
    PAM_MAX_RETRIES = "pam_max_retries"
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    MESSAGE_REPEATED = "message_repeated"
    TRANSFERRED = "transferred"
    CRON_SESSION = "cron_session"
    USER_CHILD = "user_child"
    OTHER = "other"


@dataclass
class ParsedLogEntry:
    timestamp: datetime
    hostname: str
    service: str
    pid: int
    event_type: EventType
    username: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    is_invalid_user: bool = False
    raw_message: str = ""
    repeat_count: int = 1
    extra: dict = field(default_factory=dict)


class SSHLogParser:
    """Regex-based parser for syslog SSH authentication logs."""

    # Main log line pattern: ISO8601 timestamp + hostname + service[pid]: message
    RE_MAIN = re.compile(
        r'^(\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:\d{2})\s+'
        r'(\S+)\s+'
        r'(\w+)\[(\d+)\]:\s+'
        r'(.+)$'
    )

    # Event patterns (order matters - more specific first)
    PATTERNS = [
        (EventType.MESSAGE_REPEATED, re.compile(
            r'message repeated (\d+) times?: \[\s*(.+?)\s*\]'
        )),
        (EventType.FAILED_PASSWORD, re.compile(
            r'Failed password for (?:(invalid user) )?(\S+) from ([\d.]+) port (\d+)'
        )),
        (EventType.ACCEPTED_PASSWORD, re.compile(
            r'Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)'
        )),
        (EventType.INVALID_USER, re.compile(
            r'Invalid user (\S+) from ([\d.]+) port (\d+)'
        )),
        (EventType.CONNECTION_FROM, re.compile(
            r'Connection from ([\d.]+) port (\d+)'
        )),
        (EventType.CONNECTION_CLOSED, re.compile(
            r'Connection closed by (?:(?:invalid user|authenticating user) (\S+) )?([\d.]+) port (\d+)'
        )),
        (EventType.CONNECTION_RESET, re.compile(
            r'Connection reset by (?:(?:invalid user|authenticating user) (\S+) )?([\d.]+) port (\d+)'
        )),
        (EventType.RECEIVED_DISCONNECT, re.compile(
            r'Received disconnect from ([\d.]+) port (\d+)'
        )),
        (EventType.DISCONNECTED, re.compile(
            r'Disconnected from (?:(?:invalid user|authenticating user) (\S+) )?([\d.]+) port (\d+)'
        )),
        (EventType.PAM_MAX_RETRIES, re.compile(
            r'PAM service\(sshd\) ignoring max retries; (\d+) > (\d+)'
        )),
        (EventType.PAM_MORE_FAILURES, re.compile(
            r'PAM (\d+) more authentication failures;.*rhost=([\d.]+)(?:\s+user=(\S+))?'
        )),
        (EventType.PAM_AUTH_FAILURE, re.compile(
            r'pam_unix\(sshd:auth\): authentication failure;.*rhost=([\d.]+)(?:\s+user=(\S+))?'
        )),
        (EventType.PAM_CHECK_PASS, re.compile(
            r'pam_unix\(sshd:auth\): check pass; user unknown'
        )),
        (EventType.SESSION_OPENED, re.compile(
            r'pam_unix\(sshd:session\): session opened for user (\S+?)(?:\(uid=\d+\))? by'
        )),
        (EventType.SESSION_CLOSED, re.compile(
            r'pam_unix\(sshd:session\): session closed for user (\S+)'
        )),
        (EventType.CRON_SESSION, re.compile(
            r'pam_unix\(cron:session\): session (?:opened|closed) for user (\S+)'
        )),
        (EventType.TRANSFERRED, re.compile(
            r'Transferred: sent (\d+), received (\d+) bytes'
        )),
        (EventType.USER_CHILD, re.compile(
            r'User child is on pid (\d+)'
        )),
    ]

    def parse_line(self, line: str) -> Optional[ParsedLogEntry]:
        """Parse a single log line into a ParsedLogEntry."""
        line = line.strip()
        if not line:
            return None

        main_match = self.RE_MAIN.match(line)
        if not main_match:
            return None

        timestamp_str, hostname, service, pid_str, message = main_match.groups()

        try:
            timestamp = datetime.fromisoformat(timestamp_str)
        except ValueError:
            return None

        pid = int(pid_str)

        # Skip non-sshd entries (CRON, systemd-logind, etc.) unless they're PAM sshd
        if service not in ('sshd',) and 'sshd' not in message:
            # Still parse CRON for completeness
            if service == 'CRON':
                return ParsedLogEntry(
                    timestamp=timestamp, hostname=hostname,
                    service=service, pid=pid,
                    event_type=EventType.CRON_SESSION,
                    raw_message=message
                )
            return None

        entry = ParsedLogEntry(
            timestamp=timestamp, hostname=hostname,
            service=service, pid=pid,
            event_type=EventType.OTHER,
            raw_message=message
        )

        for event_type, pattern in self.PATTERNS:
            m = pattern.search(message)
            if m:
                entry.event_type = event_type
                self._extract_fields(entry, event_type, m)
                break

        return entry

    def _extract_fields(self, entry: ParsedLogEntry, event_type: EventType, match):
        """Extract structured fields from regex match groups."""
        groups = match.groups()

        if event_type == EventType.FAILED_PASSWORD:
            invalid_marker, username, ip, port = groups
            entry.username = username
            entry.source_ip = ip
            entry.source_port = int(port)
            entry.is_invalid_user = invalid_marker is not None

        elif event_type == EventType.ACCEPTED_PASSWORD:
            entry.username = groups[0]
            entry.source_ip = groups[1]
            entry.source_port = int(groups[2])

        elif event_type == EventType.INVALID_USER:
            entry.username = groups[0]
            entry.source_ip = groups[1]
            entry.source_port = int(groups[2])
            entry.is_invalid_user = True

        elif event_type == EventType.CONNECTION_FROM:
            entry.source_ip = groups[0]
            entry.source_port = int(groups[1])

        elif event_type in (EventType.CONNECTION_CLOSED, EventType.CONNECTION_RESET,
                            EventType.DISCONNECTED):
            entry.username = groups[0]  # may be None
            entry.source_ip = groups[1]
            entry.source_port = int(groups[2])

        elif event_type == EventType.RECEIVED_DISCONNECT:
            entry.source_ip = groups[0]
            entry.source_port = int(groups[1])

        elif event_type == EventType.PAM_AUTH_FAILURE:
            entry.source_ip = groups[0]
            entry.username = groups[1]  # may be None

        elif event_type == EventType.PAM_MORE_FAILURES:
            entry.extra['failure_count'] = int(groups[0])
            entry.source_ip = groups[1]
            entry.username = groups[2]

        elif event_type == EventType.PAM_MAX_RETRIES:
            entry.extra['retries'] = int(groups[0])
            entry.extra['max_allowed'] = int(groups[1])

        elif event_type == EventType.SESSION_OPENED:
            entry.username = groups[0]

        elif event_type == EventType.SESSION_CLOSED:
            entry.username = groups[0]

        elif event_type == EventType.MESSAGE_REPEATED:
            entry.repeat_count = int(groups[0])
            entry.extra['repeated_message'] = groups[1]

        elif event_type == EventType.TRANSFERRED:
            entry.extra['bytes_sent'] = int(groups[0])
            entry.extra['bytes_received'] = int(groups[1])

    def parse_file(self, filepath: str, expand_repeats: bool = True):
        """Parse an entire log file, yielding ParsedLogEntry objects.

        Args:
            filepath: Path to log file
            expand_repeats: If True, expand 'message repeated N times' into N entries
        """
        prev_entry = None

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                entry = self.parse_line(line)
                if entry is None:
                    continue

                if entry.event_type == EventType.MESSAGE_REPEATED and expand_repeats:
                    # Expand repeated messages by re-parsing the repeated content
                    repeated_msg = entry.extra.get('repeated_message', '')
                    if repeated_msg and prev_entry:
                        expanded = self._expand_repeated(entry, repeated_msg, prev_entry)
                        for exp_entry in expanded:
                            yield exp_entry
                    else:
                        yield entry
                else:
                    yield entry

                prev_entry = entry

    def _expand_repeated(self, repeat_entry, repeated_msg, prev_entry):
        """Expand a 'message repeated N times' entry into N synthetic entries."""
        # Try to parse the repeated message content
        synthetic_line = (
            f"{repeat_entry.timestamp.isoformat()} "
            f"{repeat_entry.hostname} "
            f"{repeat_entry.service}[{repeat_entry.pid}]: "
            f"{repeated_msg}"
        )
        parsed = self.parse_line(synthetic_line)

        if parsed is None:
            # Fallback: create copies of the previous entry
            parsed = ParsedLogEntry(
                timestamp=repeat_entry.timestamp,
                hostname=repeat_entry.hostname,
                service=repeat_entry.service,
                pid=repeat_entry.pid,
                event_type=prev_entry.event_type,
                username=prev_entry.username,
                source_ip=prev_entry.source_ip,
                source_port=prev_entry.source_port,
                is_invalid_user=prev_entry.is_invalid_user,
                raw_message=repeated_msg,
            )

        entries = []
        for i in range(repeat_entry.repeat_count):
            import copy
            entry_copy = copy.deepcopy(parsed)
            entry_copy.extra['expanded_from_repeat'] = True
            entry_copy.extra['repeat_index'] = i
            entries.append(entry_copy)

        return entries
