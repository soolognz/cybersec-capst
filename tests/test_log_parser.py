"""Tests for SSH Log Parser."""

import pytest
from src.data_processing.log_parser import SSHLogParser, EventType


@pytest.fixture
def parser():
    return SSHLogParser()


class TestParseLogLine:
    def test_failed_password(self, parser):
        line = '2026-03-22T00:00:09.250246+00:00 mail sshd[2861212]: Failed password for invalid user ubuntu from 120.226.22.82 port 44188 ssh2'
        entry = parser.parse_line(line)
        assert entry is not None
        assert entry.event_type == EventType.FAILED_PASSWORD
        assert entry.username == 'ubuntu'
        assert entry.source_ip == '120.226.22.82'
        assert entry.source_port == 44188
        assert entry.is_invalid_user is True

    def test_failed_password_valid_user(self, parser):
        line = '2026-03-22T00:00:31.811086+00:00 mail sshd[2861226]: Failed password for root from 2.27.53.96 port 46996 ssh2'
        entry = parser.parse_line(line)
        assert entry.event_type == EventType.FAILED_PASSWORD
        assert entry.username == 'root'
        assert entry.is_invalid_user is False

    def test_accepted_password(self, parser):
        line = '2026-03-26T00:36:13.696996+00:00 if sshd[108034]: Accepted password for svc.monitor from 192.168.152.192 port 42595 ssh2'
        entry = parser.parse_line(line)
        assert entry.event_type == EventType.ACCEPTED_PASSWORD
        assert entry.username == 'svc.monitor'
        assert entry.source_ip == '192.168.152.192'

    def test_invalid_user(self, parser):
        line = '2026-03-22T00:00:06.847961+00:00 mail sshd[2861212]: Invalid user ubuntu from 120.226.22.82 port 44188'
        entry = parser.parse_line(line)
        assert entry.event_type == EventType.INVALID_USER
        assert entry.username == 'ubuntu'
        assert entry.is_invalid_user is True

    def test_connection_closed(self, parser):
        line = '2026-03-22T00:00:19.009855+00:00 mail sshd[2861223]: Connection closed by invalid user orangepi 165.154.227.162 port 57310 [preauth]'
        entry = parser.parse_line(line)
        assert entry.event_type == EventType.CONNECTION_CLOSED
        assert entry.source_ip == '165.154.227.162'

    def test_pam_auth_failure(self, parser):
        line = '2026-03-22T00:00:06.851722+00:00 mail sshd[2861212]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=120.226.22.82 '
        entry = parser.parse_line(line)
        assert entry.event_type == EventType.PAM_AUTH_FAILURE
        assert entry.source_ip == '120.226.22.82'

    def test_message_repeated(self, parser):
        line = '2026-03-22T00:01:52.694118+00:00 mail sshd[2861236]: message repeated 4 times: [ Failed password for root from 2.57.121.17 port 60500 ssh2]'
        entry = parser.parse_line(line)
        assert entry.event_type == EventType.MESSAGE_REPEATED
        assert entry.repeat_count == 4

    def test_pam_max_retries(self, parser):
        line = '2026-03-22T00:01:53.356871+00:00 mail sshd[2861236]: PAM service(sshd) ignoring max retries; 5 > 3'
        entry = parser.parse_line(line)
        assert entry.event_type == EventType.PAM_MAX_RETRIES

    def test_empty_line(self, parser):
        assert parser.parse_line('') is None
        assert parser.parse_line('   ') is None

    def test_non_sshd_line(self, parser):
        line = '2026-03-22T00:05:01.887340+00:00 mail CRON[2861265]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)'
        entry = parser.parse_line(line)
        assert entry is not None
        assert entry.event_type == EventType.CRON_SESSION


class TestParseFile:
    def test_parse_honeypot_sample(self, parser):
        entries = list(parser.parse_file('Dataset/honeypot_auth.log.log', expand_repeats=True))
        assert len(entries) > 100
        event_types = set(e.event_type for e in entries)
        assert EventType.FAILED_PASSWORD in event_types

    def test_parse_simulation_sample(self, parser):
        entries = list(parser.parse_file('Dataset/simulation_auth.log.log', expand_repeats=True))
        assert len(entries) > 100
        event_types = set(e.event_type for e in entries)
        assert EventType.ACCEPTED_PASSWORD in event_types
