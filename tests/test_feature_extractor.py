"""Tests for Feature Extractor."""

import pytest
import numpy as np
from datetime import datetime, timedelta, timezone
from src.data_processing.log_parser import ParsedLogEntry, EventType
from src.data_processing.labeler import LabeledEntry
from src.data_processing.feature_extractor import FeatureExtractor, FEATURE_NAMES


def make_entry(event_type, timestamp, ip='1.2.3.4', username='root', port=22, is_invalid=False):
    """Helper to create a labeled entry."""
    entry = ParsedLogEntry(
        timestamp=timestamp,
        hostname='test',
        service='sshd',
        pid=1000,
        event_type=event_type,
        username=username,
        source_ip=ip,
        source_port=port,
        is_invalid_user=is_invalid,
    )
    return LabeledEntry(entry=entry, label='normal', source_file='test')


class TestFeatureExtractor:
    @pytest.fixture
    def extractor(self):
        return FeatureExtractor(window_minutes=5, stride_minutes=5)

    def test_feature_count(self, extractor):
        """Should extract exactly 14 features."""
        assert len(FEATURE_NAMES) == 14

    def test_single_failed_attempt(self, extractor):
        """Single failed attempt should produce correct features."""
        t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        entries = [
            make_entry(EventType.FAILED_PASSWORD, t, port=10000),
        ]
        features, labels = extractor.extract_from_entries(entries)
        assert len(features) >= 1
        row = features[FEATURE_NAMES].iloc[0]
        assert row['fail_count'] == 1.0
        assert row['success_count'] == 0.0

    def test_multiple_failures_high_fail_rate(self, extractor):
        """Multiple failures should produce high fail_rate."""
        t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        entries = []
        for i in range(10):
            entries.append(make_entry(
                EventType.FAILED_PASSWORD,
                t + timedelta(seconds=i * 5),
                port=10000 + i
            ))
        features, labels = extractor.extract_from_entries(entries)
        row = features[FEATURE_NAMES].iloc[0]
        assert row['fail_count'] == 10.0
        assert row['fail_rate'] > 0.9
        assert row['unique_ports'] == 10.0

    def test_normal_session(self, extractor):
        """Normal session should have success_count > 0."""
        t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        entries = [
            make_entry(EventType.ACCEPTED_PASSWORD, t, username='admin', port=50000),
        ]
        features, labels = extractor.extract_from_entries(entries)
        row = features[FEATURE_NAMES].iloc[0]
        assert row['success_count'] == 1.0
        assert row['fail_count'] == 0.0

    def test_multiple_usernames(self, extractor):
        """Multiple usernames should be counted."""
        t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        entries = []
        users = ['root', 'admin', 'test', 'user', 'ubuntu']
        for i, user in enumerate(users):
            entries.append(make_entry(
                EventType.FAILED_PASSWORD,
                t + timedelta(seconds=i * 10),
                username=user, port=20000 + i
            ))
        features, labels = extractor.extract_from_entries(entries)
        row = features[FEATURE_NAMES].iloc[0]
        assert row['unique_usernames'] == 5.0

    def test_inter_attempt_timing(self, extractor):
        """Timing features should reflect intervals."""
        t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        entries = []
        # 5 attempts, 10 seconds apart
        for i in range(5):
            entries.append(make_entry(
                EventType.FAILED_PASSWORD,
                t + timedelta(seconds=i * 10),
                port=30000 + i
            ))
        features, labels = extractor.extract_from_entries(entries)
        row = features[FEATURE_NAMES].iloc[0]
        assert abs(row['mean_inter_attempt_time'] - 10.0) < 1.0
        assert row['min_inter_attempt_time'] < 11.0

    def test_different_ips_separate_windows(self, extractor):
        """Different IPs should produce separate feature vectors."""
        t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        entries = [
            make_entry(EventType.FAILED_PASSWORD, t, ip='10.0.0.1', port=40000),
            make_entry(EventType.FAILED_PASSWORD, t + timedelta(seconds=1), ip='10.0.0.2', port=40001),
        ]
        features, labels = extractor.extract_from_entries(entries)
        unique_ips = features['source_ip'].unique() if 'source_ip' in features.columns else []
        # Should have features for 2 different IPs
        assert len(features) >= 2

    def test_empty_entries(self, extractor):
        """Empty entries should produce empty features."""
        features, labels = extractor.extract_from_entries([])
        assert len(features) == 0

    def test_label_majority_vote(self, extractor):
        """Window label should be majority vote of entry labels."""
        t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        entries = []
        # 3 attack + 1 normal = attack majority
        for i in range(3):
            le = make_entry(EventType.FAILED_PASSWORD, t + timedelta(seconds=i), port=50000+i)
            le.label = 'attack'
            entries.append(le)
        le = make_entry(EventType.ACCEPTED_PASSWORD, t + timedelta(seconds=5), port=50010)
        le.label = 'normal'
        entries.append(le)

        features, labels = extractor.extract_from_entries(entries)
        assert labels.iloc[0] == 'attack'


class TestFeatureNames:
    def test_all_names_unique(self):
        assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))

    def test_names_are_strings(self):
        for name in FEATURE_NAMES:
            assert isinstance(name, str)
