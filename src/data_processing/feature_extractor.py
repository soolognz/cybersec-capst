"""
Feature Extractor - Extracts 14 features per source IP per time window.

Uses a sliding time-window approach (default 5 minutes) to capture
brute-force behavioral patterns across multiple SSH sessions.

All 14 features are numeric and compatible with IF, LOF, and OCSVM.
"""

import numpy as np
import pandas as pd
from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Tuple
from .log_parser import ParsedLogEntry, EventType
from .labeler import LabeledEntry


# Feature names in order
FEATURE_NAMES = [
    'fail_count',               # 1. Number of failed password attempts
    'success_count',            # 2. Number of successful logins
    'fail_rate',                # 3. Failure ratio: fail/(fail+success+eps)
    'unique_usernames',         # 4. Distinct usernames attempted
    'invalid_user_count',       # 5. Count of "Invalid user" events
    'invalid_user_ratio',       # 6. invalid_user_count / (total_attempts+eps)
    'connection_count',         # 7. Total SSH connections initiated
    'mean_inter_attempt_time',  # 8. Avg seconds between consecutive attempts
    'std_inter_attempt_time',   # 9. Std deviation of inter-attempt intervals
    'min_inter_attempt_time',   # 10. Minimum gap between attempts
    'unique_ports',             # 11. Distinct source ports used
    'pam_failure_escalation',   # 12. PAM "N more auth failures" events
    'max_retries_exceeded',     # 13. PAM "ignoring max retries" events
    'session_duration_mean',    # 14. Average session duration (seconds)
]

EPS = 1e-6  # Small constant to avoid division by zero


class FeatureExtractor:
    """Extract behavioral features from SSH log entries per IP per time window."""

    def __init__(self, window_minutes: int = 5, stride_minutes: int = 1):
        """
        Args:
            window_minutes: Size of sliding window in minutes
            stride_minutes: Step size for sliding window
        """
        self.window_size = timedelta(minutes=window_minutes)
        self.stride = timedelta(minutes=stride_minutes)

    def extract_from_entries(
        self,
        entries: List[LabeledEntry],
        return_labels: bool = True
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """Extract features from labeled entries.

        Groups entries by source IP + time window, extracts 14 features per group.

        Returns:
            features_df: DataFrame with 14 feature columns
            labels: Series with 'normal'/'attack' label per window (majority vote)
        """
        # Group entries by source IP
        ip_entries: Dict[str, List[LabeledEntry]] = defaultdict(list)
        for le in entries:
            ip = le.entry.source_ip
            if ip is not None:
                ip_entries[ip].append(le)

        all_features = []
        all_labels = []
        all_metadata = []  # For traceability

        for ip, ip_data in ip_entries.items():
            # Sort by timestamp
            ip_data.sort(key=lambda x: x.entry.timestamp)

            if not ip_data:
                continue

            start_time = ip_data[0].entry.timestamp
            end_time = ip_data[-1].entry.timestamp

            # Slide window across the time range
            window_start = start_time
            while window_start <= end_time:
                window_end = window_start + self.window_size

                # Get entries in this window
                window_entries = [
                    le for le in ip_data
                    if window_start <= le.entry.timestamp < window_end
                ]

                if window_entries:
                    features = self._extract_window_features(window_entries)
                    all_features.append(features)

                    if return_labels:
                        # Majority vote for window label
                        labels_in_window = [le.label for le in window_entries]
                        attack_count = labels_in_window.count('attack')
                        label = 'attack' if attack_count > len(labels_in_window) / 2 else 'normal'
                        all_labels.append(label)

                    all_metadata.append({
                        'source_ip': ip,
                        'window_start': window_start,
                        'window_end': window_end,
                        'entry_count': len(window_entries),
                    })

                window_start += self.stride

        features_df = pd.DataFrame(all_features, columns=FEATURE_NAMES)

        # Add metadata columns (not used as features)
        meta_df = pd.DataFrame(all_metadata)
        features_df = pd.concat([features_df, meta_df], axis=1)

        labels = pd.Series(all_labels, name='label') if return_labels else None

        return features_df, labels

    def _extract_window_features(self, window_entries: List[LabeledEntry]) -> List[float]:
        """Extract 14 features from entries within a single IP-window."""
        entries = [le.entry for le in window_entries]

        # Separate by event type
        failed = [e for e in entries if e.event_type == EventType.FAILED_PASSWORD]
        accepted = [e for e in entries if e.event_type == EventType.ACCEPTED_PASSWORD]
        invalid = [e for e in entries if e.event_type == EventType.INVALID_USER]
        connections = [e for e in entries if e.event_type in (
            EventType.CONNECTION_FROM, EventType.ACCEPTED_PASSWORD,
            EventType.FAILED_PASSWORD
        )]
        pam_more = [e for e in entries if e.event_type == EventType.PAM_MORE_FAILURES]
        pam_max = [e for e in entries if e.event_type == EventType.PAM_MAX_RETRIES]

        # 1. fail_count
        fail_count = len(failed)

        # 2. success_count
        success_count = len(accepted)

        # 3. fail_rate
        total_auth = fail_count + success_count
        fail_rate = fail_count / (total_auth + EPS)

        # 4. unique_usernames
        usernames = set()
        for e in entries:
            if e.username:
                usernames.add(e.username)
        unique_usernames = len(usernames)

        # 5. invalid_user_count
        invalid_user_count = len(invalid)

        # 6. invalid_user_ratio
        total_attempts = fail_count + success_count + invalid_user_count
        invalid_user_ratio = invalid_user_count / (total_attempts + EPS)

        # 7. connection_count
        connection_count = len(connections)

        # 8-10. Inter-attempt timing features
        auth_events = [e for e in entries if e.event_type in (
            EventType.FAILED_PASSWORD, EventType.ACCEPTED_PASSWORD,
            EventType.INVALID_USER
        )]
        auth_events.sort(key=lambda e: e.timestamp)

        if len(auth_events) >= 2:
            intervals = []
            for i in range(1, len(auth_events)):
                delta = (auth_events[i].timestamp - auth_events[i-1].timestamp).total_seconds()
                intervals.append(delta)

            mean_inter = np.mean(intervals)
            std_inter = np.std(intervals) if len(intervals) > 1 else 0.0
            min_inter = np.min(intervals)
        else:
            default_interval = self.window_size.total_seconds()
            mean_inter = default_interval
            std_inter = 0.0
            min_inter = default_interval

        # 11. unique_ports
        ports = set()
        for e in entries:
            if e.source_port is not None:
                ports.add(e.source_port)
        unique_ports = len(ports)

        # 12. pam_failure_escalation
        pam_failure_escalation = len(pam_more)

        # 13. max_retries_exceeded
        max_retries_exceeded = len(pam_max)

        # 14. session_duration_mean
        session_durations = self._compute_session_durations(entries)
        session_duration_mean = np.mean(session_durations) if session_durations else 0.0

        return [
            float(fail_count),
            float(success_count),
            float(fail_rate),
            float(unique_usernames),
            float(invalid_user_count),
            float(invalid_user_ratio),
            float(connection_count),
            float(mean_inter),
            float(std_inter),
            float(min_inter),
            float(unique_ports),
            float(pam_failure_escalation),
            float(max_retries_exceeded),
            float(session_duration_mean),
        ]

    def _compute_session_durations(self, entries: List[ParsedLogEntry]) -> List[float]:
        """Compute session durations by grouping entries by PID."""
        pid_times: Dict[int, List[float]] = defaultdict(list)
        for e in entries:
            pid_times[e.pid].append(e.timestamp.timestamp())

        durations = []
        for pid, timestamps in pid_times.items():
            if len(timestamps) >= 2:
                duration = max(timestamps) - min(timestamps)
                durations.append(duration)

        return durations
