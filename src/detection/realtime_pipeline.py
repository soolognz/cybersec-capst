"""
Real-Time Detection Pipeline - Monitors SSH auth logs and detects brute-force attacks.

Architecture:
    [auth.log] --> [LogTailer] --> [LogParser] --> [WindowManager]
                                                       |
    [IF Model] <-- [Preprocessor] <-- [FeatureExtractor] <--+
        |
    [DynamicThreshold] --> [AlertManager] --> [Email/WebSocket]
                       --> [Prevention]   --> [Fail2Ban]

Uses asyncio for non-blocking I/O. Maintains per-IP sliding windows.
"""

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Callable

import numpy as np

from src.data_processing.log_parser import SSHLogParser, ParsedLogEntry, EventType
from src.data_processing.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.data_processing.preprocessor import Preprocessor
from src.data_processing.labeler import LabeledEntry
from src.models.isolation_forest import IsolationForestModel
from src.models.dynamic_threshold import DynamicThreshold, ThreatLevel

logger = logging.getLogger(__name__)


class IPWindowManager:
    """Maintains sliding windows of log entries per source IP."""

    def __init__(self, window_minutes: int = 5, max_ips: int = 10000):
        self.window_size = timedelta(minutes=window_minutes)
        self.max_ips = max_ips
        self._windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))

    def add_entry(self, entry: ParsedLogEntry):
        """Add a parsed log entry to its IP's window."""
        if entry.source_ip is None:
            return
        self._windows[entry.source_ip].append(entry)
        self._cleanup_old(entry.source_ip)

    def _cleanup_old(self, ip: str):
        """Remove entries outside the window."""
        if not self._windows[ip]:
            return
        cutoff = self._windows[ip][-1].timestamp - self.window_size
        while self._windows[ip] and self._windows[ip][0].timestamp < cutoff:
            self._windows[ip].popleft()

    def get_active_ips(self) -> List[str]:
        """Get IPs with entries in their current window."""
        return [ip for ip, entries in self._windows.items() if entries]

    def get_entries(self, ip: str) -> List[ParsedLogEntry]:
        """Get current window entries for an IP."""
        return list(self._windows.get(ip, []))

    def clear_ip(self, ip: str):
        """Clear entries for an IP (after ban)."""
        if ip in self._windows:
            del self._windows[ip]


class RealtimePipeline:
    """Real-time SSH brute-force detection pipeline."""

    def __init__(
        self,
        log_path: str = '/var/log/auth.log',
        model_dir: str = 'trained_models',
        scoring_interval: int = 10,
        window_minutes: int = 5,
        on_alert: Optional[Callable] = None,
        on_warning: Optional[Callable] = None,
    ):
        """
        Args:
            log_path: Path to SSH auth log file
            model_dir: Directory containing trained models
            scoring_interval: Seconds between scoring cycles
            window_minutes: Size of per-IP sliding window
            on_alert: Callback for ALERT events (ip, score, decision)
            on_warning: Callback for EARLY_WARNING events
        """
        self.log_path = Path(log_path)
        self.model_dir = Path(model_dir)
        self.scoring_interval = scoring_interval

        # Components
        self.parser = SSHLogParser()
        self.extractor = FeatureExtractor(window_minutes=window_minutes, stride_minutes=window_minutes)
        self.preprocessor = Preprocessor(model_dir=model_dir)
        self.window_manager = IPWindowManager(window_minutes=window_minutes)
        self.threshold = DynamicThreshold()

        # Model (lazy-loaded)
        self._model: Optional[IsolationForestModel] = None

        # Callbacks
        self.on_alert = on_alert
        self.on_warning = on_warning

        # State
        self._running = False
        self._stats = {
            'lines_processed': 0,
            'events_parsed': 0,
            'scoring_cycles': 0,
            'alerts': 0,
            'warnings': 0,
        }

    def _load_model(self):
        """Load trained IF model and scaler."""
        self._model = IsolationForestModel()
        self._model.load(str(self.model_dir / 'isolation_forest.joblib'))
        self.preprocessor.load()
        logger.info("Model and scaler loaded successfully")

    async def start(self):
        """Start the real-time detection pipeline."""
        logger.info(f"Starting pipeline, monitoring: {self.log_path}")

        self._load_model()
        self._running = True

        # Run log tailing and periodic scoring concurrently
        await asyncio.gather(
            self._tail_log(),
            self._periodic_scoring(),
        )

    async def stop(self):
        """Stop the pipeline gracefully."""
        self._running = False
        logger.info("Pipeline stopped")

    async def _tail_log(self):
        """Tail the auth log file for new entries."""
        if not self.log_path.exists():
            logger.warning(f"Log file not found: {self.log_path}")
            # Wait for file to appear
            while self._running and not self.log_path.exists():
                await asyncio.sleep(1)

        # Seek to end of file
        with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(0, 2)  # Seek to end

            while self._running:
                line = f.readline()
                if line:
                    self._stats['lines_processed'] += 1
                    entry = self.parser.parse_line(line)
                    if entry is not None:
                        self._stats['events_parsed'] += 1
                        self.window_manager.add_entry(entry)
                else:
                    await asyncio.sleep(0.1)  # No new data, wait briefly

    async def _periodic_scoring(self):
        """Score active IPs periodically."""
        while self._running:
            await asyncio.sleep(self.scoring_interval)

            active_ips = self.window_manager.get_active_ips()
            if not active_ips:
                continue

            self._stats['scoring_cycles'] += 1

            for ip in active_ips:
                await self._score_ip(ip)

    async def _score_ip(self, ip: str):
        """Extract features and score a single IP."""
        entries = self.window_manager.get_entries(ip)
        if len(entries) < 2:
            return

        # Create labeled entries (label unknown for real-time)
        labeled = [LabeledEntry(entry=e, label='unknown', source_file='realtime') for e in entries]

        # Extract features
        import pandas as pd
        features, _ = self.extractor.extract_from_entries(labeled, return_labels=False)

        if features.empty:
            return

        # Use the latest window's features
        latest_features = features.iloc[[-1]]

        # Preprocess
        try:
            X = self.preprocessor.transform(latest_features)
        except Exception as e:
            logger.error(f"Preprocessing error for IP {ip}: {e}")
            return

        # Get anomaly score
        score = -self._model.score_samples(X)[0]  # Invert: higher = more anomalous

        # Evaluate against dynamic threshold
        decision = self.threshold.evaluate(
            anomaly_score=score,
            timestamp=entries[-1].timestamp,
            source_ip=ip,
        )

        # Handle decision
        if decision.threat_level == ThreatLevel.ALERT:
            self._stats['alerts'] += 1
            logger.warning(f"ALERT: IP {ip} score={score:.4f} ewma={decision.ewma_score:.4f}")
            if self.on_alert:
                await self._call_handler(self.on_alert, ip, score, decision)

        elif decision.threat_level == ThreatLevel.EARLY_WARNING:
            self._stats['warnings'] += 1
            logger.info(f"WARNING: IP {ip} score={score:.4f} ewma={decision.ewma_score:.4f}")
            if self.on_warning:
                await self._call_handler(self.on_warning, ip, score, decision)

    async def _call_handler(self, handler, ip, score, decision):
        """Call alert/warning handler (sync or async)."""
        if asyncio.iscoroutinefunction(handler):
            await handler(ip, score, decision)
        else:
            handler(ip, score, decision)

    def get_stats(self) -> dict:
        """Get pipeline statistics."""
        return {
            **self._stats,
            'active_ips': len(self.window_manager.get_active_ips()),
            'threshold_state': self.threshold.get_state(),
        }

    def process_log_file(self, filepath: str) -> List[dict]:
        """Process a complete log file (offline mode, for testing).

        Returns list of detections with IP, score, and threat level.
        """
        self._load_model()
        detections = []

        for entry in self.parser.parse_file(filepath, expand_repeats=True):
            self.window_manager.add_entry(entry)

        # Score all active IPs
        for ip in self.window_manager.get_active_ips():
            entries = self.window_manager.get_entries(ip)
            if len(entries) < 2:
                continue

            labeled = [LabeledEntry(entry=e, label='unknown', source_file='offline') for e in entries]
            import pandas as pd
            features, _ = self.extractor.extract_from_entries(labeled, return_labels=False)

            if features.empty:
                continue

            for i in range(len(features)):
                row = features.iloc[[i]]
                try:
                    X = self.preprocessor.transform(row)
                    score = -self._model.score_samples(X)[0]
                    decision = self.threshold.evaluate(score, source_ip=ip)
                    detections.append({
                        'ip': ip,
                        'score': float(score),
                        'threat_level': decision.threat_level.value,
                        'ewma': float(decision.ewma_score),
                    })
                except Exception:
                    continue

        return detections
