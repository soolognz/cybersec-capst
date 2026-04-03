"""
Dynamic Threshold Engine - EWMA-Adaptive Percentile Hybrid.

Core innovation of the thesis: enables early prediction of brute-force attacks
before they fully escalate, unlike static threshold systems like Fail2Ban.

Algorithm combines:
1. EWMA (Exponentially Weighted Moving Average) for score smoothing
2. Adaptive percentile-based threshold from recent score distribution
3. Two-level detection: EARLY_WARNING and ALERT
4. Self-calibration based on false positive rate

References:
- Montgomery, D.C. (2019). Statistical Quality Control. (EWMA control charts)
- Chandola, V. et al. (2009). Anomaly Detection: A Survey. ACM Computing Surveys.
- Lucas, J.M. & Saccucci, M.S. (1990). EWMA Control Chart Properties. Technometrics.
"""

import numpy as np
from collections import deque
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Tuple
from datetime import datetime


class ThreatLevel(str, Enum):
    NORMAL = "normal"
    EARLY_WARNING = "early_warning"
    ALERT = "alert"


@dataclass
class ThresholdDecision:
    """Result of threshold evaluation for a single score."""
    threat_level: ThreatLevel
    raw_score: float
    ewma_score: float
    adaptive_threshold: float
    early_warning_threshold: float
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None


class DynamicThreshold:
    """EWMA-Adaptive Percentile hybrid threshold for early attack prediction.

    The algorithm works in three stages:
    1. EWMA Smoothing: Reduces noise in individual anomaly scores while
       responding quickly to sustained anomalies.
    2. Adaptive Threshold: Computes threshold from the percentile of recent
       scores, adapting to the current baseline behavior.
    3. Two-Level Detection: Early warning threshold (lower) catches attack
       onset; alert threshold (higher) confirms active attack.

    The early warning capability is what enables "early prediction" - the system
    can warn about an emerging attack before it reaches full intensity.
    """

    def __init__(
        self,
        alpha: float = 0.3,
        base_percentile: float = 95.0,
        sensitivity_factor: float = 1.5,
        lookback_window: int = 100,
        cooldown_minutes: int = 5,
        fp_target: float = 0.02,
    ):
        """
        Args:
            alpha: EWMA smoothing factor (0-1). Higher = more responsive to changes.
                   0.3 balances noise reduction with responsiveness.
            base_percentile: Percentile of recent scores used as threshold (0-100).
                            95th percentile means only top 5% of scores trigger alerts.
            sensitivity_factor: Multiplier for early warning threshold.
                               early_warning = adaptive_threshold / sensitivity_factor.
                               1.5 means early warning triggers at 67% of alert threshold.
            lookback_window: Number of recent scores for percentile computation.
            cooldown_minutes: Minimum minutes between alerts for the same IP.
            fp_target: Target false positive rate for self-calibration.
        """
        self.alpha = alpha
        self.base_percentile = base_percentile
        self.sensitivity_factor = sensitivity_factor
        self.lookback_window = lookback_window
        self.cooldown_minutes = cooldown_minutes
        self.fp_target = fp_target

        # State
        self._score_buffer = deque(maxlen=lookback_window)
        self._ewma: Optional[float] = None
        self._alert_history: dict = {}  # ip -> last alert timestamp
        self._decision_history: List[ThresholdDecision] = []

        # Self-calibration state
        self._normal_scores = deque(maxlen=lookback_window * 2)
        self._total_decisions = 0
        self._false_positives = 0

    def evaluate(
        self,
        anomaly_score: float,
        timestamp: Optional[datetime] = None,
        source_ip: Optional[str] = None,
    ) -> ThresholdDecision:
        """Evaluate a single anomaly score against the dynamic threshold.

        Args:
            anomaly_score: Raw anomaly score from the model (inverted: higher = more anomalous)
            timestamp: When this score was computed
            source_ip: Source IP this score belongs to

        Returns:
            ThresholdDecision with threat level and threshold values
        """
        # Step 1: Update EWMA
        if self._ewma is None:
            self._ewma = anomaly_score
        else:
            self._ewma = self.alpha * anomaly_score + (1 - self.alpha) * self._ewma

        # Step 2: Update score buffer
        self._score_buffer.append(anomaly_score)

        # Step 3: Compute adaptive threshold
        if len(self._score_buffer) >= 10:
            adaptive_threshold = float(np.percentile(
                list(self._score_buffer), self.base_percentile
            ))
        else:
            # Not enough data - use a conservative default
            adaptive_threshold = anomaly_score * 2.0

        # Step 4: Compute early warning threshold
        early_warning_threshold = adaptive_threshold / self.sensitivity_factor

        # Step 5: Make decision based on EWMA score
        if self._ewma >= adaptive_threshold:
            threat_level = ThreatLevel.ALERT
        elif self._ewma >= early_warning_threshold:
            threat_level = ThreatLevel.EARLY_WARNING
        else:
            threat_level = ThreatLevel.NORMAL
            self._normal_scores.append(anomaly_score)

        # Step 6: Apply cooldown
        if source_ip and threat_level != ThreatLevel.NORMAL:
            if self._is_in_cooldown(source_ip, timestamp):
                threat_level = ThreatLevel.NORMAL  # Suppress during cooldown
            else:
                self._alert_history[source_ip] = timestamp

        decision = ThresholdDecision(
            threat_level=threat_level,
            raw_score=anomaly_score,
            ewma_score=self._ewma,
            adaptive_threshold=adaptive_threshold,
            early_warning_threshold=early_warning_threshold,
            timestamp=timestamp,
            source_ip=source_ip,
        )

        self._decision_history.append(decision)
        self._total_decisions += 1

        return decision

    def _is_in_cooldown(self, source_ip: str, timestamp: Optional[datetime]) -> bool:
        """Check if an IP is in alert cooldown period."""
        if source_ip not in self._alert_history:
            return False
        if timestamp is None:
            return False

        last_alert = self._alert_history[source_ip]
        if last_alert is None:
            return False

        from datetime import timedelta
        return (timestamp - last_alert) < timedelta(minutes=self.cooldown_minutes)

    def calibrate(self):
        """Self-calibrate threshold based on observed false positive rate.

        If FP rate is too high, increase base_percentile (less sensitive).
        If detection rate is dropping, decrease base_percentile (more sensitive).
        """
        if self._total_decisions < 50:
            return  # Need enough data

        # Recalculate from normal scores
        if len(self._normal_scores) >= 20:
            current_fp_rate = self._false_positives / max(self._total_decisions, 1)

            if current_fp_rate > self.fp_target:
                # Too many false positives - raise threshold
                self.base_percentile = min(99.0, self.base_percentile + 1.0)
            elif current_fp_rate < self.fp_target * 0.5:
                # Very low FP rate - can lower threshold for better detection
                self.base_percentile = max(85.0, self.base_percentile - 0.5)

    def reset(self):
        """Reset all state (for new monitoring session)."""
        self._score_buffer.clear()
        self._ewma = None
        self._alert_history.clear()
        self._decision_history.clear()
        self._normal_scores.clear()
        self._total_decisions = 0
        self._false_positives = 0

    def get_state(self) -> dict:
        """Get current threshold state for monitoring."""
        return {
            'ewma': self._ewma,
            'buffer_size': len(self._score_buffer),
            'base_percentile': self.base_percentile,
            'alpha': self.alpha,
            'total_decisions': self._total_decisions,
            'active_alerts': len(self._alert_history),
        }

    def evaluate_batch(
        self,
        scores: np.ndarray,
        labels: np.ndarray = None,
    ) -> Tuple[List[ThresholdDecision], dict]:
        """Evaluate a batch of scores (for offline analysis).

        Args:
            scores: Array of anomaly scores (higher = more anomalous)
            labels: Optional true labels ('normal'/'attack') for performance metrics

        Returns:
            List of decisions and performance metrics dict
        """
        self.reset()
        decisions = []

        for score in scores:
            decision = self.evaluate(float(score))
            decisions.append(decision)

        metrics = {}
        if labels is not None:
            predicted = np.array([
                'attack' if d.threat_level in (ThreatLevel.ALERT, ThreatLevel.EARLY_WARNING)
                else 'normal'
                for d in decisions
            ])

            y_true = (labels == 'attack').astype(int)
            y_pred = (predicted == 'attack').astype(int)

            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            metrics = {
                'accuracy': accuracy_score(y_true, y_pred),
                'precision': precision_score(y_true, y_pred, zero_division=0),
                'recall': recall_score(y_true, y_pred, zero_division=0),
                'f1_score': f1_score(y_true, y_pred, zero_division=0),
                'early_warnings': sum(1 for d in decisions if d.threat_level == ThreatLevel.EARLY_WARNING),
                'alerts': sum(1 for d in decisions if d.threat_level == ThreatLevel.ALERT),
                'normal': sum(1 for d in decisions if d.threat_level == ThreatLevel.NORMAL),
            }

        return decisions, metrics
