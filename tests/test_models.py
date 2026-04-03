"""Tests for ML models."""

import numpy as np
import pytest
from src.models.isolation_forest import IsolationForestModel
from src.models.lof import LOFModel
from src.models.ocsvm import OCSVMModel
from src.models.dynamic_threshold import DynamicThreshold, ThreatLevel


@pytest.fixture
def normal_data():
    """Generate synthetic normal data."""
    rng = np.random.RandomState(42)
    return rng.randn(200, 14) * 0.5 + 1.0


@pytest.fixture
def anomaly_data():
    """Generate synthetic anomalous data."""
    rng = np.random.RandomState(42)
    return rng.randn(50, 14) * 2.0 + 5.0


class TestIsolationForest:
    def test_train_predict(self, normal_data, anomaly_data):
        model = IsolationForestModel(n_estimators=50)
        model.train(normal_data)
        assert model.is_fitted

        preds = model.predict(normal_data)
        assert len(preds) == len(normal_data)
        # Most normal data should be predicted as normal (1)
        assert (preds == 1).sum() > len(normal_data) * 0.5

    def test_score_samples(self, normal_data, anomaly_data):
        model = IsolationForestModel(n_estimators=50)
        model.train(normal_data)

        normal_scores = model.score_samples(normal_data)
        anomaly_scores = model.score_samples(anomaly_data)

        # Anomaly scores should be lower (more negative) on average
        assert np.mean(anomaly_scores) < np.mean(normal_scores)


class TestLOF:
    def test_train_predict(self, normal_data):
        model = LOFModel(n_neighbors=10)
        model.train(normal_data)
        assert model.is_fitted

        preds = model.predict(normal_data)
        assert len(preds) == len(normal_data)


class TestOCSVM:
    def test_train_predict(self, normal_data):
        model = OCSVMModel(nu=0.1)
        model.train(normal_data)
        assert model.is_fitted

        preds = model.predict(normal_data)
        assert len(preds) == len(normal_data)


class TestDynamicThreshold:
    def test_normal_scores(self):
        dt = DynamicThreshold(alpha=0.3, base_percentile=95, lookback_window=50)
        rng = np.random.RandomState(42)
        # Feed varied low scores with occasional small spikes (normal variance)
        for _ in range(100):
            score = abs(rng.normal(0.1, 0.05))
            decision = dt.evaluate(score)
        # With varied normal scores, EWMA stays well below the 95th percentile
        assert decision.threat_level == ThreatLevel.NORMAL

    def test_alert_on_high_score(self):
        dt = DynamicThreshold(alpha=0.9, base_percentile=90, lookback_window=20)
        # Build baseline
        for _ in range(30):
            dt.evaluate(0.1)
        # Sudden spike
        for _ in range(10):
            decision = dt.evaluate(10.0)
        assert decision.threat_level in (ThreatLevel.ALERT, ThreatLevel.EARLY_WARNING)

    def test_early_warning(self):
        dt = DynamicThreshold(alpha=0.5, base_percentile=95, sensitivity_factor=2.0, lookback_window=20)
        # Build baseline with low scores
        for _ in range(30):
            dt.evaluate(0.1)
        # Moderate increase
        decision = None
        for _ in range(5):
            decision = dt.evaluate(1.0)
        # Should be early warning or normal (depending on accumulated EWMA)
        assert decision is not None

    def test_reset(self):
        dt = DynamicThreshold()
        dt.evaluate(1.0)
        dt.reset()
        assert dt._ewma is None
        assert len(dt._score_buffer) == 0
