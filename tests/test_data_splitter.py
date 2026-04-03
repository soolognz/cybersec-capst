"""Tests for Data Splitter."""

import pytest
import pandas as pd
import numpy as np
from src.data_processing.data_splitter import DataSplitter
from src.data_processing.feature_extractor import FEATURE_NAMES


@pytest.fixture
def sample_data():
    """Create sample feature data."""
    rng = np.random.RandomState(42)
    n_sim = 100
    n_hp = 200

    sim_features = pd.DataFrame(
        rng.randn(n_sim, 14), columns=FEATURE_NAMES
    )
    sim_features['source_ip'] = '192.168.1.1'
    sim_features['window_start'] = pd.date_range('2026-01-01', periods=n_sim, freq='5min')
    sim_features['window_end'] = sim_features['window_start'] + pd.Timedelta(minutes=5)
    sim_features['entry_count'] = 10
    sim_labels = pd.Series(['normal'] * n_sim)

    hp_features = pd.DataFrame(
        rng.randn(n_hp, 14) + 3, columns=FEATURE_NAMES
    )
    hp_features['source_ip'] = '10.0.0.1'
    hp_features['window_start'] = pd.date_range('2026-01-01', periods=n_hp, freq='5min')
    hp_features['window_end'] = hp_features['window_start'] + pd.Timedelta(minutes=5)
    hp_features['entry_count'] = 20
    hp_labels = pd.Series(['normal'] * 20 + ['attack'] * 180)

    return sim_features, sim_labels, hp_features, hp_labels


class TestDataSplitter:
    def test_split_produces_train_test(self, sample_data):
        splitter = DataSplitter()
        result = splitter.split(*sample_data)
        assert 'train' in result
        assert 'test' in result

    def test_train_is_normal_only(self, sample_data):
        splitter = DataSplitter()
        result = splitter.split(*sample_data)
        train_features, train_labels = result['train']
        assert (train_labels == 'normal').all()

    def test_train_ratio(self, sample_data):
        splitter = DataSplitter(train_ratio=0.7)
        result = splitter.split(*sample_data)
        train_features, _ = result['train']
        # Train should be ~70% of simulation data (100 samples)
        assert 65 <= len(train_features) <= 75

    def test_test_has_both_labels(self, sample_data):
        splitter = DataSplitter()
        result = splitter.split(*sample_data)
        test_features, test_labels = result['test']
        assert 'normal' in test_labels.values
        assert 'attack' in test_labels.values

    def test_feature_columns_only(self, sample_data):
        splitter = DataSplitter()
        result = splitter.split(*sample_data)
        train_features, _ = result['train']
        # Should only have the 14 feature columns
        assert list(train_features.columns) == FEATURE_NAMES

    def test_stats(self, sample_data):
        splitter = DataSplitter()
        result = splitter.split(*sample_data)
        stats = splitter.get_split_stats(result)
        assert stats['train_total'] > 0
        assert stats['test_total'] > 0
        assert stats['train_attack'] == 0
