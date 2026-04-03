"""Tests for Preprocessor."""

import pytest
import numpy as np
import pandas as pd
from src.data_processing.preprocessor import Preprocessor
from src.data_processing.feature_extractor import FEATURE_NAMES


@pytest.fixture
def sample_features():
    rng = np.random.RandomState(42)
    return pd.DataFrame(rng.randn(50, 14), columns=FEATURE_NAMES)


class TestPreprocessor:
    def test_fit_transform(self, sample_features):
        prep = Preprocessor(model_dir='trained_models')
        result = prep.fit_transform(sample_features)
        assert result.shape == (50, 14)
        assert prep._is_fitted

    def test_transform_requires_fit(self, sample_features):
        prep = Preprocessor(model_dir='trained_models')
        with pytest.raises(RuntimeError):
            prep.transform(sample_features)

    def test_transform_after_fit(self, sample_features):
        prep = Preprocessor(model_dir='trained_models')
        prep.fit_transform(sample_features)
        result = prep.transform(sample_features)
        assert result.shape == (50, 14)

    def test_handles_nan(self, sample_features):
        sample_features.iloc[0, 0] = np.nan
        sample_features.iloc[1, 3] = np.inf
        prep = Preprocessor(model_dir='trained_models')
        result = prep.fit_transform(sample_features)
        assert not np.any(np.isnan(result))
        assert not np.any(np.isinf(result))

    def test_save_load(self, sample_features, tmp_path):
        prep = Preprocessor(model_dir=str(tmp_path))
        prep.fit_transform(sample_features)
        prep.save('test_scaler.joblib')

        prep2 = Preprocessor(model_dir=str(tmp_path))
        prep2.load('test_scaler.joblib')
        assert prep2._is_fitted

        result = prep2.transform(sample_features)
        assert result.shape == (50, 14)
