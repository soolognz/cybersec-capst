"""
Preprocessor - Scales features using RobustScaler and handles NaN values.

RobustScaler is chosen over StandardScaler because:
- Uses median and IQR (resistant to outliers in training data)
- Training data may have occasional extreme values from normal user behavior
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.preprocessing import RobustScaler
from typing import Tuple, Optional
from .feature_extractor import FEATURE_NAMES


class Preprocessor:
    """Preprocess features for model training and inference."""

    def __init__(self, model_dir: str = 'trained_models'):
        self.scaler = RobustScaler()
        self.model_dir = Path(model_dir)
        self.feature_names = FEATURE_NAMES
        self._is_fitted = False

    def fit_transform(self, train_features: pd.DataFrame) -> np.ndarray:
        """Fit scaler on training data and transform.

        Args:
            train_features: Training features DataFrame (normal-only data)

        Returns:
            Scaled feature array
        """
        features = train_features[self.feature_names].copy()

        # Handle NaN/Inf
        features = features.replace([np.inf, -np.inf], np.nan)
        features = features.fillna(0.0)

        scaled = self.scaler.fit_transform(features.values)
        self._is_fitted = True

        return scaled

    def transform(self, features: pd.DataFrame) -> np.ndarray:
        """Transform features using fitted scaler.

        Args:
            features: Features DataFrame to transform

        Returns:
            Scaled feature array
        """
        if not self._is_fitted:
            raise RuntimeError("Preprocessor not fitted. Call fit_transform first.")

        feat = features[self.feature_names].copy()
        feat = feat.replace([np.inf, -np.inf], np.nan)
        feat = feat.fillna(0.0)

        return self.scaler.transform(feat.values)

    def save(self, filename: str = 'scaler.joblib'):
        """Save fitted scaler to disk."""
        self.model_dir.mkdir(parents=True, exist_ok=True)
        filepath = self.model_dir / filename
        joblib.dump(self.scaler, filepath)

    def load(self, filename: str = 'scaler.joblib'):
        """Load fitted scaler from disk."""
        filepath = self.model_dir / filename
        self.scaler = joblib.load(filepath)
        self._is_fitted = True
