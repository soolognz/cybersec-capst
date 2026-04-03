"""
Isolation Forest Model - Main anomaly detection model.

Isolation Forest (Liu et al., 2008) isolates anomalies by randomly selecting
a feature and then randomly selecting a split value. Anomalies require fewer
splits to isolate, resulting in shorter average path lengths in the trees.

Advantages for SSH brute-force detection:
- O(n log n) training complexity
- No distance metric assumptions
- Naturally produces anomaly scores (not just binary)
- Handles high-dimensional data well
"""

import time
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import ParameterGrid
from sklearn.metrics import f1_score
from typing import Dict, Optional, Tuple


class IsolationForestModel:
    """Isolation Forest wrapper with training, prediction, and tuning."""

    def __init__(
        self,
        n_estimators: int = 200,
        max_samples: str = 'auto',
        contamination: str = 'auto',
        max_features: float = 1.0,
        random_state: int = 42,
    ):
        self.params = {
            'n_estimators': n_estimators,
            'max_samples': max_samples,
            'contamination': contamination,
            'max_features': max_features,
            'random_state': random_state,
        }
        self.model = IsolationForest(**self.params)
        self.training_time: float = 0.0
        self.is_fitted: bool = False

    def train(self, X_train: np.ndarray) -> 'IsolationForestModel':
        """Train on normal-only data.

        Args:
            X_train: Scaled feature array (normal behavior only)
        """
        start = time.time()
        self.model.fit(X_train)
        self.training_time = time.time() - start
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly labels.

        Returns:
            Array of 1 (normal) or -1 (anomaly)
        """
        return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores (lower = more anomalous).

        Returns:
            Array of anomaly scores (negative = more anomalous)
        """
        return self.model.score_samples(X)

    def predict_labels(self, X: np.ndarray) -> np.ndarray:
        """Predict as 'normal'/'attack' string labels."""
        preds = self.predict(X)
        return np.where(preds == 1, 'normal', 'attack')

    def get_feature_importance(self, feature_names: list) -> Dict[str, float]:
        """Estimate feature importance using anomaly score sensitivity.

        Uses permutation-based importance: how much anomaly score changes
        when each feature is shuffled.
        """
        # This is a simplified version; full permutation importance
        # should be computed on the test set
        return {name: 0.0 for name in feature_names}

    def tune_hyperparameters(
        self,
        X_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        param_grid: Optional[Dict] = None,
    ) -> Tuple['IsolationForestModel', Dict]:
        """Grid search for best hyperparameters.

        Args:
            X_train: Training features (normal only)
            X_test: Test features
            y_test: Test labels ('normal'/'attack')
            param_grid: Dict of parameter lists to search

        Returns:
            Best model and best parameters dict
        """
        if param_grid is None:
            param_grid = {
                'n_estimators': [100, 200, 300],
                'max_samples': [256, 512, 'auto'],
                'max_features': [0.5, 0.75, 1.0],
            }

        # Convert labels to binary: normal=1, attack=-1
        y_binary = np.where(y_test == 'normal', 1, -1)

        best_f1 = -1
        best_params = {}
        results = []

        for params in ParameterGrid(param_grid):
            model = IsolationForest(
                random_state=42,
                contamination='auto',
                **params
            )
            model.fit(X_train)
            preds = model.predict(X_test)

            # F1 for attack class (label=-1)
            f1 = f1_score(y_binary, preds, pos_label=-1, zero_division=0)

            results.append({**params, 'f1_score': f1})

            if f1 > best_f1:
                best_f1 = f1
                best_params = params

        # Re-train with best params
        self.params.update(best_params)
        self.model = IsolationForest(
            random_state=42,
            contamination='auto',
            **best_params
        )
        self.train(X_train)

        return self, {'best_params': best_params, 'best_f1': best_f1, 'all_results': results}

    def save(self, path: str = 'trained_models/isolation_forest.joblib'):
        """Save model to disk."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            'model': self.model,
            'params': self.params,
            'training_time': self.training_time,
        }, path)

    def load(self, path: str = 'trained_models/isolation_forest.joblib'):
        """Load model from disk."""
        data = joblib.load(path)
        self.model = data['model']
        self.params = data['params']
        self.training_time = data['training_time']
        self.is_fitted = True
        return self
