"""
Local Outlier Factor (LOF) Model - Benchmark for comparison.

LOF (Breunig et al., 2000) measures the local density deviation of a data point
with respect to its neighbors. Points with substantially lower density than
their neighbors are considered outliers.

Note: novelty=True is required for prediction on unseen data.
"""

import time
import joblib
import numpy as np
from pathlib import Path
from sklearn.neighbors import LocalOutlierFactor
from sklearn.model_selection import ParameterGrid
from sklearn.metrics import f1_score
from typing import Dict, Optional, Tuple


class LOFModel:
    """Local Outlier Factor wrapper with training, prediction, and tuning."""

    def __init__(
        self,
        n_neighbors: int = 20,
        contamination: str = 'auto',
        metric: str = 'euclidean',
        novelty: bool = True,
    ):
        self.params = {
            'n_neighbors': n_neighbors,
            'contamination': contamination,
            'metric': metric,
            'novelty': novelty,
        }
        self.model = LocalOutlierFactor(**self.params)
        self.training_time: float = 0.0
        self.is_fitted: bool = False

    def train(self, X_train: np.ndarray) -> 'LOFModel':
        """Train on normal-only data."""
        start = time.time()
        self.model.fit(X_train)
        self.training_time = time.time() - start
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly labels: 1 (normal) or -1 (anomaly)."""
        return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores (negative LOF scores; lower = more anomalous)."""
        return self.model.score_samples(X)

    def predict_labels(self, X: np.ndarray) -> np.ndarray:
        """Predict as 'normal'/'attack' string labels."""
        preds = self.predict(X)
        return np.where(preds == 1, 'normal', 'attack')

    def tune_hyperparameters(
        self,
        X_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        param_grid: Optional[Dict] = None,
    ) -> Tuple['LOFModel', Dict]:
        """Grid search for best hyperparameters."""
        if param_grid is None:
            param_grid = {
                'n_neighbors': [10, 20, 30, 50],
            }

        y_binary = np.where(y_test == 'normal', 1, -1)
        best_f1 = -1
        best_params = {}
        results = []

        for params in ParameterGrid(param_grid):
            model = LocalOutlierFactor(
                novelty=True,
                contamination='auto',
                metric='euclidean',
                **params
            )
            model.fit(X_train)
            preds = model.predict(X_test)
            f1 = f1_score(y_binary, preds, pos_label=-1, zero_division=0)

            results.append({**params, 'f1_score': f1})
            if f1 > best_f1:
                best_f1 = f1
                best_params = params

        self.params.update(best_params)
        self.model = LocalOutlierFactor(
            novelty=True, contamination='auto', metric='euclidean',
            **best_params
        )
        self.train(X_train)

        return self, {'best_params': best_params, 'best_f1': best_f1, 'all_results': results}

    def save(self, path: str = 'trained_models/lof.joblib'):
        """Save model to disk."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            'model': self.model,
            'params': self.params,
            'training_time': self.training_time,
        }, path)

    def load(self, path: str = 'trained_models/lof.joblib'):
        """Load model from disk."""
        data = joblib.load(path)
        self.model = data['model']
        self.params = data['params']
        self.training_time = data['training_time']
        self.is_fitted = True
        return self
