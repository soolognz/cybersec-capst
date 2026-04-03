"""
One-Class SVM Model - Benchmark for comparison.

One-Class SVM (Scholkopf et al., 2001) learns a decision boundary that
encompasses the normal training data. Points falling outside this boundary
are classified as anomalies.

Uses RBF kernel by default for non-linear boundary.
"""

import time
import joblib
import numpy as np
from pathlib import Path
from sklearn.svm import OneClassSVM
from sklearn.model_selection import ParameterGrid
from sklearn.metrics import f1_score
from typing import Dict, Optional, Tuple


class OCSVMModel:
    """One-Class SVM wrapper with training, prediction, and tuning."""

    def __init__(
        self,
        kernel: str = 'rbf',
        gamma: str = 'scale',
        nu: float = 0.05,
    ):
        self.params = {
            'kernel': kernel,
            'gamma': gamma,
            'nu': nu,
        }
        self.model = OneClassSVM(**self.params)
        self.training_time: float = 0.0
        self.is_fitted: bool = False

    def train(self, X_train: np.ndarray) -> 'OCSVMModel':
        """Train on normal-only data.

        Note: OCSVM can be slow on large datasets. Consider subsampling
        if training data exceeds 10,000 samples.
        """
        # Subsample for performance if needed
        if len(X_train) > 5000:
            rng = np.random.RandomState(42)
            idx = rng.choice(len(X_train), size=5000, replace=False)
            X_subset = X_train[idx]
        else:
            X_subset = X_train

        start = time.time()
        self.model.fit(X_subset)
        self.training_time = time.time() - start
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly labels: 1 (normal) or -1 (anomaly)."""
        return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores (signed distance to boundary; lower = more anomalous)."""
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
    ) -> Tuple['OCSVMModel', Dict]:
        """Grid search for best hyperparameters."""
        if param_grid is None:
            param_grid = {
                'nu': [0.01, 0.05, 0.1],
                'gamma': ['scale', 'auto'],
            }

        y_binary = np.where(y_test == 'normal', 1, -1)
        best_f1 = -1
        best_params = {}
        results = []

        for params in ParameterGrid(param_grid):
            model = OneClassSVM(kernel='rbf', **params)

            # Subsample for speed
            if len(X_train) > 5000:
                rng = np.random.RandomState(42)
                idx = rng.choice(len(X_train), size=5000, replace=False)
                model.fit(X_train[idx])
            else:
                model.fit(X_train)

            preds = model.predict(X_test)
            f1 = f1_score(y_binary, preds, pos_label=-1, zero_division=0)

            results.append({**params, 'f1_score': f1})
            if f1 > best_f1:
                best_f1 = f1
                best_params = params

        self.params.update(best_params)
        self.model = OneClassSVM(kernel='rbf', **best_params)
        self.train(X_train)

        return self, {'best_params': best_params, 'best_f1': best_f1, 'all_results': results}

    def save(self, path: str = 'trained_models/ocsvm.joblib'):
        """Save model to disk."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            'model': self.model,
            'params': self.params,
            'training_time': self.training_time,
        }, path)

    def load(self, path: str = 'trained_models/ocsvm.joblib'):
        """Load model from disk."""
        data = joblib.load(path)
        self.model = data['model']
        self.params = data['params']
        self.training_time = data['training_time']
        self.is_fitted = True
        return self
