"""
Model Comparator - Side-by-side evaluation of IF, LOF, and OCSVM.

Computes comprehensive metrics for thesis report:
- Accuracy, Precision, Recall, F1-Score
- ROC-AUC, PR-AUC
- Confusion matrices
- Training/inference time
- Memory footprint
"""

import sys
import time
import numpy as np
import pandas as pd
from typing import Dict, List
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score,
    confusion_matrix, classification_report, roc_curve,
    precision_recall_curve,
)


class ModelComparator:
    """Compare anomaly detection models on the same test set."""

    def __init__(self):
        self.results: Dict[str, Dict] = {}

    def evaluate_model(
        self,
        model_name: str,
        model,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> Dict:
        """Evaluate a single model on the test set.

        Args:
            model_name: Name for display ('Isolation Forest', 'LOF', 'OCSVM')
            model: Trained model with predict() and score_samples()
            X_test: Scaled test features
            y_test: True labels ('normal'/'attack')

        Returns:
            Dictionary of evaluation metrics
        """
        # Convert labels to binary: normal=0, attack=1
        y_true = np.where(y_test == 'attack', 1, 0)

        # Get predictions
        start = time.time()
        raw_preds = model.predict(X_test)
        inference_time = time.time() - start

        # Convert sklearn convention (1=normal, -1=anomaly) to (0=normal, 1=attack)
        y_pred = np.where(raw_preds == -1, 1, 0)

        # Get anomaly scores for ROC/PR curves
        scores = model.score_samples(X_test)
        # Invert scores: sklearn uses lower=more anomalous, ROC expects higher=more positive
        anomaly_scores = -scores

        # Metrics
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        # AUC metrics using anomaly scores
        try:
            roc_auc = roc_auc_score(y_true, anomaly_scores)
        except ValueError:
            roc_auc = 0.0

        try:
            pr_auc = average_precision_score(y_true, anomaly_scores)
        except ValueError:
            pr_auc = 0.0

        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()

        # False positive rate
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # ROC curve data
        fpr_curve, tpr_curve, roc_thresholds = roc_curve(y_true, anomaly_scores)

        # PR curve data
        prec_curve, rec_curve, pr_thresholds = precision_recall_curve(y_true, anomaly_scores)

        # Memory estimate
        model_size = sys.getsizeof(model)

        result = {
            'model_name': model_name,
            'accuracy': round(acc, 4),
            'precision': round(prec, 4),
            'recall': round(rec, 4),
            'f1_score': round(f1, 4),
            'roc_auc': round(roc_auc, 4),
            'pr_auc': round(pr_auc, 4),
            'false_positive_rate': round(fpr, 4),
            'true_positives': int(tp),
            'false_positives': int(fp),
            'true_negatives': int(tn),
            'false_negatives': int(fn),
            'confusion_matrix': cm,
            'training_time': round(model.training_time, 4),
            'inference_time_total': round(inference_time, 4),
            'inference_time_per_sample': round(inference_time / len(X_test), 6),
            'model_size_bytes': model_size,
            'roc_curve': (fpr_curve, tpr_curve),
            'pr_curve': (prec_curve, rec_curve),
            'classification_report': classification_report(
                y_true, y_pred, target_names=['normal', 'attack'], zero_division=0
            ),
        }

        self.results[model_name] = result
        return result

    def get_comparison_table(self) -> pd.DataFrame:
        """Get a comparison table of all evaluated models."""
        rows = []
        for name, r in self.results.items():
            rows.append({
                'Model': name,
                'Accuracy': r['accuracy'],
                'Precision': r['precision'],
                'Recall': r['recall'],
                'F1-Score': r['f1_score'],
                'ROC-AUC': r['roc_auc'],
                'PR-AUC': r['pr_auc'],
                'FPR': r['false_positive_rate'],
                'Training Time (s)': r['training_time'],
                'Inference Time/sample (s)': r['inference_time_per_sample'],
            })
        return pd.DataFrame(rows).set_index('Model')

    def print_comparison(self):
        """Print formatted comparison results."""
        table = self.get_comparison_table()
        print("\n" + "=" * 80)
        print("MODEL COMPARISON RESULTS")
        print("=" * 80)
        print(table.to_string())
        print("\n")

        for name, r in self.results.items():
            print(f"\n--- {name} ---")
            print(f"Confusion Matrix:")
            print(f"  TN={r['true_negatives']}, FP={r['false_positives']}")
            print(f"  FN={r['false_negatives']}, TP={r['true_positives']}")
            print(f"\n{r['classification_report']}")
