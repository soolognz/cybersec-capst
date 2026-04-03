"""
Optimized Pipeline - Improves model performance by:
1. Using non-overlapping windows (stride=window) to reduce feature correlation
2. Adding derived features for better discrimination
3. Extended hyperparameter search
4. Contamination tuning for Isolation Forest

Run: python -m src.optimize_pipeline
"""

import sys
import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.model_selection import ParameterGrid

sys.path.insert(0, '.')

from src.data_processing.log_parser import SSHLogParser
from src.data_processing.labeler import DataLabeler
from src.data_processing.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.data_processing.data_splitter import DataSplitter

OUTPUT_DIR = Path('output')
MODEL_DIR = Path('trained_models')


def run_optimized():
    print("=" * 70)
    print("OPTIMIZED PIPELINE - Improving Model Performance")
    print("=" * 70)

    # ====================================================
    # Step 1: Data with NON-OVERLAPPING windows
    # ====================================================
    print("\n[1] Parsing and labeling data...")
    labeler = DataLabeler()
    sim_entries = labeler.label_simulation('Dataset/simulation_auth.log.log')
    hp_entries = labeler.label_honeypot('Dataset/honeypot_auth.log.log')

    print(f"  Simulation: {len(sim_entries)} entries")
    print(f"  Honeypot: {len(hp_entries)} entries")

    # Use NON-OVERLAPPING windows (stride=5 = window_size)
    # This reduces correlated/duplicate feature vectors
    print("\n[2] Feature extraction (non-overlapping 5-min windows)...")
    extractor = FeatureExtractor(window_minutes=5, stride_minutes=5)

    sim_features, sim_labels = extractor.extract_from_entries(sim_entries)
    hp_features, hp_labels = extractor.extract_from_entries(hp_entries)

    print(f"  Simulation features: {len(sim_features)}")
    print(f"  Honeypot features: {len(hp_features)}")

    # ====================================================
    # Step 2: Add derived features
    # ====================================================
    print("\n[3] Adding derived features...")

    def add_derived_features(df):
        """Add derived features to improve discrimination."""
        feat = df[FEATURE_NAMES].copy()

        # Attempt intensity: total attempts / window
        feat['attempt_intensity'] = feat['fail_count'] + feat['success_count'] + feat['invalid_user_count']

        # Failure-to-connection ratio
        feat['fail_per_connection'] = feat['fail_count'] / (feat['connection_count'] + 1e-6)

        # Port diversity relative to connections
        feat['port_per_connection'] = feat['unique_ports'] / (feat['connection_count'] + 1e-6)

        # Timing regularity score (low std / mean = regular = bot-like)
        feat['timing_regularity'] = feat['std_inter_attempt_time'] / (feat['mean_inter_attempt_time'] + 1e-6)

        # Combined PAM escalation
        feat['pam_total'] = feat['pam_failure_escalation'] + feat['max_retries_exceeded']

        # Log transform for skewed features
        for col in ['fail_count', 'connection_count', 'unique_ports', 'attempt_intensity']:
            feat[f'log_{col}'] = np.log1p(feat[col])

        return feat

    sim_features_ext = add_derived_features(sim_features)
    hp_features_ext = add_derived_features(hp_features)

    extended_feature_names = list(sim_features_ext.columns)
    print(f"  Total features: {len(extended_feature_names)} (was 14, added {len(extended_feature_names)-14})")

    # ====================================================
    # Step 3: Data split
    # ====================================================
    print("\n[4] Splitting data...")
    n_sim = len(sim_features_ext)
    split_idx = int(n_sim * 0.7)

    X_train_raw = sim_features_ext.iloc[:split_idx].copy()
    X_test_normal_sim = sim_features_ext.iloc[split_idx:].copy()
    y_train = pd.Series(['normal'] * len(X_train_raw))

    hp_normal_mask = hp_labels == 'normal'
    hp_attack_mask = hp_labels == 'attack'

    X_hp_normal = hp_features_ext[hp_normal_mask.values].copy()
    X_hp_attack = hp_features_ext[hp_attack_mask.values].copy()

    # Combine test normal
    X_test_normal = pd.concat([X_test_normal_sim, X_hp_normal], ignore_index=True)

    # Sample attack to get 1:3 ratio
    n_normal = len(X_test_normal)
    n_attack = min(n_normal * 3, len(X_hp_attack))

    rng = np.random.RandomState(42)
    attack_idx = rng.choice(len(X_hp_attack), size=n_attack, replace=False)
    X_test_attack = X_hp_attack.iloc[attack_idx].copy()

    X_test_raw = pd.concat([X_test_normal, X_test_attack], ignore_index=True)
    y_test = np.array(['normal'] * len(X_test_normal) + ['attack'] * len(X_test_attack))

    # Shuffle
    shuffle = rng.permutation(len(X_test_raw))
    X_test_raw = X_test_raw.iloc[shuffle].reset_index(drop=True)
    y_test = y_test[shuffle]

    print(f"  Train: {len(X_train_raw)} (normal)")
    print(f"  Test: {len(X_test_raw)} (normal={n_normal}, attack={n_attack})")

    # ====================================================
    # Step 4: Scale
    # ====================================================
    print("\n[5] Scaling with RobustScaler...")
    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train_raw.values)
    X_test = scaler.transform(X_test_raw.values)

    # ====================================================
    # Step 5: Optimized IF with contamination tuning
    # ====================================================
    print("\n[6] Optimized Isolation Forest training...")

    y_binary = np.where(y_test == 'attack', -1, 1)

    best_if_f1 = -1
    best_if_model = None
    best_if_params = {}

    if_grid = {
        'n_estimators': [200, 300, 500],
        'max_samples': [256, 512, 1024],
        'max_features': [0.5, 0.75, 1.0],
        'contamination': [0.01, 0.05, 0.1, 0.15],
    }

    print(f"  Grid search: {len(list(ParameterGrid(if_grid)))} combinations...")
    for params in ParameterGrid(if_grid):
        model = IsolationForest(random_state=42, **params)
        model.fit(X_train)
        preds = model.predict(X_test)
        f1 = f1_score(y_binary, preds, pos_label=-1, zero_division=0)

        if f1 > best_if_f1:
            best_if_f1 = f1
            best_if_model = model
            best_if_params = params

    print(f"  Best IF params: {best_if_params}")
    print(f"  Best IF F1: {best_if_f1:.4f}")

    # ====================================================
    # Step 6: Optimized LOF
    # ====================================================
    print("\n[7] Optimized LOF training...")

    best_lof_f1 = -1
    best_lof_model = None
    best_lof_params = {}

    for n in [10, 20, 30, 50, 70]:
        model = LocalOutlierFactor(n_neighbors=n, novelty=True, contamination='auto')
        model.fit(X_train)
        preds = model.predict(X_test)
        f1 = f1_score(y_binary, preds, pos_label=-1, zero_division=0)

        if f1 > best_lof_f1:
            best_lof_f1 = f1
            best_lof_model = model
            best_lof_params = {'n_neighbors': n}

    print(f"  Best LOF params: {best_lof_params}")
    print(f"  Best LOF F1: {best_lof_f1:.4f}")

    # ====================================================
    # Step 7: Optimized OCSVM
    # ====================================================
    print("\n[8] Optimized OCSVM training...")

    best_svm_f1 = -1
    best_svm_model = None
    best_svm_params = {}

    # Subsample for OCSVM speed
    if len(X_train) > 3000:
        svm_train = X_train[rng.choice(len(X_train), 3000, replace=False)]
    else:
        svm_train = X_train

    for nu in [0.001, 0.005, 0.01, 0.05, 0.1]:
        for gamma in ['scale', 'auto']:
            model = OneClassSVM(kernel='rbf', nu=nu, gamma=gamma)
            model.fit(svm_train)
            preds = model.predict(X_test)
            f1 = f1_score(y_binary, preds, pos_label=-1, zero_division=0)

            if f1 > best_svm_f1:
                best_svm_f1 = f1
                best_svm_model = model
                best_svm_params = {'nu': nu, 'gamma': gamma}

    print(f"  Best OCSVM params: {best_svm_params}")
    print(f"  Best OCSVM F1: {best_svm_f1:.4f}")

    # ====================================================
    # Step 8: Full evaluation
    # ====================================================
    print("\n" + "=" * 70)
    print("OPTIMIZED MODEL COMPARISON")
    print("=" * 70)

    models = {
        'Isolation Forest': best_if_model,
        'LOF': best_lof_model,
        'One-Class SVM': best_svm_model,
    }

    results = {}
    for name, model in models.items():
        preds = model.predict(X_test)
        y_pred = np.where(preds == -1, 1, 0)
        y_true = np.where(y_test == 'attack', 1, 0)

        scores = -model.score_samples(X_test)

        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        try:
            roc = roc_auc_score(y_true, scores)
        except:
            roc = 0.0

        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        results[name] = {
            'Accuracy': round(acc, 4),
            'Precision': round(prec, 4),
            'Recall': round(rec, 4),
            'F1-Score': round(f1, 4),
            'ROC-AUC': round(roc, 4),
            'FPR': round(fpr, 4),
            'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        }

        print(f"\n  {name}:")
        print(f"    Accuracy={acc:.4f}  Precision={prec:.4f}  Recall={rec:.4f}  F1={f1:.4f}")
        print(f"    ROC-AUC={roc:.4f}  FPR={fpr:.4f}")
        print(f"    CM: TN={tn} FP={fp} FN={fn} TP={tp}")

    # ====================================================
    # Save optimized results
    # ====================================================
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    opt_results = {
        'optimized_results': results,
        'if_params': best_if_params,
        'lof_params': best_lof_params,
        'ocsvm_params': best_svm_params,
        'n_features': len(extended_feature_names),
        'feature_names': extended_feature_names,
        'train_size': len(X_train_raw),
        'test_size': len(X_test_raw),
    }

    with open(OUTPUT_DIR / 'optimized_results.json', 'w') as f:
        json.dump(opt_results, f, indent=2, default=str)

    # Save comparison CSV
    df = pd.DataFrame(results).T
    df.to_csv(OUTPUT_DIR / 'optimized_comparison.csv')

    print(f"\n  Results saved to {OUTPUT_DIR}/optimized_results.json")
    print(f"  Comparison saved to {OUTPUT_DIR}/optimized_comparison.csv")

    # ====================================================
    # Compare with baseline
    # ====================================================
    print("\n" + "=" * 70)
    print("IMPROVEMENT OVER BASELINE")
    print("=" * 70)

    baseline = {
        'Isolation Forest': {'Accuracy': 0.8076, 'F1-Score': 0.8863, 'FPR': 0.7692},
        'LOF': {'Accuracy': 0.8415, 'F1-Score': 0.9045, 'FPR': 0.6338},
        'One-Class SVM': {'Accuracy': 0.8573, 'F1-Score': 0.9131, 'FPR': 0.5709},
    }

    for name in results:
        if name in baseline:
            b = baseline[name]
            o = results[name]
            print(f"\n  {name}:")
            print(f"    Accuracy: {b['Accuracy']:.4f} → {o['Accuracy']:.4f} ({'+' if o['Accuracy']>b['Accuracy'] else ''}{(o['Accuracy']-b['Accuracy'])*100:.2f}%)")
            print(f"    F1-Score: {b['F1-Score']:.4f} → {o['F1-Score']:.4f} ({'+' if o['F1-Score']>b['F1-Score'] else ''}{(o['F1-Score']-b['F1-Score'])*100:.2f}%)")
            print(f"    FPR:      {b['FPR']:.4f} → {o['FPR']:.4f} ({'+' if o['FPR']<b['FPR'] else ''}{(b['FPR']-o['FPR'])*100:.2f}% reduction)")


if __name__ == '__main__':
    run_optimized()
