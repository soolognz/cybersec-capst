"""
Main Pipeline - Orchestrates data processing, model training, and evaluation.

Usage:
    python -m src.pipeline --mode full
    python -m src.pipeline --mode train
    python -m src.pipeline --mode evaluate
"""

import argparse
import json
import sys
import os
import numpy as np
import pandas as pd
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.data_processing.log_parser import SSHLogParser
from src.data_processing.labeler import DataLabeler
from src.data_processing.feature_extractor import FeatureExtractor, FEATURE_NAMES
from src.data_processing.data_splitter import DataSplitter
from src.data_processing.preprocessor import Preprocessor
from src.models.isolation_forest import IsolationForestModel
from src.models.lof import LOFModel
from src.models.ocsvm import OCSVMModel
from src.models.model_comparator import ModelComparator
from src.models.dynamic_threshold import DynamicThreshold


# Paths
DATASET_DIR = Path('Dataset')
MODEL_DIR = Path('trained_models')
OUTPUT_DIR = Path('output')

HONEYPOT_LOG = DATASET_DIR / 'honeypot_auth.log.log'
SIMULATION_LOG = DATASET_DIR / 'simulation_auth.log.log'


def step_1_label_data():
    """Step 1: Parse and label both log files."""
    print("=" * 60)
    print("STEP 1: Parsing and Labeling Data")
    print("=" * 60)

    labeler = DataLabeler()

    print(f"\nParsing simulation log: {SIMULATION_LOG}")
    sim_entries = labeler.label_simulation(str(SIMULATION_LOG))
    sim_stats = labeler.get_label_stats(sim_entries)
    print(f"  Total entries: {sim_stats['total']}")
    print(f"  Normal: {sim_stats['normal']} ({sim_stats['normal_pct']}%)")
    print(f"  Attack: {sim_stats['attack']} ({sim_stats['attack_pct']}%)")

    print(f"\nParsing honeypot log: {HONEYPOT_LOG}")
    hp_entries = labeler.label_honeypot(str(HONEYPOT_LOG))
    hp_stats = labeler.get_label_stats(hp_entries)
    print(f"  Total entries: {hp_stats['total']}")
    print(f"  Normal: {hp_stats['normal']} ({hp_stats['normal_pct']}%)")
    print(f"  Attack: {hp_stats['attack']} ({hp_stats['attack_pct']}%)")

    return sim_entries, hp_entries


def step_2_extract_features(sim_entries, hp_entries):
    """Step 2: Extract features from labeled entries."""
    print("\n" + "=" * 60)
    print("STEP 2: Feature Extraction (14 features per IP-window)")
    print("=" * 60)

    extractor = FeatureExtractor(window_minutes=5, stride_minutes=1)

    print("\nExtracting simulation features...")
    sim_features, sim_labels = extractor.extract_from_entries(sim_entries)
    print(f"  Feature vectors: {len(sim_features)}")
    print(f"  Features: {FEATURE_NAMES}")

    print("\nExtracting honeypot features...")
    hp_features, hp_labels = extractor.extract_from_entries(hp_entries)
    print(f"  Feature vectors: {len(hp_features)}")

    return sim_features, sim_labels, hp_features, hp_labels


def step_3_split_data(sim_features, sim_labels, hp_features, hp_labels):
    """Step 3: Split into train/test sets."""
    print("\n" + "=" * 60)
    print("STEP 3: Data Splitting (70/30 + 1:3 ratio)")
    print("=" * 60)

    splitter = DataSplitter(train_ratio=0.7)
    split_data = splitter.split(sim_features, sim_labels, hp_features, hp_labels)

    stats = splitter.get_split_stats(split_data)
    print(f"\n  Train set: {stats['train_total']} samples")
    print(f"    Normal: {stats['train_normal']}, Attack: {stats['train_attack']}")
    print(f"  Test set: {stats['test_total']} samples")
    print(f"    Normal: {stats['test_normal']}, Attack: {stats['test_attack']}")
    print(f"    Ratio: {stats['test_ratio']}")

    return split_data


def step_4_preprocess(split_data):
    """Step 4: Scale features."""
    print("\n" + "=" * 60)
    print("STEP 4: Preprocessing (RobustScaler)")
    print("=" * 60)

    preprocessor = Preprocessor(model_dir=str(MODEL_DIR))

    train_features, train_labels = split_data['train']
    test_features, test_labels = split_data['test']

    X_train = preprocessor.fit_transform(train_features)
    X_test = preprocessor.transform(test_features)

    preprocessor.save()
    print(f"  Train shape: {X_train.shape}")
    print(f"  Test shape: {X_test.shape}")
    print(f"  Scaler saved to {MODEL_DIR}/scaler.joblib")

    y_test = test_labels.values

    return X_train, X_test, y_test


def step_5_train_models(X_train, X_test, y_test):
    """Step 5: Train and tune all three models."""
    print("\n" + "=" * 60)
    print("STEP 5: Model Training & Hyperparameter Tuning")
    print("=" * 60)

    # Isolation Forest
    print("\n--- Isolation Forest (Main Model) ---")
    if_model = IsolationForestModel()
    if_model, if_tuning = if_model.tune_hyperparameters(X_train, X_test, y_test)
    print(f"  Best params: {if_tuning['best_params']}")
    print(f"  Best F1: {if_tuning['best_f1']:.4f}")
    print(f"  Training time: {if_model.training_time:.4f}s")
    if_model.save()

    # LOF
    print("\n--- Local Outlier Factor (Benchmark) ---")
    lof_model = LOFModel()
    lof_model, lof_tuning = lof_model.tune_hyperparameters(X_train, X_test, y_test)
    print(f"  Best params: {lof_tuning['best_params']}")
    print(f"  Best F1: {lof_tuning['best_f1']:.4f}")
    print(f"  Training time: {lof_model.training_time:.4f}s")
    lof_model.save()

    # One-Class SVM
    print("\n--- One-Class SVM (Benchmark) ---")
    ocsvm_model = OCSVMModel()
    ocsvm_model, ocsvm_tuning = ocsvm_model.tune_hyperparameters(X_train, X_test, y_test)
    print(f"  Best params: {ocsvm_tuning['best_params']}")
    print(f"  Best F1: {ocsvm_tuning['best_f1']:.4f}")
    print(f"  Training time: {ocsvm_model.training_time:.4f}s")
    ocsvm_model.save()

    return if_model, lof_model, ocsvm_model


def step_6_evaluate(if_model, lof_model, ocsvm_model, X_test, y_test):
    """Step 6: Comprehensive model comparison."""
    print("\n" + "=" * 60)
    print("STEP 6: Model Evaluation & Comparison")
    print("=" * 60)

    comparator = ModelComparator()

    comparator.evaluate_model('Isolation Forest', if_model, X_test, y_test)
    comparator.evaluate_model('LOF', lof_model, X_test, y_test)
    comparator.evaluate_model('One-Class SVM', ocsvm_model, X_test, y_test)

    comparator.print_comparison()

    # Save comparison table
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    table = comparator.get_comparison_table()
    table.to_csv(OUTPUT_DIR / 'model_comparison.csv')
    print(f"\nComparison table saved to {OUTPUT_DIR}/model_comparison.csv")

    return comparator


def step_7_dynamic_threshold(if_model, X_test, y_test):
    """Step 7: Evaluate dynamic threshold with IF scores."""
    print("\n" + "=" * 60)
    print("STEP 7: Dynamic Threshold Evaluation")
    print("=" * 60)

    # Get IF anomaly scores (inverted: higher = more anomalous)
    raw_scores = if_model.score_samples(X_test)
    anomaly_scores = -raw_scores

    threshold = DynamicThreshold(
        alpha=0.3,
        base_percentile=95.0,
        sensitivity_factor=1.5,
        lookback_window=100,
    )

    decisions, metrics = threshold.evaluate_batch(anomaly_scores, y_test)

    print(f"\n  Dynamic Threshold Results:")
    print(f"    Accuracy:  {metrics.get('accuracy', 0):.4f}")
    print(f"    Precision: {metrics.get('precision', 0):.4f}")
    print(f"    Recall:    {metrics.get('recall', 0):.4f}")
    print(f"    F1-Score:  {metrics.get('f1_score', 0):.4f}")
    print(f"    Early Warnings: {metrics.get('early_warnings', 0)}")
    print(f"    Alerts: {metrics.get('alerts', 0)}")
    print(f"    Normal: {metrics.get('normal', 0)}")

    # Save results
    results = {
        'metrics': {k: float(v) if isinstance(v, (np.floating, float)) else v
                    for k, v in metrics.items()},
        'threshold_state': threshold.get_state(),
    }
    with open(OUTPUT_DIR / 'dynamic_threshold_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n  Results saved to {OUTPUT_DIR}/dynamic_threshold_results.json")

    return threshold, decisions


def step_8_feature_importance(if_model, X_test, y_test):
    """Step 8: Compute and rank feature importance."""
    print("\n" + "=" * 60)
    print("STEP 8: Feature Importance Ranking")
    print("=" * 60)

    from sklearn.inspection import permutation_importance

    # Convert labels for importance
    y_binary = np.where(y_test == 'attack', -1, 1)

    # Use permutation importance
    result = permutation_importance(
        if_model.model, X_test, y_binary,
        n_repeats=10, random_state=42, scoring='accuracy'
    )

    importance_df = pd.DataFrame({
        'Feature': FEATURE_NAMES,
        'Importance_Mean': result.importances_mean,
        'Importance_Std': result.importances_std,
    }).sort_values('Importance_Mean', ascending=False)

    print("\n  Feature Importance Ranking:")
    for i, row in importance_df.iterrows():
        print(f"    {row['Feature']:30s} {row['Importance_Mean']:.4f} +/- {row['Importance_Std']:.4f}")

    importance_df.to_csv(OUTPUT_DIR / 'feature_importance.csv', index=False)
    print(f"\n  Saved to {OUTPUT_DIR}/feature_importance.csv")

    return importance_df


def run_full_pipeline():
    """Run the complete pipeline from raw logs to evaluation."""
    print("\n" + "#" * 60)
    print("# SSH BRUTE-FORCE DETECTION - FULL PIPELINE")
    print("#" * 60)

    # Ensure output dirs exist
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Step 1-4: Data pipeline
    sim_entries, hp_entries = step_1_label_data()
    sim_features, sim_labels, hp_features, hp_labels = step_2_extract_features(sim_entries, hp_entries)
    split_data = step_3_split_data(sim_features, sim_labels, hp_features, hp_labels)
    X_train, X_test, y_test = step_4_preprocess(split_data)

    # Save processed data for notebooks
    np.save(OUTPUT_DIR / 'X_train.npy', X_train)
    np.save(OUTPUT_DIR / 'X_test.npy', X_test)
    np.save(OUTPUT_DIR / 'y_test.npy', y_test)

    # Save unscaled features for analysis
    train_features, train_labels = split_data['train']
    test_features, test_labels = split_data['test']
    train_features.to_csv(OUTPUT_DIR / 'train_features.csv', index=False)
    test_features.to_csv(OUTPUT_DIR / 'test_features.csv', index=False)
    test_labels.to_csv(OUTPUT_DIR / 'test_labels.csv', index=False)

    # Step 5-6: Models
    if_model, lof_model, ocsvm_model = step_5_train_models(X_train, X_test, y_test)
    comparator = step_6_evaluate(if_model, lof_model, ocsvm_model, X_test, y_test)

    # Step 7: Dynamic threshold
    threshold, decisions = step_7_dynamic_threshold(if_model, X_test, y_test)

    # Step 8: Feature importance
    importance_df = step_8_feature_importance(if_model, X_test, y_test)

    print("\n" + "#" * 60)
    print("# PIPELINE COMPLETE")
    print("#" * 60)
    print(f"\n  Models saved to: {MODEL_DIR}/")
    print(f"  Results saved to: {OUTPUT_DIR}/")

    return {
        'comparator': comparator,
        'threshold': threshold,
        'feature_importance': importance_df,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SSH Brute-Force Detection Pipeline')
    parser.add_argument('--mode', choices=['full', 'train', 'evaluate'],
                        default='full', help='Pipeline mode')
    args = parser.parse_args()

    if args.mode == 'full':
        run_full_pipeline()
