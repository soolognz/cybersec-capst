"""
Data Splitter - Splits labeled data into train/test sets.

Strategy:
- Train: 70% of simulation features (chronological, normal-only)
- Test: 30% simulation (normal) + honeypot attack data, ratio normal:attack = 1:3
"""

import numpy as np
import pandas as pd
from typing import Tuple, Dict
from .feature_extractor import FEATURE_NAMES


class DataSplitter:
    """Split feature data into train and test sets."""

    def __init__(self, train_ratio: float = 0.7, test_normal_attack_ratio: float = 1/3):
        """
        Args:
            train_ratio: Fraction of simulation data for training
            test_normal_attack_ratio: Desired ratio of normal:attack in test set
        """
        self.train_ratio = train_ratio
        self.target_ratio = test_normal_attack_ratio

    def split(
        self,
        sim_features: pd.DataFrame,
        sim_labels: pd.Series,
        hp_features: pd.DataFrame,
        hp_labels: pd.Series,
    ) -> Dict[str, Tuple[pd.DataFrame, pd.Series]]:
        """Split data into train and test sets.

        Args:
            sim_features: Features from simulation log (all normal)
            sim_labels: Labels from simulation log
            hp_features: Features from honeypot log (mixed)
            hp_labels: Labels from honeypot log

        Returns:
            dict with 'train' and 'test' keys, each containing (features, labels) tuple
        """
        # Chronological split of simulation data (already ordered by time)
        n_sim = len(sim_features)
        split_idx = int(n_sim * self.train_ratio)

        # Feature columns only (exclude metadata)
        feature_cols = FEATURE_NAMES

        # Train set: first 70% of simulation (normal only)
        train_features = sim_features.iloc[:split_idx][feature_cols].copy()
        train_labels = sim_labels.iloc[:split_idx].copy()

        # Test normal: remaining 30% of simulation
        test_normal_features = sim_features.iloc[split_idx:][feature_cols].copy()
        test_normal_labels = sim_labels.iloc[split_idx:].copy()

        # Honeypot data split by label
        hp_normal_mask = hp_labels == 'normal'
        hp_attack_mask = hp_labels == 'attack'

        hp_normal_features = hp_features[hp_normal_mask][feature_cols].copy()
        hp_normal_labels = hp_labels[hp_normal_mask].copy()
        hp_attack_features = hp_features[hp_attack_mask][feature_cols].copy()
        hp_attack_labels = hp_labels[hp_attack_mask].copy()

        # Combine test normal: simulation test + honeypot normal
        all_test_normal_features = pd.concat(
            [test_normal_features, hp_normal_features], ignore_index=True
        )
        all_test_normal_labels = pd.concat(
            [test_normal_labels, hp_normal_labels], ignore_index=True
        )

        n_test_normal = len(all_test_normal_features)

        # Sample attack data to achieve 1:3 ratio
        n_attack_target = int(n_test_normal * 3)

        if len(hp_attack_features) >= n_attack_target:
            # Randomly sample attack data
            attack_sample_idx = np.random.RandomState(42).choice(
                len(hp_attack_features), size=n_attack_target, replace=False
            )
            test_attack_features = hp_attack_features.iloc[attack_sample_idx].copy()
            test_attack_labels = hp_attack_labels.iloc[attack_sample_idx].copy()
        else:
            # Use all available attack data
            test_attack_features = hp_attack_features.copy()
            test_attack_labels = hp_attack_labels.copy()
            n_attack_target = len(test_attack_features)

        # Combine test set
        test_features = pd.concat(
            [all_test_normal_features, test_attack_features], ignore_index=True
        )
        test_labels = pd.concat(
            [all_test_normal_labels, test_attack_labels], ignore_index=True
        )

        # Shuffle test set
        shuffle_idx = np.random.RandomState(42).permutation(len(test_features))
        test_features = test_features.iloc[shuffle_idx].reset_index(drop=True)
        test_labels = test_labels.iloc[shuffle_idx].reset_index(drop=True)

        result = {
            'train': (train_features, train_labels),
            'test': (test_features, test_labels),
        }

        # Print split statistics
        stats = self.get_split_stats(result)
        return result

    def get_split_stats(self, split_data: dict) -> dict:
        """Get statistics about the data split."""
        train_features, train_labels = split_data['train']
        test_features, test_labels = split_data['test']

        stats = {
            'train_total': len(train_features),
            'train_normal': int((train_labels == 'normal').sum()),
            'train_attack': int((train_labels == 'attack').sum()),
            'test_total': len(test_features),
            'test_normal': int((test_labels == 'normal').sum()),
            'test_attack': int((test_labels == 'attack').sum()),
            'test_ratio': f"1:{(test_labels == 'attack').sum() / max((test_labels == 'normal').sum(), 1):.1f}",
        }
        return stats
