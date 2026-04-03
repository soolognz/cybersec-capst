"""
01 - Data Exploration & Analysis
Run: python notebooks/01_data_exploration.py

Exploratory analysis of both SSH log datasets:
- honeypot_auth.log.log (real attacks from VPS)
- simulation_auth.log.log (simulated normal behavior)
"""

import sys
sys.path.insert(0, '.')

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from collections import Counter
from pathlib import Path

from src.data_processing.log_parser import SSHLogParser, EventType
from src.data_processing.labeler import DataLabeler
from src.data_processing.feature_extractor import FeatureExtractor, FEATURE_NAMES

OUTPUT = Path('output/figures')
OUTPUT.mkdir(parents=True, exist_ok=True)

# ============================================================
# Parse both datasets
# ============================================================
print("Parsing logs...")
parser = SSHLogParser()

hp_entries = list(parser.parse_file('Dataset/honeypot_auth.log.log', expand_repeats=True))
sim_entries = list(parser.parse_file('Dataset/simulation_auth.log.log', expand_repeats=True))

print(f"Honeypot entries: {len(hp_entries)}")
print(f"Simulation entries: {len(sim_entries)}")

# ============================================================
# Event type distribution
# ============================================================
hp_types = Counter(e.event_type.value for e in hp_entries)
sim_types = Counter(e.event_type.value for e in sim_entries)

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
pd.Series(hp_types).sort_values().plot.barh(ax=ax1, color='#e74c3c')
ax1.set_title('Honeypot Log - Event Type Distribution')
ax1.set_xlabel('Count')

pd.Series(sim_types).sort_values().plot.barh(ax=ax2, color='#2ecc71')
ax2.set_title('Simulation Log - Event Type Distribution')
ax2.set_xlabel('Count')

plt.tight_layout()
plt.savefig(OUTPUT / 'event_type_distribution.png', dpi=150)
plt.close()
print("Saved: event_type_distribution.png")

# ============================================================
# Source IP analysis (honeypot)
# ============================================================
hp_ips = Counter(e.source_ip for e in hp_entries if e.source_ip)
top_ips = pd.Series(dict(hp_ips.most_common(20)))

fig, ax = plt.subplots(figsize=(12, 6))
top_ips.plot.barh(ax=ax, color='#e74c3c')
ax.set_title('Top 20 Attacking IPs (Honeypot)')
ax.set_xlabel('Number of Events')
plt.tight_layout()
plt.savefig(OUTPUT / 'top_attacking_ips.png', dpi=150)
plt.close()
print("Saved: top_attacking_ips.png")

# ============================================================
# Timeline analysis
# ============================================================
hp_timestamps = [e.timestamp for e in hp_entries if e.event_type == EventType.FAILED_PASSWORD]
if hp_timestamps:
    hp_hours = pd.Series([t.hour for t in hp_timestamps])
    fig, ax = plt.subplots(figsize=(10, 5))
    hp_hours.value_counts().sort_index().plot.bar(ax=ax, color='#e74c3c')
    ax.set_title('Failed Password Attempts by Hour (Honeypot)')
    ax.set_xlabel('Hour of Day (UTC)')
    ax.set_ylabel('Count')
    plt.tight_layout()
    plt.savefig(OUTPUT / 'attack_timeline_hourly.png', dpi=150)
    plt.close()
    print("Saved: attack_timeline_hourly.png")

# ============================================================
# Feature distribution comparison
# ============================================================
print("\nExtracting features for comparison...")
labeler = DataLabeler()
sim_labeled = labeler.label_simulation('Dataset/simulation_auth.log.log')
hp_labeled = labeler.label_honeypot('Dataset/honeypot_auth.log.log')

extractor = FeatureExtractor(window_minutes=5, stride_minutes=1)
sim_features, sim_labels = extractor.extract_from_entries(sim_labeled)
hp_features, hp_labels = extractor.extract_from_entries(hp_labeled)

# Combine for comparison
sim_features_only = sim_features[FEATURE_NAMES].copy()
hp_features_only = hp_features[FEATURE_NAMES].copy()
sim_features_only['label'] = 'normal'
hp_attack = hp_features_only[hp_labels == 'attack'].copy()
hp_attack['label'] = 'attack'

combined = pd.concat([sim_features_only, hp_attack], ignore_index=True)

# Box plots for key features
key_features = ['fail_count', 'fail_rate', 'unique_usernames', 'mean_inter_attempt_time',
                'min_inter_attempt_time', 'session_duration_mean']

fig, axes = plt.subplots(2, 3, figsize=(18, 10))
for i, feat in enumerate(key_features):
    ax = axes[i // 3, i % 3]
    data_normal = combined[combined['label'] == 'normal'][feat].clip(upper=combined[feat].quantile(0.95))
    data_attack = combined[combined['label'] == 'attack'][feat].clip(upper=combined[feat].quantile(0.95))
    ax.boxplot([data_normal, data_attack], labels=['Normal', 'Attack'])
    ax.set_title(feat)

plt.suptitle('Feature Distribution: Normal vs Attack', fontsize=14)
plt.tight_layout()
plt.savefig(OUTPUT / 'feature_distribution_comparison.png', dpi=150)
plt.close()
print("Saved: feature_distribution_comparison.png")

# ============================================================
# Correlation matrix
# ============================================================
fig, ax = plt.subplots(figsize=(12, 10))
corr = sim_features[FEATURE_NAMES].corr()
sns.heatmap(corr, annot=True, fmt='.2f', cmap='RdBu_r', center=0, ax=ax)
ax.set_title('Feature Correlation Matrix (Normal Data)')
plt.tight_layout()
plt.savefig(OUTPUT / 'feature_correlation_matrix.png', dpi=150)
plt.close()
print("Saved: feature_correlation_matrix.png")

# ============================================================
# Summary statistics
# ============================================================
print("\n=== Summary Statistics ===")
print(f"\nHoneypot: {len(hp_entries)} entries, {len(hp_ips)} unique IPs")
print(f"Simulation: {len(sim_entries)} entries")
print(f"\nFeature vectors: {len(sim_features)} (simulation), {len(hp_features)} (honeypot)")
print(f"Normal: {(sim_labels == 'normal').sum() + (hp_labels == 'normal').sum()}")
print(f"Attack: {(hp_labels == 'attack').sum()}")

print("\nAll figures saved to output/figures/")
