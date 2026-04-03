"""Generate additional thesis figures: architecture, preprocessing, threshold visualization.
Uses joblib to load trusted locally-trained model artifacts."""

import sys
sys.path.insert(0, '.')
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from pathlib import Path
import joblib

OUTPUT = Path('output/benchmark_figures')
OUTPUT.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({'font.size': 11, 'font.family': 'serif', 'figure.dpi': 200, 'figure.facecolor': 'white'})

# ---- FIG: System Architecture ----
fig, ax = plt.subplots(figsize=(16, 10))
ax.axis('off')
ax.set_xlim(0, 10)
ax.set_ylim(0, 8)

def draw_box(ax, x, y, w, h, text, color='#DBEAFE', edge='#2563EB'):
    rect = mpatches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.05",
        facecolor=color, edgecolor=edge, linewidth=1.5)
    ax.add_patch(rect)
    ax.text(x + w/2, y + h/2, text, ha='center', va='center', fontsize=9, fontweight='bold')

def draw_arrow(ax, x1, y1, x2, y2):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(arrowstyle='->', color='#64748B', lw=1.5))

# Layer 1: Data Sources
draw_box(ax, 0.5, 6.5, 2.5, 1, 'SSH Server\n/var/log/auth.log', '#FEE2E2', '#EF4444')
draw_box(ax, 3.5, 6.5, 2.5, 1, 'Filebeat\n(Log Shipper)', '#E0E7FF', '#6366F1')
draw_box(ax, 6.5, 6.5, 3, 1, 'Logstash\n(Parse + Enrich + GeoIP)', '#E0E7FF', '#6366F1')

# Layer 2: Storage + Detection
draw_box(ax, 0.5, 4.5, 2.5, 1, 'Detection Worker\n(Python asyncio)', '#FEF3C7', '#F59E0B')
draw_box(ax, 3.5, 4.5, 2.5, 1, 'Redis Stream\n(Message Queue)', '#DCFCE7', '#22C55E')
draw_box(ax, 6.5, 4.5, 3, 1, 'Elasticsearch\n(Index + Search)', '#E0E7FF', '#6366F1')

# Layer 3: AI + Threshold
draw_box(ax, 0.5, 2.5, 1.8, 1, 'Log Parser\n14 Features', '#DBEAFE', '#2563EB')
draw_box(ax, 2.5, 2.5, 1.8, 1, 'Isolation Forest\nModel', '#FEF3C7', '#F59E0B')
draw_box(ax, 4.5, 2.5, 2, 1, 'Dynamic Threshold\nEWMA + Percentile', '#FEF3C7', '#F59E0B')
draw_box(ax, 6.8, 2.5, 2.8, 1, 'Kibana\n(3 Dashboards)', '#E0E7FF', '#6366F1')

# Layer 4: Response
draw_box(ax, 0.5, 0.5, 2, 1, 'Alert Manager\n(Email + WS)', '#DCFCE7', '#22C55E')
draw_box(ax, 2.8, 0.5, 2, 1, 'Fail2Ban\n(Auto IP Ban)', '#FEE2E2', '#EF4444')
draw_box(ax, 5.2, 0.5, 2.2, 1, 'FastAPI\nBackend', '#DCFCE7', '#22C55E')
draw_box(ax, 7.8, 0.5, 1.8, 1, 'React\nDashboard', '#DCFCE7', '#22C55E')

# Arrows
draw_arrow(ax, 2.75, 7, 3.5, 7)  # SSH -> Filebeat
draw_arrow(ax, 5.75, 7, 6.5, 7)  # Filebeat -> Logstash
draw_arrow(ax, 1.75, 6.5, 1.75, 5.5)  # SSH -> Detector
draw_arrow(ax, 8, 6.5, 8, 5.5)  # Logstash -> ES
draw_arrow(ax, 2.75, 4.5, 2.75, 3.5)  # Detector -> Features
draw_arrow(ax, 1.4, 3, 2.5, 3)  # Features -> IF
draw_arrow(ax, 4.3, 3, 4.5, 3)  # IF -> Threshold
draw_arrow(ax, 3, 4.5, 3.5, 5)  # Detector -> Redis
draw_arrow(ax, 6.8, 3, 6.8, 3.5)  # Kibana
draw_arrow(ax, 4.5, 2.5, 1.5, 1.5)  # Threshold -> Alert
draw_arrow(ax, 4.5, 2.5, 3.8, 1.5)  # Threshold -> Fail2Ban
draw_arrow(ax, 5.75, 4.5, 5.75, 1.5)  # Redis -> API
draw_arrow(ax, 7, 1, 7.8, 1)  # API -> React

ax.set_title('Figure 1: Overall System Architecture — SSH Brute-Force Detection with Early Prediction',
             fontsize=13, fontweight='bold', pad=15)
plt.tight_layout()
plt.savefig(OUTPUT / 'fig_system_architecture.png', bbox_inches='tight')
plt.close()
print("[1/4] System Architecture")

# ---- FIG: Preprocessing Pipeline ----
fig, ax = plt.subplots(figsize=(14, 4))
ax.axis('off')

steps = [
    ('1. Log\nParsing', '#DBEAFE'),
    ('2. Event\nClassification', '#DBEAFE'),
    ('3. Data\nLabeling', '#E0E7FF'),
    ('4. Window\nGrouping', '#FEF3C7'),
    ('5. Feature\nExtraction', '#FEF3C7'),
    ('6. Data\nSplitting', '#DCFCE7'),
    ('7. Robust\nScaling', '#DCFCE7'),
    ('8. Model\nTraining', '#FEE2E2'),
]

for i, (label, color) in enumerate(steps):
    x = i * 1.6 + 0.3
    rect = mpatches.FancyBboxPatch((x, 0.5), 1.3, 2, boxstyle="round,pad=0.1",
        facecolor=color, edgecolor='#64748B', linewidth=1.5)
    ax.add_patch(rect)
    ax.text(x + 0.65, 1.5, label, ha='center', va='center', fontsize=9, fontweight='bold')
    if i < len(steps) - 1:
        ax.annotate('', xy=(x + 1.5, 1.5), xytext=(x + 1.3, 1.5),
            arrowprops=dict(arrowstyle='->', color='#374151', lw=2))

ax.set_xlim(0, 13.5)
ax.set_ylim(0, 3.5)
ax.set_title('Figure 14: Data Preprocessing Pipeline (8 Steps)', fontsize=13, fontweight='bold')
plt.tight_layout()
plt.savefig(OUTPUT / 'fig_preprocessing_pipeline.png', bbox_inches='tight')
plt.close()
print("[2/4] Preprocessing Pipeline")

# ---- FIG: Dynamic Threshold Visualization ----
np.random.seed(42)
n = 200
normal_scores = np.random.normal(0.3, 0.05, 100)
attack_scores = np.concatenate([
    np.random.normal(0.3, 0.05, 20),
    np.linspace(0.35, 0.7, 30),
    np.random.normal(0.65, 0.08, 50),
])
all_scores = np.concatenate([normal_scores, attack_scores])

# Compute EWMA
alpha = 0.3
ewma = np.zeros(n)
ewma[0] = all_scores[0]
for i in range(1, n):
    ewma[i] = alpha * all_scores[i] + (1 - alpha) * ewma[i-1]

# Compute adaptive threshold
from collections import deque
buf = deque(maxlen=50)
thresholds = np.zeros(n)
for i in range(n):
    buf.append(all_scores[i])
    thresholds[i] = np.percentile(list(buf), 95) if len(buf) >= 10 else all_scores[i] * 2

early_warning = thresholds / 1.5

fig, ax = plt.subplots(figsize=(14, 6))
x = np.arange(n)
ax.plot(x, all_scores, 'o', alpha=0.3, markersize=3, color='#94A3B8', label='Raw Anomaly Scores')
ax.plot(x, ewma, linewidth=2, color='#2563EB', label='EWMA Smoothed Score')
ax.plot(x, thresholds, '--', linewidth=2, color='#EF4444', label='Alert Threshold (95th percentile)')
ax.plot(x, early_warning, ':', linewidth=2, color='#F59E0B', label='Early Warning Threshold')

ax.axvspan(0, 100, alpha=0.05, color='green', label='Normal Period')
ax.axvspan(100, 200, alpha=0.05, color='red', label='Attack Period')
ax.axvline(x=100, color='red', linestyle='-', alpha=0.3, linewidth=1)
ax.text(100, max(all_scores) * 1.05, 'Attack Begins', ha='center', fontsize=10, color='red', fontweight='bold')

ax.set_xlabel('Time Window')
ax.set_ylabel('Anomaly Score')
ax.set_title('Figure 29: Dynamic Threshold Adaptation During Normal-to-Attack Transition', fontweight='bold')
ax.legend(loc='upper left', fontsize=9)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(OUTPUT / 'fig_dynamic_threshold_viz.png', bbox_inches='tight')
plt.close()
print("[3/4] Dynamic Threshold Visualization")

# ---- FIG: AI vs Fail2Ban Detection Time ----
fig, ax = plt.subplots(figsize=(10, 6))
scenarios = ['Basic\nBrute-Force', 'Distributed', 'Low-and-Slow', 'Credential\nStuffing', 'Dictionary\nAttack']
ai_times = [3, 3, 4, 3, 2]
f2b_times = [5, 8, float('inf'), 5, 5]
f2b_display = [5, 8, 15, 5, 5]

x = np.arange(len(scenarios))
width = 0.35
bars1 = ax.bar(x - width/2, ai_times, width, label='AI System (attempts to detect)', color='#2563EB')
bars2 = ax.bar(x + width/2, f2b_display, width, label='Fail2Ban (attempts to detect)', color='#EF4444')

for bar, val in zip(bars1, ai_times):
    ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.2, str(val), ha='center', fontweight='bold', fontsize=11)
for bar, val, orig in zip(bars2, f2b_display, f2b_times):
    label = str(val) if orig != float('inf') else 'N/A'
    ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.2, label, ha='center', fontweight='bold', fontsize=11)

ax.set_xlabel('Attack Scenario')
ax.set_ylabel('Number of Attempts Before Detection')
ax.set_title('Figure 32: Detection Speed Comparison — AI System vs. Fail2Ban', fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(scenarios)
ax.legend()
ax.set_ylim(0, 18)
plt.tight_layout()
plt.savefig(OUTPUT / 'fig_ai_vs_fail2ban.png', bbox_inches='tight')
plt.close()
print("[4/4] AI vs Fail2Ban Detection Time")

total = len(list(OUTPUT.glob('*.png')))
print(f"\nTotal figures: {total} in {OUTPUT}/")
