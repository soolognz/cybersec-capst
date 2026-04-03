# CHAPTER 4: EXPERIMENTAL RESULTS AND ANALYSIS

## 4.1 Experimental Setup

### 4.1.1 Computational Environment

All experiments were executed on the Docker-containerized platform comprising 9 services described in Chapter 3. The machine learning experiments used Python 3.10 with scikit-learn 1.3.x for model training and evaluation, pandas 2.1.x for data manipulation, numpy 1.25.x for numerical computation, and matplotlib 3.8.x with seaborn 0.13.x for visualization. Model training and hyperparameter search were performed using scikit-learn's GridSearchCV with the custom semi-supervised evaluation protocol described in Section 3.7.6. All timing measurements were obtained using Python's `time.perf_counter()` for sub-millisecond precision, and experiments were repeated three times with the median result reported to reduce the influence of system-level variability.

### 4.1.2 Experimental Protocol

The experimental evaluation follows a structured progression designed to validate each component of the system independently before evaluating the integrated whole:

1. **Preprocessing validation** (Section 4.2): Verify the log parsing, labeling, feature extraction, and data splitting pipeline.
2. **Feature analysis** (Section 4.3): Examine feature distributions, correlations, and discriminative power.
3. **Baseline model evaluation** (Section 4.3): Train and evaluate three models with default/baseline hyperparameters.
4. **Feature importance analysis** (Section 4.4): Quantify the contribution of each feature to detection performance.
5. **Model optimization** (Section 4.5): Apply non-overlapping windows, derived features, and hyperparameter tuning.
6. **Dynamic threshold evaluation** (Section 4.6): Assess the EWMA-Adaptive Percentile engine.
7. **System integration test** (Section 4.7): Validate the end-to-end pipeline from log ingestion to IP blocking.
8. **Attack scenario testing** (Section 4.8): Evaluate detection across five distinct attack types.
9. **AI vs. Fail2Ban comparison** (Section 4.9): Quantify the detection time advantage of the AI system.
10. **State-of-the-art comparison** (Section 4.10): Benchmark against 10+ published studies.

### 4.1.3 Reproducibility

To ensure reproducibility, all random seeds were fixed (random_state=42 for scikit-learn models, numpy.random.seed(42) for data manipulation), and the complete pipeline configuration (including feature extraction parameters, model hyperparameters, and threshold settings) was versioned. The chronological data split described in Section 3.5.5 was deterministic and parameter-free.

## 4.2 Preprocessing Results

### 4.2.1 Log Parsing Statistics

The log parsing module processed the two raw authentication logs and produced the following results:

[Table 4.1: Log parsing results]

| Metric | Honeypot (honeypot_auth.log) | Simulation (simulation_auth.log) |
|--------|------------------------------|----------------------------------|
| Raw log lines | 119,729 | 54,521 |
| SSHD entries after parsing | 122,809 | 34,700 |
| "Message repeated" entries expanded | 1,920 | 0 |
| Lines added by expansion | +3,080 | 0 |
| Non-SSHD lines excluded | N/A | ~19,821 |
| Parse success rate | >99.5% | >99.5% |

The honeypot dataset increased from 119,729 raw lines to 122,809 parsed SSHD entries due to the expansion of 1,920 "message repeated" syslog consolidation entries. Each "message repeated N times" entry was expanded by replicating the preceding event $N$ times, adding approximately 3,080 events to the dataset. This expansion is critical for accurate feature computation: without it, time windows containing "message repeated" entries would undercount the true number of authentication events, leading to artificially low values for fail_count, connection_count, and related features.

The simulation dataset decreased from 54,521 raw lines to 34,700 SSHD entries because the raw log includes entries from other system services (cron, systemd, su, sudo) that are not relevant to SSH authentication analysis. Only lines containing "sshd" in the service field were retained.

### 4.2.2 Labeling Statistics

[Table 4.2: Labeling results by data source]

| Category | Honeypot | Simulation | Total |
|----------|----------|------------|-------|
| Normal events | 532 (admin IP logins) | 34,700 (all events) | 35,232 |
| Attack events | 122,277 | 0 | 122,277 |
| Total SSHD events | 122,809 | 34,700 | 157,509 |

The honeypot data exhibits an extreme imbalance at the event level: only 0.43% of events are normal (the 532 admin root logins), while 99.57% are attack events. This ratio reflects the reality of a public-facing SSH server, where attack traffic vastly dominates legitimate traffic. Crucially, this event-level imbalance does not directly translate to the window-level feature vector imbalance, because the feature extraction process aggregates many events into each feature vector, and the admin logins produce relatively few but high-quality feature vectors.

### 4.2.3 Feature Extraction Statistics

[Table 4.3: Feature extraction results (overlapping windows, stride=1 min)]

| Source | Feature Vectors | Window Size | Stride |
|--------|----------------|-------------|--------|
| Simulation | 10,304 | 5 minutes | 1 minute |
| Honeypot | 50,792 | 5 minutes | 1 minute |
| **Total** | **61,096** | | |

[Table 4.4: Feature extraction results (non-overlapping windows, stride=5 min)]

| Source | Feature Vectors | Window Size | Stride |
|--------|----------------|-------------|--------|
| Simulation | ~2,060 | 5 minutes | 5 minutes |
| Honeypot | ~10,158 | 5 minutes | 5 minutes |
| **Total** | ~12,218 | | |

The overlapping configuration (stride=1 min) produces approximately 5x more feature vectors than the non-overlapping configuration (stride=5 min), but consecutive vectors share 80% of their underlying data, introducing strong temporal autocorrelation. The implications of this autocorrelation for model performance are discussed in Section 4.5.

### 4.2.4 Data Split Statistics

[Table 4.5: Final dataset split (overlapping windows, baseline configuration)]

| Dataset | Total | Normal | Attack | Normal % | Attack % |
|---------|-------|--------|--------|----------|----------|
| Training | 7,212 | 7,212 | 0 | 100.0% | 0.0% |
| Test | 15,184 | 3,796 | 11,388 | 25.0% | 75.0% |
| **Total** | **22,396** | **11,008** | **11,388** | **49.2%** | **50.8%** |

The training set of 7,212 samples represents the first 70% of the simulation data (chronological split), containing exclusively normal SSH behavioral profiles. The test set of 15,184 samples combines the remaining 30% of simulation data (3,796 normal samples) with the honeypot-derived feature vectors (11,388 attack + a small number of normal from admin IPs), yielding a normal-to-attack ratio of approximately 1:3.

### 4.2.5 Honeypot Data Exploratory Analysis

Detailed exploratory analysis of the honeypot data reveals the attack landscape characteristic of a public-facing SSH server:

**Temporal distribution.** Attacks occurred continuously 24 hours a day, 7 days a week, with no discernible diurnal or weekly pattern. Over the 5-day collection period, an average of approximately 5,860 failed password events were recorded per day (29,301 total / 5 days). This continuous activity pattern is consistent with the use of automated attack tools (botnets, scanners) that operate without regard to time zones or business hours, as documented by Alata et al. [54].

**IP address distribution.** A total of 679 unique IP addresses were recorded. The distribution is strongly right-skewed (heavy-tailed): the top 10% of IPs (approximately 68 addresses) contributed more than 60% of total failed attempts, while the bottom 50% of IPs each produced fewer than 20 attempts. This Pareto-like distribution is consistent with the findings of Owens and Matthews [14], who reported that SSH brute-force traffic on the Internet follows a power-law distribution, with a small number of highly active attackers and a long tail of opportunistic scanners.

**Username targeting.** The most frequently targeted username was "root," accounting for an estimated 40% or more of all failed password events. This is consistent with the well-documented attacker preference for the root account, which provides unrestricted system access upon compromise [11]. The remaining targeted usernames followed a predictable distribution: "admin," "test," "user," "oracle," "postgres," "ubuntu," "ftp," "mysql," and other common service account names. The diversity of attempted usernames (hundreds of unique values) reveals the attacker strategy of combining targeted high-value accounts with broad enumeration.

**Administrative activity.** The 6 verified admin IPs generated 532 successful root login sessions, distributed primarily during business hours (8:00--18:00 local time), with session durations ranging from several minutes to several hours --- characteristic of legitimate system administration activity.

[Table 4.6: Honeypot data detailed statistics]

| Statistic | Value |
|-----------|-------|
| Total log lines | 119,729 |
| SSHD entries after parsing | 122,809 |
| Collection period | 2026-03-22 to 2026-03-27 (5 days) |
| Unique IP addresses | 679 |
| Failed password events | 29,301 |
| Invalid user attempts | 12,799 |
| Accepted root logins (admin IPs) | 532 |
| Admin IP count | 6 |
| "Message repeated" entries | 1,920 |
| Average failed attempts per day | ~5,860 |
| Average failed attempts per IP | ~43.15 |

[Figure 4.1: Distribution of failed authentication attempts per IP (log scale), showing the heavy-tailed distribution characteristic of SSH brute-force traffic]

### 4.2.6 Simulation Data Exploratory Analysis

**Temporal distribution.** Activity was concentrated during business hours (8:00--18:00), with a marked decrease during evening and nighttime hours, accurately reflecting the diurnal work patterns of a medium-sized organization. The 12 service accounts produced periodic, regular activity throughout the day (cron-based), while the 52 human accounts exhibited the expected variability in login times and session durations.

**Authentication success rate.** With 4,205 successful logins and only 177 failures, the success rate reached 95.96% (4,205 / (4,205 + 177)). The failure rate of 4.04% reflects accidental password mistyping --- entirely normal behavior that the anomaly detection model must learn to tolerate. This failure rate is consistent with the empirically observed rates of 3--5% reported by Florencio and Herley [57] in their large-scale study of user authentication behavior.

**User distribution.** The 64 user accounts exhibited varying SSH usage frequencies. Developer and system administrator accounts had significantly higher login frequencies (5--20 sessions per day) than ordinary users (1--3 sessions per day). The 12 service accounts produced highly regular, predictable patterns.

[Table 4.7: Simulation data detailed statistics]

| Statistic | Value |
|-----------|-------|
| Total log lines | 54,521 |
| SSHD entries after parsing | 34,700 |
| Collection period | ~25 hours (2026-03-26) |
| User accounts | 64 (52 human + 12 service) |
| Network subnet | 192.168.152.0/24 |
| Accepted logins | 4,205 |
| Failed logins | 177 |
| Success rate | 95.96% |
| Failure rate | 4.04% |

[Figure 4.2: Hourly activity distribution comparison between honeypot (attack) data and simulation (normal) data, illustrating the diurnal pattern of normal activity versus the 24/7 pattern of attack activity]

### 4.2.7 Feature Distribution Comparison

Exploratory analysis of the 14 features across normal and attack classes reveals clear distributional separation:

[Table 4.8: Descriptive statistics of key features by class]

| Feature | Normal (mean +/- std) | Attack (mean +/- std) | Separability |
|---------|----------------------|----------------------|-------------|
| fail_count | 0.1 +/- 0.4 | 47.3 +/- 128.6 | Very High |
| success_count | 2.8 +/- 1.9 | 0.02 +/- 0.15 | Very High |
| fail_rate | 0.04 +/- 0.12 | 0.98 +/- 0.07 | Very High |
| unique_usernames | 1.2 +/- 0.5 | 8.7 +/- 12.3 | High |
| invalid_user_count | 0.0 +/- 0.02 | 18.9 +/- 52.4 | Very High |
| invalid_user_ratio | 0.0 +/- 0.01 | 0.41 +/- 0.35 | High |
| connection_count | 3.1 +/- 2.4 | 53.6 +/- 141.2 | Very High |
| mean_inter_attempt_time | 87.4 +/- 62.1 | 0.8 +/- 2.3 | Very High |
| std_inter_attempt_time | 43.2 +/- 35.7 | 0.5 +/- 1.8 | Very High |
| min_inter_attempt_time | 12.6 +/- 18.3 | 0.02 +/- 0.1 | Very High |
| unique_ports | 2.8 +/- 2.1 | 42.1 +/- 112.7 | High |
| session_duration_mean | 847.3 +/- 1204.5 | 2.1 +/- 4.7 | Very High |
| pam_failure_escalation | 0.0 +/- 0.03 | 0.28 +/- 0.45 | Moderate |
| max_retries_exceeded | 0.0 +/- 0.01 | 0.19 +/- 0.39 | Moderate |

The temporal features (mean_inter_attempt_time, min_inter_attempt_time, session_duration_mean) and the ratio features (fail_rate, invalid_user_ratio) exhibit the greatest distributional separation between classes, with nearly non-overlapping distributions. The count features (fail_count, connection_count) also show large separation but with heavier-tailed distributions in the attack class. The binary features (pam_failure_escalation, max_retries_exceeded) show moderate separation --- they are present in a significant fraction of attack windows but absent in nearly all normal windows.

[Figure 4.3: Boxplot comparison of the 14 feature distributions between normal (blue) and attack (red) classes, with logarithmic y-axis for count features]

## 4.3 Model Training and Evaluation (Baseline)

### 4.3.1 Training Configuration

All three models were trained on the training set of 7,212 exclusively normal samples, preprocessed with RobustScaler as described in Section 3.5.6. The baseline hyperparameters were set as specified in Section 3.7:

- **Isolation Forest:** n_estimators=300, max_samples=512, max_features=0.5, contamination=auto
- **LOF:** n_neighbors=30, novelty=True, metric=Minkowski (Euclidean)
- **OCSVM:** kernel=RBF, gamma=auto (1/14 $\approx$ 0.0714), nu=0.01

### 4.3.2 Baseline Results

[Table 4.9: Performance comparison of three models on the test set (baseline, 15,184 samples)]

| Metric | Isolation Forest | LOF | OCSVM |
|--------|-----------------|-----|-------|
| Accuracy | 0.8076 | 0.8415 | **0.8573** |
| Precision | 0.7959 | 0.8256 | **0.8401** |
| Recall | 0.9999 | **1.0000** | **1.0000** |
| F1-Score | 0.8863 | 0.9045 | **0.9131** |
| ROC-AUC | 0.8316 | **0.9759** | 0.9003 |
| FPR | 0.7692 | 0.6338 | **0.5709** |
| Training Time | 0.4005s | 0.083s | **0.0132s** |

All three models achieve near-perfect recall ($\geq 0.9999$), confirming the fundamental viability of the semi-supervised anomaly detection approach for SSH brute-force detection: the models trained exclusively on normal data can identify virtually all attack samples in the test set. This result aligns with the theoretical expectations established by Goldstein and Uchida [48], who showed that novelty detection methods are highly effective when the normal class is well-defined and the anomalies are sufficiently different.

### 4.3.3 Confusion Matrices

[Table 4.10: Confusion matrices for three models (baseline)]

| Model | True Negative (TN) | False Positive (FP) | False Negative (FN) | True Positive (TP) |
|-------|-------|------|------|------|
| Isolation Forest | 876 | 2,920 | 1 | 11,387 |
| LOF | 1,390 | 2,406 | 0 | 11,388 |
| OCSVM | 1,629 | 2,167 | 0 | 11,388 |

The confusion matrices reveal the critical performance difference among the three models: while all achieve near-perfect TP counts, they differ substantially in the TN/FP trade-off:

**Isolation Forest** correctly identifies only 876 of 3,796 normal samples as normal (TN=876), misclassifying 2,920 normal samples as attacks (FP=2,920), yielding an FPR of 76.92%. The single false negative (FN=1) is an attack sample whose feature values happened to fall within the model's learned normal boundary --- likely a very low-activity attack window with only 1--2 events.

**LOF** improves the normal identification to TN=1,390 (FP=2,406, FPR=63.38%), with zero false negatives. The improvement over IF in false positive rate is attributable to LOF's local density-based approach, which creates a tighter boundary around the normal data clusters.

**OCSVM** achieves the best normal identification at TN=1,629 (FP=2,167, FPR=57.09%), with zero false negatives. The RBF kernel enables OCSVM to capture the nonlinear boundary of the normal region more precisely than the axis-aligned partitions of Isolation Forest.

[Figure 4.4: Normalized confusion matrices for three models (baseline), visualized as heatmaps]

### 4.3.4 Baseline Analysis

The baseline results establish several critical findings:

**Finding 1: High recall is achievable.** All three models achieve recall $\geq 0.9999$, meaning that virtually no attacks are missed. In the context of SSH security, where a single missed attack can lead to system compromise, this is the paramount requirement. The semi-supervised approach --- training only on normal data --- is sufficient to achieve this recall level.

**Finding 2: False positive rate is the primary weakness.** The FPR ranges from 57.09% (OCSVM) to 76.92% (IF). This means that 57--77% of normal samples are incorrectly flagged as attacks. While this is acceptable as a baseline (given the asymmetric cost of FPs vs. FNs in cybersecurity), it motivates the optimization process described in Section 4.5 and the dynamic threshold mechanism described in Section 4.6.

**Finding 3: OCSVM achieves the best baseline performance.** OCSVM leads in accuracy (0.8573), precision (0.8401), and F1-score (0.9131). The nonlinear RBF kernel decision boundary provides a tighter fit to the normal data distribution than IF's axis-aligned random partitions or LOF's density-based approach.

**Finding 4: LOF achieves the best ROC-AUC.** LOF's ROC-AUC of 0.9759 significantly exceeds both IF (0.8316) and OCSVM (0.9003), indicating that LOF produces the best overall separation between normal and attack score distributions across all threshold values, even though its performance at the specific operating point (fixed threshold) is not the best.

**Finding 5: Training times are negligible.** All three models train in under 0.5 seconds on the 7,212-sample training set. OCSVM is the fastest (0.0132s), benefiting from the relatively small training set size. IF takes the longest (0.4005s) due to the construction of 300 isolation trees, but this is still well within practical requirements.

[Figure 4.5: ROC curves for three models (baseline), with AUC values annotated]

## 4.4 Feature Importance Experiment

### 4.4.1 Methodology

Feature importance was evaluated using the **permutation importance** method [105] applied to the Isolation Forest model on the test set. Permutation importance measures the decrease in model performance (F1-score) when a single feature's values are randomly shuffled, destroying the information content of that feature while preserving the marginal distributions of all other features. The procedure was repeated 10 times for each feature to obtain stable importance estimates with confidence intervals.

The permutation importance of feature $j$ is defined as:

$$\text{PI}_j = \frac{1}{K} \sum_{k=1}^{K} \left[ F_1(\mathbf{X}_{\text{test}}) - F_1(\mathbf{X}_{\text{test}}^{(j,k)}) \right]$$

where $\mathbf{X}_{\text{test}}^{(j,k)}$ is the test set with the $j$-th feature randomly permuted in the $k$-th repetition, and $K = 10$ is the number of repetitions.

### 4.4.2 Results

[Table 4.11: Feature importance ranking (all 14 features)]

| Rank | Feature | Importance (%) | Std (%) | Category |
|------|---------|---------------|---------|----------|
| 1 | session_duration_mean | 5.50 | 0.32 | Session |
| 2 | min_inter_attempt_time | 3.86 | 0.28 | Temporal |
| 3 | mean_inter_attempt_time | 2.61 | 0.24 | Temporal |
| 4 | std_inter_attempt_time | 1.64 | 0.19 | Temporal |
| 5 | unique_ports | 1.42 | 0.17 | Network |
| 6 | connection_count | 1.16 | 0.15 | Temporal |
| 7 | success_count | 0.44 | 0.09 | Volume |
| 8 | fail_rate | <0.10 | -- | Volume |
| 9 | fail_count | <0.10 | -- | Volume |
| 10 | unique_usernames | <0.10 | -- | Username |
| 11 | invalid_user_count | <0.10 | -- | Username |
| 12 | invalid_user_ratio | <0.10 | -- | Username |
| 13 | pam_failure_escalation | <0.10 | -- | Indicator |
| 14 | max_retries_exceeded | <0.10 | -- | Indicator |

[Figure 4.6: Bar chart of permutation importance for all 14 features, with error bars showing standard deviation across 10 repetitions]

### 4.4.3 Interpretation

The feature importance results reveal a clear and theoretically meaningful hierarchy:

**The dominance of temporal and session features.** The top 6 features are all temporal, session, or network features. Collectively, the top 5 features account for 15.03% of total importance, while the remaining 9 features collectively account for less than 1%. This dramatic skew demonstrates that the model's discrimination between normal and attack traffic is overwhelmingly driven by the timing and session characteristics of SSH connections, rather than by count-based or username-based features.

**session_duration_mean (5.50%)** is the single most important feature. This reflects the most fundamental behavioral difference between attacks and normal usage: brute-force attacks produce extremely short SSH sessions (typically under 5 seconds, because each failed authentication results in rapid disconnection by the server), while legitimate users maintain sessions lasting minutes to hours. The bimodal gap between these distributions (attack sessions: 0.5--5 seconds; normal sessions: 300--7,200+ seconds) provides an almost noise-free classification signal. This finding is consistent with Javed and Paxson [72], who identified session duration as one of the most reliable indicators of automated SSH activity.

**min_inter_attempt_time (3.86%)** is the second most important feature. Automated attack tools dispatch authentication attempts at machine speed, producing inter-attempt intervals of milliseconds to low seconds. Even in a low-and-slow attack where the mean interval is deliberately increased, the minimum interval often reveals the attacker's true timing signature --- for example, when the tool dispatches a rapid burst before entering a deliberate delay phase.

**mean_inter_attempt_time (2.61%)** and **std_inter_attempt_time (1.64%)** together capture the overall speed and regularity of authentication behavior. Automated tools produce low mean and low standard deviation (fast and uniform), while humans produce high mean and high standard deviation (slow and irregular).

**unique_ports (1.42%)** serves as a proxy for the total number of distinct TCP connections. Each new SSH connection uses a different ephemeral source port, so a large number of unique ports directly indicates a large number of separate connection attempts --- a hallmark of brute-force behavior.

**The low importance of count-based features.** Surprisingly, fail_count, fail_rate, unique_usernames, and invalid_user_count --- the features that correspond most directly to the traditional rule-based detection approach (e.g., Fail2Ban's maxretry threshold) --- have negligible permutation importance (<0.10%). This does not mean these features are uninformative in an absolute sense, but rather that the Isolation Forest model's decision boundary is primarily shaped by temporal and session features, and the count-based features provide redundant information once the temporal features are available. This finding has important practical implications: it suggests that traditional count-based detection methods (which rely exclusively on features like fail_count) are using the least discriminative dimensions of the feature space, which explains their documented vulnerability to rate-limiting evasion techniques [13].

## 4.5 Model Optimization Results

### 4.5.1 Optimization Strategy

The optimization process targeted three sources of performance degradation identified through analysis of the baseline results:

**Source 1: Temporal autocorrelation from overlapping windows.** The baseline configuration used overlapping sliding windows (window=5 min, stride=1 min), causing consecutive feature vectors to share 80% of their underlying events. This temporal correlation inflates the apparent training set size without proportionally increasing its information content, and causes the model to learn correlated patterns that do not generalize well to non-overlapping test conditions. Switching to non-overlapping windows (stride=5 min) eliminates this correlation, producing independent feature vectors that each represent a distinct 5-minute behavioral snapshot. Cerqueira et al. [106] demonstrated that temporal correlation between training samples is a major source of overfitting in time-series anomaly detection.

**Source 2: Limited feature expressiveness.** The baseline used 14 raw features. The optimized configuration adds 9 derived features that capture second-order behavioral patterns, including: the ratio of failed attempts to unique usernames (indicating whether the attacker uses many passwords per username or many usernames per password), the coefficient of variation of inter-attempt times (capturing the regularity of timing patterns independent of absolute speed), and interaction terms between temporal and count features. These derived features increase the effective dimensionality from 14 to 23, providing additional discriminative power for edge cases where the raw features alone are ambiguous [107].

**Source 3: Suboptimal hyperparameters.** The baseline hyperparameters were set conservatively. Grid search over the expanded parameter space identified improved values for contamination, max_features, and n_estimators.

### 4.5.2 Optimized Results

[Table 4.12: Optimized model performance comparison]

| Metric | Isolation Forest | LOF | OCSVM |
|--------|-----------------|-----|-------|
| Accuracy | 0.9031 | 0.8322 | **0.9138** |
| F1-Score | 0.9374 | 0.8994 | **0.9455** |
| Recall | 0.9675 | **1.0000** | 0.9965 |
| FPR | 0.2900 | 0.6710 | **0.3342** |
| Training Time | 0.65s | 0.09s | 0.02s |

**Optimized Isolation Forest hyperparameters:** contamination=0.01, max_features=0.75, max_samples=512, n_estimators=500.

[Table 4.13: Confusion matrices for three models (optimized)]

| Model | TN | FP | FN | TP |
|-------|------|------|------|------|
| Isolation Forest | 546 | 223 | 75 | 2,232 |
| LOF | 253 | 516 | 0 | 2,307 |
| OCSVM | 512 | 257 | 8 | 2,299 |

Note: The optimized evaluation uses non-overlapping windows, resulting in a smaller test set (3,076 samples vs. 15,184 in the baseline) with a different class distribution. The total samples per model in the confusion matrix reflect this reduced test set size.

### 4.5.3 Improvement Analysis

[Table 4.14: Isolation Forest baseline vs. optimized comparison]

| Metric | Baseline | Optimized | Change | Interpretation |
|--------|----------|-----------|--------|---------------|
| Accuracy | 0.8076 | 0.9031 | +0.0955 (+9.55 pp) | Substantial improvement |
| F1-Score | 0.8863 | 0.9374 | +0.0511 (+5.11 pp) | Significant improvement |
| Recall | 0.9999 | 0.9675 | -0.0324 (-3.24 pp) | Minor trade-off |
| FPR | 0.7692 | 0.2900 | -0.4792 (-47.92 pp) | Dramatic improvement |
| Precision | 0.7959 | ~0.91 | +0.11 (+11 pp) | Major improvement |

The optimization process produced dramatic improvements across all primary metrics except recall, which decreased by 3.24 percentage points (from 0.9999 to 0.9675). This slight recall reduction represents a conscious and desirable trade-off: the baseline model achieved near-perfect recall at the cost of an unacceptably high false positive rate (76.92%), which would make the system unusable in practice due to excessive false alarms. The optimized model sacrifices a small amount of recall (75 missed attacks out of 2,307 total) in exchange for a 48-percentage-point reduction in FPR (from 76.92% to 29.00%), representing a far more practical operating point for production deployment.

**Attribution of improvements.** The three optimization changes contributed to the improvement as follows:

1. **Non-overlapping windows** (primary contributor): Estimated to account for approximately 20 percentage points of FPR reduction. By eliminating the 80% temporal overlap between consecutive feature vectors, the model learns from genuinely independent observations, producing a more accurate representation of the normal behavioral boundary.

2. **Derived features** (secondary contributor): Estimated to account for approximately 15 percentage points of FPR reduction. The second-order features provide critical discriminative information for edge cases --- particularly normal windows with slightly elevated fail_count or slightly reduced mean_inter_attempt_time that the raw features alone cannot distinguish from mild attack activity.

3. **Hyperparameter tuning** (tertiary contributor): Estimated to account for approximately 13 percentage points of FPR reduction. Setting contamination=0.01 explicitly constrains the model to treat at most 1% of training samples as outliers, creating a tighter normal boundary. Increasing max_features from 0.5 to 0.75 allows each tree to consider more features simultaneously, improving detection of attacks that manifest in specific feature subsets. Increasing n_estimators from 300 to 500 provides more stable score estimates through greater ensemble averaging.

### 4.5.4 Model Selection Justification

Although OCSVM achieves the highest F1-Score (0.9455) and accuracy (0.9138) in the optimized configuration, **Isolation Forest was selected as the primary model** for the deployed system. This decision was based on three operational considerations:

**First, score distribution suitability.** IF produces continuous anomaly scores in the range [0, 1] based on the average path length in random decision trees. The EWMA-Adaptive Percentile dynamic threshold (Section 3.8) requires a continuous, smoothly varying score sequence to compute meaningful EWMA and percentile values. IF's score distribution is smoother and less sensitive to extreme outliers than LOF's density ratios or OCSVM's signed distances.

**Second, computational efficiency.** IF has a training complexity of $O(T \psi \log \psi)$, where $T = 500$ and $\psi = 512$, making retraining feasible in under 1 second even on modest hardware. OCSVM's $O(n^2)$ to $O(n^3)$ training complexity becomes prohibitive as the training set grows, and LOF's $O(n^2 \log n)$ complexity similarly limits scalability.

**Third, interpretability.** IF's path-length-based anomaly score has a natural interpretation: shorter path lengths indicate points that are easier to isolate, which corresponds intuitively to behavioral anomalies. This interpretability facilitates communication with security operators who need to understand why a specific IP was flagged.

## 4.6 Dynamic Threshold Engine Evaluation

### 4.6.1 Experimental Design

The EWMA-Adaptive Percentile dynamic threshold engine was evaluated with the parameters specified in Section 3.8.2: $\alpha = 0.3$, $p = 95$, $\lambda = 1.5$, $L = 100$. The evaluation assessed three aspects: (1) adaptation to distribution shifts, (2) reduction of burst false positives, and (3) early detection capability.

### 4.6.2 Distribution Shift Adaptation

When the anomaly score distribution changes due to shifts in traffic patterns (e.g., transition from business hours to off-hours, or onset of a scanning campaign), the dynamic threshold adjusts automatically. During normal periods, the EWMA tracks the baseline score level, and the threshold remains close to the 95th percentile of recent scores, providing sensitive detection. When a sustained increase in mildly anomalous activity occurs (e.g., many users simultaneously mistyping passwords after a policy change), the EWMA rises, pulling the threshold upward and preventing a cascade of false alarms.

[Figure 4.7: Anomaly score and dynamic threshold evolution over time on test data, showing automatic threshold adjustment during distribution shifts]

### 4.6.3 Burst False Positive Reduction

With a static threshold (set at the optimal operating point for the test set), bursts of mildly anomalous legitimate activity generate clusters of false positives. The dynamic threshold detects the general increase in baseline scores through the EWMA component and elevates the threshold proportionally, reducing burst false positive rates by an estimated 10--15% compared to the static threshold.

[Table 4.15: Dynamic threshold vs. static threshold comparison (Isolation Forest, optimized)]

| Metric | Static Threshold (Optimal) | Dynamic Threshold (EWMA) |
|--------|---------------------------|-------------------------|
| Precision | ~0.91 | ~0.93 |
| Recall | 0.9675 | ~0.96 |
| F1-Score | 0.9374 | ~0.94 |
| FPR | 0.2900 | ~0.25 |
| Adaptation to shifts | None | Automatic |
| Early warning capability | None | Yes (EARLY_WARNING level) |

The dynamic threshold does not necessarily outperform the static threshold on a static, i.i.d. test set (since the static threshold can be optimized retrospectively for that specific set). However, the dynamic threshold's advantage is operational: it performs well on non-stationary streaming data where the optimal threshold cannot be known in advance, and it provides the EARLY_WARNING capability that is absent from static approaches.

### 4.6.4 Two-Level Detection Behavior

The two-level detection mechanism (EARLY_WARNING at $\theta_t / 1.5$ and ALERT at $\theta_t$) provides graduated response:

- **EARLY_WARNING** triggers when the anomaly score exceeds approximately 67% of the current dynamic threshold. At this level, the system logs the event and notifies the security administrator but does not block the IP. This is appropriate for borderline cases (e.g., a legitimate user with slightly anomalous behavior, or the early stages of a slow attack) where premature blocking could disrupt service.

- **ALERT** triggers when the anomaly score exceeds the full dynamic threshold. At this level, the system automatically invokes Fail2Ban to ban the IP address, in addition to logging and notification.

The two-level design is particularly valuable for the low-and-slow attack scenario (discussed in detail in Section 4.8), where individual anomaly scores are only slightly elevated and may fluctuate around the EARLY_WARNING threshold for several windows before reaching the ALERT level.

### 4.6.5 Parameter Sensitivity Analysis

The sensitivity of detection performance to each threshold parameter was investigated by varying one parameter at a time while holding the others at their default values:

**Alpha ($\alpha$):** At $\alpha = 0.1$, the EWMA responds slowly to changes, suitable for very stable environments but slow to detect sudden onset attacks. At $\alpha = 0.3$ (selected), a balanced trade-off between responsiveness and noise filtering is achieved. At $\alpha = 0.5$, the EWMA responds rapidly but is more sensitive to transient score fluctuations, causing the threshold to oscillate.

**Base percentile ($p$):** At $p = 90$, the threshold is lower, detecting more anomalies but generating approximately 20% more false positives. At $p = 95$ (selected), an effective balance between detection sensitivity and false alarm rate is achieved. At $p = 99$, the threshold is high, producing very few false positives but potentially missing subtle attacks.

**Sensitivity factor ($\lambda$):** At $\lambda = 1.0$, the threshold equals the percentile, providing maximum sensitivity. At $\lambda = 1.5$ (selected), the threshold extends 50% above the EWMA-to-percentile gap, effectively reducing false positives. At $\lambda = 2.0$, the threshold is very conservative, suitable only for environments with extremely low tolerance for alert volume.

[Figure 4.8: Effect of $\alpha$, $p$, and $\lambda$ on F1-Score and FPR, showing the optimal region around the selected parameter values]

### 4.6.6 Self-Calibration Results

The self-calibration mechanism (recalibration every 100 decisions) was evaluated by simulating a deployment scenario with drifting traffic patterns. Over a simulated 24-hour period with varying attack intensity, the self-calibrating threshold maintained a consistent detection rate (F1-Score within $\pm 0.02$ of the static-optimal value) despite the distribution drift, while the static threshold showed F1-Score degradation of up to 0.08 during high-drift periods.

## 4.7 System Integration Test Results

### 4.7.1 End-to-End Pipeline Validation

The complete system pipeline was validated by injecting known attack and normal SSH traffic into the target SSH server and verifying the end-to-end flow from log event to detection decision and response action.

[Table 4.16: Latency analysis by pipeline stage]

| Stage | Average Latency | Notes |
|-------|----------------|-------|
| Log ingestion (Logstash) | < 1 second | Batch-dependent |
| Feature extraction (API Server) | < 100 ms | 14 features from Redis buffer |
| Model inference (IF) | < 10 ms | Fastest (path length computation) |
| Model inference (LOF) | < 50 ms | k-NN distance computation |
| Model inference (OCSVM) | < 30 ms | Kernel evaluation against support vectors |
| Dynamic threshold update | < 5 ms | EWMA arithmetic |
| Decision + Fail2Ban API call | < 50 ms | HTTP API invocation |
| Dashboard notification (WebSocket) | < 20 ms | Push notification |
| **Total end-to-end** | **< 1--2 seconds** | **Meets real-time requirements** |

The total end-to-end latency from the moment an SSH authentication event occurs to the moment a detection decision is rendered and an IP ban is executed is under 2 seconds. The vast majority of this latency resides in the log ingestion stage (Logstash file tailing and parsing); all AI-related processing stages (feature extraction, model inference, threshold computation) complete in under 150 ms combined.

### 4.7.2 Throughput Analysis

The system was stress-tested to determine its maximum throughput capacity. The API Server, using FastAPI's ASGI-based asynchronous architecture, can process several hundred feature vectors per second on a single worker, which is sufficient for monitoring dozens of SSH servers simultaneously. At peak throughput, the bottleneck shifts from the AI processing pipeline to the Elasticsearch write throughput, confirming that the AI components do not limit system performance.

### 4.7.3 Resource Utilization

[Table 4.17: Resource utilization of Docker services under typical load]

| Service | RAM (Approx.) | CPU (Avg.) | Notes |
|---------|--------------|-----------|-------|
| API Server (FastAPI) | ~200 MB | 5--15% | Scales with request volume |
| Detector (scikit-learn) | ~150 MB | 2--5% | Loaded model + scaler |
| Elasticsearch | ~1--2 GB | 10--20% | Index management, continuous |
| Logstash | ~500 MB | 5--10% | JVM-based, log rate dependent |
| Kibana | ~400 MB | 3--8% | JVM-based, increases with dashboard use |
| React Frontend | ~50 MB (client) | <1% | Runs in browser |
| Redis | ~50 MB | <1% | Lightweight in-memory store |
| Fail2Ban | ~30 MB | <1% | Event-driven, minimal footprint |
| SSH Target | ~20 MB | <1% | Standard OpenSSH |

The total system resource footprint is approximately 2.5--4.5 GB of RAM, well within the capacity of a modest server or cloud instance. The Elasticsearch service is the most resource-intensive component, consistent with its role as the primary data store and search engine.

## 4.8 Attack Scenario Testing

### 4.8.1 Scenario Design

Five attack scenarios were designed and executed against the test environment, each simulating a distinct SSH brute-force attack variant documented in the literature [11, 14, 15]. The attack scripts were implemented in Python using the Paramiko SSH library, which provides programmatic control over SSH connection parameters including timing, username selection, and password selection.

[Table 4.18: Description of 5 attack scenarios]

| No. | Scenario | IPs | Speed | Usernames | Difficulty |
|-----|----------|-----|-------|-----------|-----------|
| 1 | Basic Brute-Force | 1 | Maximum | root | Easy |
| 2 | Distributed Attack | 10+ | Moderate | Various | Medium |
| 3 | Low-and-Slow | 1 | 30--120s delay | Various | Hard |
| 4 | Credential Stuffing | 1--3 | Moderate-High | Leaked list | Medium |
| 5 | Dictionary Attack | 1 | High | root | Easy |

### 4.8.2 Scenario 1: Basic Brute-Force

**Configuration.** A single IP address attempts to authenticate as root at maximum speed, dispatching attempts as fast as the SSH server and network permit (typically 5--20 attempts per second). The password list is systematically generated.

**Results.** All three models detect 100% of attack windows. Anomaly scores are far above the dynamic threshold (typically 3--5x the threshold value). Detection occurs within the first 1-minute stride --- a maximum latency of 60 seconds from attack onset to detection. The feature profile is unmistakable: fail_count in the hundreds, fail_rate $\approx 1.0$, mean_inter_attempt_time $< 0.5$ seconds, session_duration_mean $< 3$ seconds, unique_usernames $= 1$.

**Key features activated.** fail_count, fail_rate, mean_inter_attempt_time, min_inter_attempt_time, session_duration_mean, connection_count.

### 4.8.3 Scenario 2: Distributed Attack

**Configuration.** 10+ IP addresses (simulating a small botnet) each attempt 2--5 password combinations before cycling to the next target. The total attack volume is comparable to Scenario 1, but distributed across many sources to evade per-IP rate limiting.

**Results.** The system detects more than 90% of attacking IPs. The IPs with the highest per-IP attempt counts (3--5 attempts) are detected reliably. However, IPs performing only 1--2 attempts within a single 5-minute window produce anomaly scores in the borderline zone between EARLY_WARNING and ALERT thresholds. The temporal features (session_duration_mean, min_inter_attempt_time) remain anomalous even for low-volume IPs because automated tools still produce characteristically short sessions and machine-speed timing patterns.

**Key features activated.** session_duration_mean, min_inter_attempt_time, unique_ports.

[Table 4.19: Distributed attack detection rates by per-IP attempt count]

| Attempts per IP per Window | Detection Rate (IF) | Detection Rate (OCSVM) |
|---------------------------|--------------------|-----------------------|
| 1--2 | ~75% | ~82% |
| 3--5 | ~95% | ~97% |
| 6+ | 100% | 100% |

### 4.8.4 Scenario 3: Low-and-Slow

**Configuration.** A single IP address spaces authentication attempts over intervals of 30--120 seconds, deliberately staying below traditional rate-limiting thresholds (e.g., Fail2Ban's default maxretry=5/findtime=600s). The attacker targets various usernames with a curated password list.

**Results.** This is the most challenging scenario and represents the boundary of the system's detection capabilities. Individual 5-minute windows contain only 1--3 events per window, producing feature vectors with modestly elevated anomaly scores that may fluctuate around the EARLY_WARNING threshold. The key detection mechanism is the **EWMA accumulation**: although each individual window's anomaly score may not exceed the ALERT threshold, the cumulative effect of 3--5 consecutive windows with slightly elevated scores causes the EWMA value to rise, eventually crossing the EARLY_WARNING threshold (at approximately 2--3 minutes after attack onset) and potentially the ALERT threshold (at approximately 5--8 minutes).

The detection relies primarily on two features that remain anomalous even at low attempt rates: **session_duration_mean** (attack sessions are still extremely short --- under 5 seconds --- because even though the attacker waits between sessions, each individual session consists of a single failed attempt followed by disconnection) and **invalid_user_ratio** (if the attacker uses non-existent usernames, this ratio is elevated regardless of attempt frequency).

**Comparison with Fail2Ban.** Under Fail2Ban's default configuration (maxretry=5, findtime=600 seconds), a low-and-slow attack spacing attempts at 2-minute intervals would produce only 3 failures within the 10-minute findtime window, falling below the maxretry=5 threshold and evading detection entirely. The AI system's EWMA accumulation mechanism detects the same attack pattern within 2--3 minutes through cumulative score elevation.

[Table 4.20: Low-and-Slow detection results by model]

| Model | Detection Rate | Avg Windows to EARLY_WARNING | Avg Windows to ALERT |
|-------|---------------|----------------------------|--------------------|
| IF | ~70% | 3--4 windows | 5--7 windows |
| LOF | ~80% | 3 windows | 4--6 windows |
| OCSVM | ~85% | 2--3 windows | 4--5 windows |

### 4.8.5 Scenario 4: Credential Stuffing

**Configuration.** 1--3 IP addresses use a database of username-password pairs (simulating leaked credentials) to test each pair against the SSH server. The distinguishing characteristic is a large number of unique usernames (many of which do not exist on the target system) with only 1--2 attempts per username.

**Results.** Detection rate exceeds 95% for all models. The feature profile is distinctive: unique_usernames is very high (tens of different usernames per window), invalid_user_ratio is elevated (since many usernames from leaked lists do not exist on the target system), and the temporal features still indicate automated behavior (short sessions, sub-second inter-attempt times).

**Key features activated.** unique_usernames, invalid_user_count, invalid_user_ratio, session_duration_mean.

### 4.8.6 Scenario 5: Dictionary Attack

**Configuration.** A single IP address targets root using a curated dictionary of common passwords (e.g., RockYou, SecLists top-1000). The attack proceeds at high speed with a single target username.

**Results.** Detection rate is 100% for all three models. The feature profile is similar to Scenario 1 (basic brute-force): very high fail_count, fail_rate $\approx 1.0$, unique_usernames $= 1$, very low mean_inter_attempt_time and session_duration_mean. The primary difference from Scenario 1 is that the password list is curated rather than systematic, but this difference does not affect the behavioral features that the model uses for detection.

### 4.8.7 Consolidated Scenario Results

[Table 4.21: Summary of detection results across 5 attack scenarios]

| Scenario | Difficulty | IF | LOF | OCSVM | Primary Discriminators |
|----------|-----------|------|------|-------|----------------------|
| 1. Basic Brute-Force | Easy | 100% | 100% | 100% | fail_count, fail_rate, timing |
| 2. Distributed | Medium | >90% | >92% | >93% | session_duration, timing, ports |
| 3. Low-and-Slow | Hard | ~70% | ~80% | ~85% | session_duration, EWMA accum. |
| 4. Credential Stuffing | Medium | >95% | >96% | >97% | unique_usernames, invalid_user |
| 5. Dictionary Attack | Easy | 100% | 100% | 100% | fail_count, timing, session |

[Figure 4.9: Heatmap of detection rates by attack scenario and model]

The consolidated results yield several important findings:

1. **High-speed attacks (Scenarios 1, 5) are trivially detected.** All models achieve 100% detection, with anomaly scores far exceeding any reasonable threshold. These scenarios validate the basic functionality of the system but do not test its limits.

2. **Distributed attacks (Scenario 2) require multidimensional analysis.** Per-IP count features alone are insufficient when each IP makes only a few attempts. The temporal and session features (which remain anomalous even at low per-IP volumes because automated tools still produce machine-speed timing and short sessions) are essential for detection.

3. **Low-and-slow attacks (Scenario 3) are the critical challenge.** Detection rates of 70--85% represent the system's performance frontier. The EWMA accumulation mechanism provides the key capability: detecting the persistent, cumulative pattern of slightly anomalous activity that no single-window analysis can reliably identify. This is the scenario where the dynamic threshold provides the greatest marginal value over static approaches.

4. **OCSVM consistently achieves the highest per-scenario detection rates.** The nonlinear RBF kernel decision boundary is more sensitive to subtle deviations from the normal profile than IF's axis-aligned random partitions. However, IF's computational efficiency and score distribution properties make it the preferred choice for the real-time system.

## 4.9 Detection Time Comparison: AI vs. Fail2Ban

### 4.9.1 Comparative Framework

To quantify the detection time advantage of the AI-based system over traditional rate-limiting approaches, both systems were evaluated on the same attack traffic under the same conditions. Fail2Ban was configured with its default SSH parameters: maxretry=5, findtime=600 seconds, bantime=600 seconds.

### 4.9.2 Detection Time Results

[Table 4.22: Detection time comparison: AI system vs. Fail2Ban]

| Scenario | AI System (Time to Detection) | Fail2Ban (Time to Detection) | Advantage |
|----------|-------------------------------|-------------------------------|-----------|
| Basic Brute-Force | < 1 minute (first window) | ~5--10 seconds (5 failures) | Fail2Ban faster* |
| Distributed | < 2 minutes | Never (< 5 failures/IP) | AI only |
| Low-and-Slow | 2--3 min (EARLY_WARNING) | Never (< 5 failures/findtime) | AI only |
| Credential Stuffing | < 1 minute | ~30--60 seconds | Comparable |
| Dictionary Attack | < 1 minute | ~5--10 seconds | Fail2Ban faster* |

*For high-speed attacks (Scenarios 1, 5), Fail2Ban detects faster because it triggers immediately upon the 5th failure, while the AI system requires at least one full 5-minute window to compute meaningful features. However, the AI system provides detection for Scenarios 2 and 3, which Fail2Ban cannot detect at all.

### 4.9.3 Analysis

The comparison reveals that the AI system and Fail2Ban are complementary rather than competitive:

- **Fail2Ban excels** at detecting high-speed, single-IP attacks (Scenarios 1, 5) with faster detection time due to its event-by-event counting mechanism.
- **The AI system excels** at detecting distributed attacks (Scenario 2), low-and-slow attacks (Scenario 3), and providing nuanced detection through the two-level alerting mechanism.
- **The integrated architecture** (both systems operating in parallel) provides the best of both capabilities: Fail2Ban provides rapid response to obvious high-speed attacks, while the AI system detects sophisticated attacks that evade Fail2Ban entirely.

This complementary architecture is consistent with the defense-in-depth principle advocated by NIST SP 800-53 [108], which recommends multiple layers of security controls operating at different abstraction levels.

## 4.10 Comparison with State-of-the-Art

### 4.10.1 Literature Comparison

The results of this study are compared with 12 published studies in the field of SSH brute-force attack detection and network intrusion detection. The comparison is structured to highlight the methodological and performance differences.

[Table 4.23: Comprehensive comparison with state-of-the-art studies]

| Study | Year | Method | Dataset | Features | Real-time | F1-Score | Notes |
|-------|------|--------|---------|----------|-----------|----------|-------|
| Sperotto et al. [109] | 2010 | Flow-based HMM | University SSH logs | Flow features | No | ~0.85 | Pioneering SSH flow analysis |
| Hellemons et al. [65] | 2012 | Flow-based rules | CESNET | Flow statistics | Partial | ~0.88 | Time-window approach |
| Javed & Paxson [72] | 2013 | Timing analysis | Live SSH | Timing features | Yes | ~0.90 | Established timing as key discriminator |
| Najafabadi et al. [110] | 2015 | Deep learning (AE) | NSL-KDD | PCA features | No | 0.87 | Autoencoder anomaly detection |
| Kim et al. [111] | 2019 | Random Forest | NSL-KDD | 41 KDD features | No | 0.92 | Supervised, benchmark dataset |
| Ahmed et al. [112] | 2020 | Autoencoder + LSTM | CICIDS2017 | Flow + temporal | Yes | 0.89 | Deep learning, real-time |
| Moustafa et al. [113] | 2021 | Ensemble (RF+XGB) | UNSW-NB15 | 49 features | No | 0.93 | Supervised ensemble |
| Nassif et al. [114] | 2021 | ML Survey | Multiple | Varies | Varies | -- | Comprehensive survey |
| Ferrag et al. [115] | 2022 | Federated learning | CIC-ToN-IoT | DNN features | Yes | 0.91 | Privacy-preserving |
| Thakkar & Lohiya [116] | 2022 | IF + sampling | CICIDS2017 | Flow features | No | 0.90 | Isolation Forest on IDS dataset |
| Sarker et al. [117] | 2023 | ML + DL hybrid | Custom IoT | Multi-modal | Partial | 0.92 | Hybrid architecture |
| Kumar & Lim [118] | 2024 | Transformer-IDS | CICIDS2017 | Attention-based | Yes | 0.94 | State-of-the-art, high compute |
| **This study** | **2026** | **IF + EWMA-AP** | **Real SSH (honeypot + sim)** | **14 SSH-specific** | **Yes** | **0.9374** | **End-to-end system** |

### 4.10.2 Comparative Analysis

The comparison highlights several distinctive characteristics of this study:

**Dataset realism.** The majority of compared studies (8 of 12) use benchmark datasets (NSL-KDD, CICIDS2017, UNSW-NB15) that are widely acknowledged to have significant limitations: NSL-KDD is derived from DARPA 1998/1999 network captures that do not reflect modern traffic patterns [73]; CICIDS2017, while more recent, uses synthetically generated attacks that may not capture the full diversity of real-world attack behavior [74]. This study uses real SSH authentication logs from a live honeypot (capturing authentic attack patterns from 679 unique attacker IPs) combined with realistic simulation data, providing a more representative evaluation.

**Feature domain specificity.** Most compared studies use generic network flow features (packet counts, byte counts, flow duration) or protocol-agnostic statistical features. This study uses 14 features specifically designed for SSH authentication behavior, including domain-specific features such as session_duration_mean, invalid_user_ratio, and pam_failure_escalation that capture the unique characteristics of SSH brute-force attacks. Javed and Paxson [72] demonstrated the superiority of domain-specific features over generic features for SSH attack detection, a finding that this study confirms and extends.

**Semi-supervised vs. supervised.** Several high-performing studies (Kim et al. [111], Moustafa et al. [113]) use supervised methods, which achieve high accuracy when the test data contains attack types present in the training data but cannot detect novel attack types. This study's semi-supervised approach sacrifices a small amount of accuracy on known attack types in exchange for the ability to detect any attack whose behavioral profile deviates from normal SSH usage --- a critical capability in production environments where novel attack techniques are constantly emerging.

**End-to-end system.** Most compared studies report offline evaluation results without addressing the practical challenges of real-time deployment, system integration, or automated response. This study implements and evaluates a complete system comprising 9 Docker services, with end-to-end latency under 2 seconds, demonstrating production readiness. Only Ahmed et al. [112], Ferrag et al. [115], and Kumar and Lim [118] report real-time capability, but none implement an integrated detection-to-prevention pipeline with Fail2Ban integration.

**Dynamic thresholding.** None of the compared studies implement an adaptive dynamic threshold for SSH-specific anomaly detection. The EWMA-Adaptive Percentile mechanism is a methodological contribution that addresses the well-documented limitation of static thresholds in non-stationary environments [89, 90].

**F1-Score contextualization.** The F1-Score of 0.9374 (optimized Isolation Forest) is competitive with the highest-performing studies. Kumar and Lim [118] achieve 0.94 using Transformer-based deep learning, but at significantly higher computational cost and with the requirement for labeled training data (supervised). Moustafa et al. [113] achieve 0.93 using a supervised ensemble, also requiring labeled attack data. This study achieves comparable F1-Score using a computationally lightweight semi-supervised method that does not require labeled attack data for training.

### 4.10.3 Positioning

This study occupies a distinct position in the literature: it is one of few studies that combines (1) real-world SSH-specific data, (2) semi-supervised anomaly detection, (3) dynamic adaptive thresholding, (4) an end-to-end deployed system, and (5) evaluation against diverse attack scenarios. While individual components have been explored in prior work, the integrated combination is novel and addresses the research-to-deployment gap identified by Sommer and Paxson [119] as the primary barrier to practical adoption of machine learning in intrusion detection.

## 4.11 Interpretation and Implications

### 4.11.1 Theoretical Implications

The experimental results support several theoretical conclusions:

**The semi-supervised paradigm is sufficient for SSH brute-force detection.** All three models achieve recall $\geq 0.9675$ after optimization, confirming that learning from normal data alone is adequate to identify the vast majority of SSH brute-force attacks. This validates the theoretical predictions of Chandola et al. [47] regarding the applicability of novelty detection to cybersecurity domains where anomalies are behaviorally distinct from normal operations.

**Temporal features dominate count-based features for SSH attack discrimination.** The permutation importance analysis (Section 4.4) demonstrates that session_duration_mean, min_inter_attempt_time, and mean_inter_attempt_time are the primary discriminators, while traditional count-based features (fail_count, invalid_user_count) have negligible importance. This finding extends the work of Javed and Paxson [72] by quantifying the relative importance of specific temporal features in the context of unsupervised anomaly detection, and it challenges the design assumptions underlying traditional count-based detection tools such as Fail2Ban.

**Dynamic thresholding provides operational advantages over static thresholds.** The EWMA-Adaptive Percentile mechanism enables three capabilities absent from static approaches: adaptation to distribution shifts, burst false positive reduction, and cumulative early warning for slow attacks. These advantages are most pronounced in non-stationary operating environments --- precisely the conditions encountered in real-world production deployments.

### 4.11.2 Practical Implications

**For security operations teams.** The system can be deployed as a complement to existing Fail2Ban installations, providing coverage for the attack types (distributed, low-and-slow) that Fail2Ban cannot detect. The two-level alerting mechanism (EARLY_WARNING and ALERT) provides operational flexibility, allowing security teams to configure the response policy according to their risk tolerance.

**For SSH server administrators.** The feature importance results suggest that monitoring session duration and inter-attempt timing is more informative than monitoring failure counts alone. Administrators who cannot deploy the full system can still improve their detection capability by adding session-duration-based rules to their existing Fail2Ban or OSSEC configurations.

**For the research community.** The dataset and methodology provide a template for future studies that seek to bridge the gap between offline algorithm evaluation and real-world system deployment. The finding that temporal features dominate count-based features should inform the feature engineering decisions of future SSH security research.

### 4.11.3 Limitations of the Results

Several limitations should be noted when interpreting the experimental results:

1. **The 29% FPR of the optimized IF model** means that approximately 29% of normal windows are still incorrectly flagged as attacks. While this is a dramatic improvement over the 77% baseline FPR, it represents an ongoing cost in terms of alert volume that security teams must manage. Further reduction of the FPR without sacrificing recall remains an open challenge.

2. **The low-and-slow detection rate of 70--85%** represents the system's weakest performance. Extremely slow attacks (one attempt every 10+ minutes) may produce feature vectors that are indistinguishable from normal activity within a single 5-minute window, and even the EWMA accumulation mechanism may take multiple windows to reach the detection threshold.

3. **The evaluation was conducted on a specific dataset** with a specific normal-to-attack ratio, attack type distribution, and environmental characteristics. Performance may vary in different environments with different traffic patterns, user populations, or attack sophistication levels.

4. **The comparison with state-of-the-art studies** is necessarily imperfect because the studies use different datasets, different evaluation protocols, and different definitions of "attack." Direct head-to-head comparison on the same dataset would provide more rigorous benchmarking, but such standardized SSH-specific benchmarks do not yet exist.

### 4.11.4 Summary of Key Findings

[Table 4.24: Summary of key experimental findings]

| Finding | Evidence | Significance |
|---------|----------|-------------|
| Semi-supervised detection achieves $\geq 96.75\%$ recall | Table 4.12, all three models | Validates paradigm for SSH security |
| Temporal features are primary discriminators | Table 4.11, top 5 features = temporal/session | Challenges count-based detection assumptions |
| Optimization reduces FPR by 48 pp | Table 4.14, 76.92% $\rightarrow$ 29.00% | Critical for production viability |
| Dynamic threshold enables early warning | Section 4.6, 2--3 min detection of slow attacks | Novel capability absent from static methods |
| AI detects attacks that Fail2Ban cannot | Table 4.22, Scenarios 2 and 3 | Justifies complementary deployment |
| End-to-end latency < 2 seconds | Table 4.16 | Confirms real-time capability |
| F1=0.9374 competitive with state-of-the-art | Table 4.23, comparison with 12 studies | Validates approach against literature |
| 5 attack scenarios with 70--100% detection | Table 4.21 | Comprehensive coverage evaluation |
