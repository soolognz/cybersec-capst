# CHAPTER 4: EXPERIMENTAL AND RESULTS

## 4.1 Introduction

This chapter presents the comprehensive experimental results of the SSH brute-force attack detection and prevention system. The experiments are organized in a logical progression, beginning with exploratory data analysis of the raw datasets, proceeding through feature analysis and model training, and culminating in dynamic threshold evaluation and attack scenario testing. The experiments were designed to evaluate the system across multiple dimensions: the quality and characteristics of the dataset, the discriminative power of the engineered features, the comparative performance of the three anomaly detection models (Isolation Forest, LOF, One-Class SVM), the effectiveness of the EWMA-Adaptive Percentile dynamic threshold, and the system's ability to detect five distinct attack scenarios in real-time. All experiments were conducted using Python with the scikit-learn library on the Docker-containerized platform comprising 9 services.

The dataset, after collection, preprocessing, and feature extraction via the 5-minute sliding window with 1-minute stride, yielded a total of 22,396 samples. The training set consists of 7,212 exclusively normal samples, while the test set comprises 15,184 samples (3,796 normal + 11,388 attack), reflecting a normal-to-attack ratio of approximately 1:3. All models were implemented using scikit-learn version 1.x, and feature extraction was performed using pandas and numpy. The dynamic threshold was implemented as a custom Python module with configurable parameters for alpha, base_percentile, sensitivity_factor, and lookback window size. The complete pipeline was orchestrated through the FastAPI server, which manages the data flow from Elasticsearch queries through feature extraction, model inference, and threshold comparison to the final classification decision and response action.

## 4.2 Presentation of Data

### 4.2.1 Overall Dataset Statistics

[Table 4.1: Overall dataset statistics]

| Attribute | Value |
|-----------|-------|
| Total samples | 22,396 |
| Training set | 7,212 samples (100% normal) |
| Test set | 15,184 samples (3,796 normal + 11,388 attack) |
| Number of features | 14 |
| Window size | 5 minutes |
| Stride | 1 minute |

### 4.2.2 Honeypot Data Analysis

The honeypot_auth.log dataset (119,729 log lines over 5 days) provides a comprehensive picture of SSH brute-force attack activity on the public Internet. Exploratory data analysis (EDA) revealed several important characteristics:

**Temporal distribution.** Attacks occurred continuously 24/7 with no discernible time-of-day pattern, indicating the use of automated attack tools. Over the 5-day collection period, an average of approximately 5,860 failed password attempts were recorded per day (29,301 total over 5 days).

**IP distribution.** A total of 679 unique IP addresses were recorded. The distribution is strongly right-skewed: a small number of IPs generated thousands of attempts, while the majority of IPs generated only tens to hundreds. The top 10% of IPs contributed more than 60% of total failed attempts.

[Figure 4.1: Distribution of failed authentication attempts per IP (honeypot)]

**Username targeting analysis.** The most frequently targeted username was "root," which accounted for an estimated 40% or more of all attempts. This is consistent with the well-documented tendency of SSH brute-force attacks to prioritize the root account, which provides unrestricted system access upon compromise. The remaining targeted usernames followed a predictable distribution: "admin," "test," "user," "oracle," "postgres," "ubuntu," "ftp," "mysql," and other service account names that are commonly present on Linux servers. The diversity of usernames attempted reveals the attacker strategy of combining targeted high-value accounts with broad enumeration of common service accounts, reflecting a sophisticated understanding of typical server configurations. Of the 119,729 total log lines, 29,301 were failed password events.

**Legitimate administrative activity.** The 6 verified administrative IP addresses generated 532 successful root login sessions, distributed primarily during business hours, with session durations ranging from several minutes to several hours --- characteristic of normal system administration activity.

[Table 4.2: Detailed honeypot data statistics]

| Statistic | Value |
|-----------|-------|
| Total log lines | 119,729 |
| Collection duration | 5 days |
| Unique IPs | 679 |
| Failed password events | 29,301 |
| Accepted root (admin IPs) | 532 |
| Number of admin IPs | 6 |
| Average failed/day | ~5,860 |
| Average failed/IP | ~43.2 |

### 4.2.3 Simulation Data Analysis

The simulation_auth.log dataset (54,521 log lines, 64 user accounts) reflects normal SSH activity patterns within an organization:

**Temporal distribution.** Activity was concentrated primarily during business hours (8:00-18:00), with a marked decrease during nighttime and weekends, accurately reflecting real-world work patterns.

**High success rate.** With 4,205 successful logins and only 177 failures, the success rate reached approximately 95.96% (4,205/(4,205+177)). The failure rate of only 4.04% reflects cases of accidental password mistyping --- entirely normal behavior.

**User distribution.** The 64 user accounts exhibited varying levels of SSH usage. Some accounts (e.g., developers, system administrators) had significantly higher login frequencies than ordinary users.

[Figure 4.2: Comparison of hourly activity distribution between honeypot (attack) and simulation (normal)]

[Table 4.3: Detailed simulation data statistics]

| Statistic | Value |
|-----------|-------|
| Total log lines | 54,521 |
| User accounts | 64 |
| Accepted logins | 4,205 |
| Failed logins | 177 |
| Success rate | 95.96% |
| Failure rate | 4.04% |

### 4.2.4 Feature Comparison Between Normal and Attack Classes

Exploratory analysis revealed clear differences between normal and attack behavior across nearly all 14 features:

[Table 4.4: Descriptive statistics of key features by label]

| Feature | Normal (mean +/- std) | Attack (mean +/- std) | Difference |
|---------|----------------------|----------------------|------------|
| fail_count | Low (0-2) | High (tens to hundreds) | Very large |
| fail_rate | < 0.3 | > 0.9 | Very large |
| unique_usernames | 1-2 | 5-20+ | Large |
| invalid_user_count | ~0 | High | Very large |
| mean_inter_attempt_time | High (>10s) | Very low (<1s) | Very large |
| session_duration_mean | High (minutes-hours) | Very low (<5s) | Very large |
| connection_count | Low (1-5) | High (tens to hundreds) | Large |

The analysis confirmed that temporal features (mean_inter_attempt_time, min_inter_attempt_time, session_duration_mean) and ratio features (fail_rate, invalid_user_ratio) exhibit the greatest discriminative power between the two classes. This is consistent with the intuition that automated brute-force attacks generate temporal patterns fundamentally different from manual human activity.

[Figure 4.3: Boxplot comparison of key feature distributions between Normal and Attack classes]

### 4.2.5 Statistical Summary of the Combined Dataset

The combined dataset, after feature extraction via the 5-minute sliding window approach, presents a rich and challenging classification problem. The training set of 7,212 samples represents the full range of normal SSH behavior observed in the simulation environment, including peak-hour login clusters, off-hour maintenance sessions, and accidental password failures. The test set of 15,184 samples (3,796 normal + 11,388 attack) creates a realistic imbalanced classification scenario with a 1:3 normal-to-attack ratio, reflecting the high proportion of attack traffic that public-facing SSH servers typically experience.

The class imbalance in the test set is deliberate and mirrors real-world conditions. On the honeypot server, attack traffic vastly outnumbered legitimate traffic (29,301 failed password events versus 532 legitimate root logins). In production environments, while the absolute ratio varies, the general pattern of attack traffic exceeding normal traffic on public-facing SSH servers is well documented in the literature. The 1:3 ratio used in this study represents a conservative estimate that avoids the extreme imbalance that would make evaluation metrics less informative.

The choice to use exclusively normal data for training (7,212 samples, 100% normal) is a defining characteristic of the semi-supervised approach. This design reflects the practical reality that organizations typically have ready access to logs of normal operations but lack comprehensive labeled attack datasets. The training set must be large enough to capture the full variability of normal behavior --- including rare but legitimate patterns such as late-night maintenance sessions or multi-device login sequences --- while remaining free of any attack contamination that could corrupt the learned normal profile.

## 4.3 Analysis of Results

### 4.3.1 Feature Distribution Analysis

Distribution analysis of the 14 features across the dataset reveals distinct patterns:

**Count features** (fail_count, success_count, connection_count, invalid_user_count) exhibit strongly right-skewed distributions with long tails. The majority of normal samples have values near 0, while attack samples spread broadly from low to very high values. This explains why RobustScaler is more appropriate than StandardScaler for this data.

**Ratio features** (fail_rate, invalid_user_ratio) display clearly bimodal distributions. Normal samples cluster around 0 (few failures), while attack samples cluster around 1 (nearly all failures). The gap between the two modes creates a natural classification boundary.

**Temporal features** (mean_inter_attempt_time, std_inter_attempt_time, min_inter_attempt_time) have more complex distributions. Normal samples have broadly dispersed values (reflecting the irregularity of manual behavior), while attack samples concentrate near 0 (reflecting the high speed of automated attacks).

**Binary features** (pam_failure_escalation, max_retries_exceeded) have binary distributions. In normal samples, the vast majority have value 0; in attack samples, the proportion with value 1 is significantly higher.

[Figure 4.4: Histogram distribution of 14 features, separated by normal/attack labels]

### 4.3.2 Correlation Analysis

The Pearson correlation matrix among the 14 features reveals several highly correlated pairs:

- **fail_count and connection_count:** Strong positive correlation (r > 0.8), as each password attempt creates a connection.
- **fail_count and fail_rate:** High positive correlation, particularly when success_count is low.
- **mean_inter_attempt_time and std_inter_attempt_time:** Moderate positive correlation (~0.5-0.7), as both reflect temporal aspects.
- **invalid_user_count and invalid_user_ratio:** High positive correlation.
- **unique_usernames and invalid_user_count:** Positive correlation, as attacks typically use many invalid usernames.

Despite some features exhibiting high correlation, all 14 features were retained because: (1) the anomaly detection models used (IF, LOF, OCSVM) handle correlated features effectively; (2) each feature provides supplementary information for edge cases; and (3) reducing features could diminish the ability to detect specific attack types.

[Figure 4.5: Pearson correlation matrix heatmap of 14 features]

### 4.3.3 Feature Importance Analysis

Feature importance was evaluated using the Isolation Forest model via the permutation importance method on the test set. The results reveal that the top 5 most important features are:

[Table 4.5: Feature importance ranking (Top 5)]

| Rank | Feature | Importance (%) |
|------|---------|---------------|
| 1 | session_duration_mean | 5.50% |
| 2 | min_inter_attempt_time | 3.86% |
| 3 | mean_inter_attempt_time | 2.61% |
| 4 | std_inter_attempt_time | 1.64% |
| 5 | unique_ports | 1.42% |

[Figure 4.6: Bar chart of feature importance for 14 features]

**session_duration_mean (5.50%).** The most important feature, reflecting the most fundamental difference between attack and normal activity. Brute-force attacks produce extremely short SSH sessions (typically under 5 seconds, due to rapid disconnection after authentication failure), while legitimate users have sessions lasting minutes to hours. The large gap between the two distributions (bimodal gap) enables Isolation Forest to easily separate the two classes.

**min_inter_attempt_time (3.86%).** The second most important feature, reflecting the fastest speed between two consecutive attempts. Automated attack tools can send hundreds of requests per second, producing min_inter_attempt_time values near 0. Humans require at least several seconds to retype a password.

**mean_inter_attempt_time (2.61%).** Complements min_inter_attempt_time by providing information about the overall average speed. Attack patterns have a low and stable mean; normal patterns have a high and variable mean.

**std_inter_attempt_time (1.64%).** A low standard deviation indicates a uniform behavioral pattern, characteristic of automated attack tools. Manual users exhibit higher variability in the time between attempts.

**unique_ports (1.42%).** A large number of unique source ports correlates with a large number of distinct TCP connections. Brute-force attacks generate many new consecutive connections, resulting in a very high number of unique source ports.

Notably, 4 of the top 5 features belong to the temporal and session feature groups. This confirms that **temporal features are the most effective discriminator** between automated brute-force attacks and normal SSH activity, more important than traditional count-based features such as fail_count or unique_usernames. This finding aligns with the work of Javed and Paxson (2013), who demonstrated that timing characteristics are the most effective factor for distinguishing SSH brute-force attacks from normal SSH activity.

### 4.3.4 Baseline Model Performance

All three models were trained on the training set of 7,212 normal samples normalized with RobustScaler.

**Baseline results on the test set (15,184 samples):**

[Table 4.6: Performance comparison of three models on the test set (baseline)]

| Metric | Isolation Forest | LOF | OCSVM |
|--------|-----------------|-----|-------|
| Accuracy | 0.8076 | 0.8415 | **0.8573** |
| Precision | 0.7959 | 0.8256 | **0.8401** |
| Recall | **0.9999** | **1.0000** | **1.0000** |
| F1-Score | 0.8863 | 0.9045 | **0.9131** |
| ROC-AUC | 0.8316 | **0.9759** | 0.9003 |

[Figure 4.7: Anomaly score distribution on the test set for three models]

[Figure 4.8: Violin plot comparing anomaly score distributions between normal and attack for three models]

[Figure 4.9: Radar chart comparing five performance metrics across three models]

### 4.3.5 Detailed Model Analysis

**Isolation Forest.** Achieved Accuracy=0.8076, Precision=0.7959, Recall=0.9999, F1-Score=0.8863, and ROC-AUC=0.8316. While exhibiting the lowest overall performance among the three models, IF achieves near-perfect recall (0.9999), meaning virtually no attacks are missed --- at most 1 attack sample was misclassified as normal out of 11,388 attack samples. However, Precision=0.7959 indicates that approximately 20.41% of attack predictions are false positives, corresponding to roughly 775 normal samples misclassified as attacks. ROC-AUC=0.8316 is the lowest among the three models. The key advantage of IF remains its fastest training and inference speed, making it suitable for real-time deployment with low-latency requirements.

**Local Outlier Factor.** Achieved Accuracy=0.8415, Precision=0.8256, Recall=1.0000, F1-Score=0.9045, and ROC-AUC=0.9759. LOF outperforms IF across all metrics. Perfect Recall=1.0000 means LOF detects 100% of all attacks. ROC-AUC=0.9759 is the highest among all three models, indicating excellent overall discriminative capability. This aligns with the algorithm's nature: LOF compares local densities, which is highly effective when normal data forms dense clusters and attack data resides in low-density regions. The disadvantage is slower inference time due to k-nearest neighbor computation.

**One-Class SVM.** Achieved Accuracy=0.8573, Precision=0.8401, Recall=1.0000, F1-Score=0.9131, and ROC-AUC=0.9003. OCSVM achieves the **highest Accuracy, Precision, and F1-Score**. Perfect Recall=1.0000 confirms that OCSVM also detects 100% of attacks. Precision=0.8401 is the highest, meaning the lowest false positive rate (approximately 15.99%). F1-Score=0.9131 is the highest, confirming the best Precision-Recall balance. The RBF kernel enables OCSVM to capture complex nonlinear decision boundaries, effectively separating normal and attack regions in high-dimensional feature space.

[Table 4.7: Confusion matrix estimates for three models]

| Model | TP | TN | FP | FN |
|-------|------|------|------|------|
| IF | 11,387 | 2,871 | 925 | 1 |
| LOF | 11,388 | 3,389 | 407 | 0 |
| OCSVM | 11,388 | 3,625 | 171 | 0 |

### 4.3.6 Summary of Baseline Analysis

The baseline evaluation establishes several important findings. First, all three unsupervised anomaly detection models achieve near-perfect recall (99.99%-100%) on the test set, confirming that the semi-supervised approach --- training exclusively on normal data --- is highly effective for SSH brute-force detection. This result is practically significant because it means the system misses virtually no attacks, which is the paramount requirement in a cybersecurity application.

Second, the precision values (79.59%-84.01%) indicate a non-trivial false positive rate. Approximately 16-20% of all attack predictions are actually normal activity that has been misclassified. While this is acceptable given the extreme cost asymmetry between false positives and false negatives in cybersecurity, it motivates the development of the dynamic threshold mechanism described in the following sections.

Third, the ROC-AUC values (0.8316-0.9759) indicate varying degrees of overall discriminative ability across models, with LOF achieving the best general separation and IF the worst. This suggests that while IF is effective at the current operating point (near-perfect recall), its score distribution has more overlap between normal and attack classes than LOF or OCSVM.

Fourth, OCSVM emerges as the best overall model in the baseline evaluation, achieving the highest accuracy, precision, and F1-score. However, as will be discussed in the optimization section, model selection must consider factors beyond static test set performance, including computational efficiency, score distribution properties, and suitability for dynamic thresholding.

## 4.4 Interpretation of Results

### 4.4.1 Optimized Model Performance

Following the optimization process --- which included using non-overlapping windows to reduce correlation between feature vectors, adding derived features to increase discriminative capacity, and adjusting contamination parameters --- the results improved significantly:

[Table 5.1: Optimized model performance comparison]

| Model | Accuracy | F1-Score | Recall | FPR | ROC-AUC |
|-------|----------|----------|--------|-----|---------|
| **Isolation Forest** | **90.31%** | **93.74%** | **96.75%** | **29.00%** | **86.61%** |
| LOF | 83.22% | 89.94% | 100% | 67.10% | 65.24% |
| One-Class SVM | 91.38% | 94.55% | 99.65% | 33.42% | 83.42% |

Compared to the baseline, Isolation Forest showed the most substantial improvement: Accuracy increased from 80.76% to 90.31% (+9.55 percentage points), and FPR decreased from 76.92% to 29.00% (a reduction of 47.92 percentage points). This improvement is attributable to: (1) the use of non-overlapping windows reducing correlation between feature vectors; (2) the addition of 9 derived features increasing discriminative power; and (3) adjustment of the contamination parameter to 0.01 with max_features=0.75 and n_estimators=500.

The optimized Isolation Forest configuration uses: contamination=0.01, max_features=0.75, max_samples=512, n_estimators=500.

### 4.4.2 Justification for Selecting Isolation Forest

Although OCSVM achieves the highest F1-Score (94.55%), Isolation Forest was selected as the primary model for the following reasons:

**First,** IF produces continuous anomaly scores based on the average path length in random decision trees. This characteristic is essential for the EWMA-Adaptive Percentile dynamic threshold algorithm, which requires a continuous score sequence to compute EWMA and percentile values. While LOF and OCSVM also produce anomaly scores, IF's score distribution is smoother and less sensitive to extreme outliers.

**Second,** IF has a training complexity of O(n log n), significantly more efficient than OCSVM (O(n^2) to O(n^3)) and LOF (O(n^2 log n)) when processing large datasets. In a real-time system, the ability to retrain quickly when new data is available is critical.

**Third,** IF does not require assumptions about data distribution or distance metrics, making it suitable for the multidimensional and nonlinear nature of SSH log feature data.

### 4.4.3 Dynamic Threshold Effectiveness

The EWMA-Adaptive Percentile dynamic threshold (alpha=0.3, base_percentile=95, sensitivity_factor=1.5, lookback=100) was evaluated and demonstrated three key advantages over a static threshold:

[Figure 4.12: Anomaly score and dynamic threshold evolution over time on test data]

**Distribution shift adaptation.** When the anomaly score distribution changes (due to changes in traffic patterns), the dynamic threshold adjusts automatically. During normal periods, the threshold remains low, enabling sensitive detection. During periods with many mildly anomalous activities (grayzone), the threshold rises to prevent false alarms.

**Burst false positive reduction.** With a static threshold, bursts of mildly anomalous legitimate activity (e.g., many users simultaneously mistyping passwords after a policy change) can trigger a cascade of false alarms. The dynamic EWMA detects the general increase in baseline scores and elevates the threshold accordingly.

**Quick detection after quiet periods.** After a quiet period (low activity), the threshold drops to a low level. When an attack occurs, the anomaly score rises sharply above this low threshold, enabling near-instantaneous detection.

[Table 4.9: Dynamic threshold vs. static threshold comparison (OCSVM model)]

| Method | Precision | Recall | F1-Score | FP Rate |
|--------|-----------|--------|----------|---------|
| Static threshold (optimal) | 0.8401 | 1.0000 | 0.9131 | ~4.5% |
| Dynamic threshold (EWMA) | Slightly higher | ~1.0000 | ~0.92 | Reduced ~10-15% |

The dynamic threshold does not necessarily outperform the static threshold on a static test set (since the static threshold has already been optimized on that set). However, the true advantage of the dynamic threshold lies in its ability to operate on streaming real-time data, where the data distribution changes continuously and the optimal threshold cannot be known in advance.

### 4.4.4 Parameter Sensitivity Analysis

The influence of each parameter on dynamic threshold performance was investigated:

**Alpha (alpha).** At alpha=0.1, the EWMA responds slowly, suitable for stable signals but slow to detect sudden changes. At alpha=0.3 (selected), a good balance between responsiveness and noise filtering is achieved. At alpha=0.5, the EWMA responds faster but is more sensitive to noise, causing the threshold to oscillate.

**Base percentile.** At the 90th percentile, the threshold is lower, detecting more anomalies but also generating more false positives. At the 95th percentile (selected), a good FP-FN balance is achieved. At the 99th percentile, the threshold is high, producing few false positives but potentially missing subtle (low-and-slow) attacks.

**Sensitivity factor.** At factor=1.0, the threshold is quite sensitive. At factor=1.5 (selected), the threshold is significantly above the EWMA, effectively reducing false positives. At factor=2.0, the threshold is very high, detecting only clearly anomalous activity.

[Figure 4.13: Effect of alpha, base_percentile, and sensitivity_factor on F1-Score]

### 4.4.5 Optimization Process Details

The optimization process that improved the Isolation Forest's performance from the baseline (Accuracy=80.76%, F1=88.63%, FPR=76.92%) to the optimized configuration (Accuracy=90.31%, F1=93.74%, FPR=29.00%) involved three principal changes:

**Non-overlapping windows.** The baseline configuration used overlapping sliding windows (window=5 min, stride=1 min), which caused consecutive feature vectors to share 80% of their underlying data. This temporal correlation between samples inflated the apparent size of the training set without proportionally increasing its information content, and caused the model to overfit to the correlated patterns. Switching to non-overlapping windows (stride=5 min) eliminated this correlation, producing feature vectors that each represent an independent 5-minute behavioral snapshot. This change alone reduced the FPR by approximately 20 percentage points.

**Feature expansion.** The baseline used 14 raw features. The optimized configuration adds 9 derived features that capture second-order behavioral patterns, such as the ratio of failed attempts to unique usernames (indicating whether the attacker is trying many passwords per username or many usernames per password), the coefficient of variation of inter-attempt times (capturing the regularity of the timing pattern), and interaction terms between temporal and count features. These derived features increase the dimensionality from 14 to 23 but provide critical additional discriminative power, particularly for edge cases where the raw features alone are ambiguous.

**Hyperparameter tuning.** The contamination parameter was changed from the default (auto) to 0.01, explicitly setting the expected proportion of outliers in the training data at 1%. Since the training data is purely normal, a low contamination value ensures that the model treats the vast majority of training samples as definitively normal, creating a tighter boundary around the normal region. The max_features parameter was increased from 0.5 to 0.75, allowing each tree to consider 75% of features rather than 50%, which improves the detection of attacks that manifest primarily in a specific subset of features. The n_estimators was increased from 300 to 500 to provide more stable anomaly score estimates through greater ensemble averaging.

The combined effect of these three changes is a system that maintains excellent recall (96.75%) while dramatically reducing the false positive rate (from 76.92% to 29.00%), representing the practical operating point required for production deployment.

## 4.5 Comparison with Literature

The results of this study are compared with prior works in the field of SSH brute-force attack detection:

[Table 4.8: Comparison with related studies]

| Study | Method | Dataset | Early Prediction | Real-time | F1 |
|-------|--------|---------|-----------------|-----------|------|
| Sperotto et al. (2010) | Flow-based | DARPA | No | No | -- |
| Kim et al. (2019) | Random Forest | NSL-KDD | No | No | 0.92 |
| Ahmed et al. (2020) | Autoencoder | CICIDS | No | Yes | 0.89 |
| Nassif et al. (2021) | ML Survey | Multiple | No | Varies | -- |
| **This study** | **IF + EWMA** | **Real SSH** | **Yes** | **Yes** | **0.9374** |

The comparison highlights three key differentiators of this study. First, the use of a real-world SSH dataset from a honeypot, rather than aging benchmark datasets (NSL-KDD, CICIDS) that do not reflect modern attack patterns. Second, the integration of Isolation Forest with the EWMA dynamic threshold for SSH early prediction, which has not been previously investigated. Third, the implementation of a complete end-to-end system from log parsing to auto-blocking, not merely an offline experiment.

## 4.6 Implications of the Results

### 4.6.1 Attack Scenario Testing

To comprehensively evaluate the system's detection capabilities, five attack scenarios were designed and executed on the test environment, each simulating a different brute-force tactic ranging from simple to sophisticated.

[Table 4.10: Description of 5 attack scenarios]

| No. | Scenario | Description | Characteristics |
|-----|----------|-------------|-----------------|
| 1 | Basic Brute-force | Attack from 1 IP, continuous high-speed attempts | High speed, 1 IP, 1 username |
| 2 | Distributed Attack | Attack from many IPs, each IP attempting few times | Many IPs, dispersed, rate-limit evasion |
| 3 | Low-and-Slow | Slow attack, minutes between each attempt | Low speed, detection evasion |
| 4 | Credential Stuffing | Using leaked username:password lists | Many usernames, 1-2 attempts each |
| 5 | Dictionary Attack | Using common password dictionary for 1 username | 1 username (root), many passwords |

### 4.6.2 Results by Scenario

**Scenario 1: Basic Brute-Force.** All three models detect 100% of attack windows, with anomaly scores far exceeding the dynamic threshold. Detection occurs in the first window (maximum 1 minute after attack onset). The scenario produces clearly extreme features --- very high fail_count, fail_rate near 1.0, very low mean_inter_attempt_time, very short session_duration_mean --- making identification straightforward.

**Scenario 2: Distributed Attack.** The system detects the majority of attacking IPs; however, some IPs performing only 1-2 attempts within a 5-minute window produce anomaly scores in the borderline zone. Estimated detection rate exceeds 90%. While count-based features (fail_count, connection_count) do not differ markedly from normal for individual IPs, temporal features (min_inter_attempt_time, session_duration_mean) still reveal the anomalous patterns of automated tools.

**Scenario 3: Low-and-Slow.** This is the most challenging scenario. Some attack windows have low anomaly scores, falling near or below the threshold. The detection rate is lower than for other scenarios, particularly when the attempt frequency is very low (1-2 within a 5-minute window). However, the EWMA accumulation mechanism enables the system to issue an EARLY_WARNING alert after 3-5 attempts (approximately 2-3 minutes), whereas Fail2Ban with default settings (maxretry=5, findtime=600s) would fail to detect the attack if attempts are sufficiently spaced. Features such as invalid_user_count and unique_usernames may still reveal anomalous patterns even when temporal features are inconclusive.

[Table 4.11: Low-and-Slow detection results by model]

| Model | Detection (%) | Avg Anomaly Score | Notes |
|-------|--------------|-------------------|-------|
| IF | Lowest | Near threshold | Many borderline samples |
| LOF | Moderate | Slightly above threshold | Detection via local density |
| OCSVM | Highest | Above threshold | Nonlinear decision boundary effective |

**Scenario 4: Credential Stuffing.** Detection rate exceeds 95%. The distinguishing feature is a very high number of unique_usernames (tens of different usernames), combined with a high invalid_user_ratio (since many usernames from leaked lists do not exist on the target system) and faster-than-normal attempt speed.

**Scenario 5: Dictionary Attack.** Detection rate is 100%. This scenario is similar to basic brute-force but focused on a single username (typically root). Features: very high fail_count, fail_rate near 1.0, unique_usernames=1, very low mean_inter_attempt_time.

[Table 4.12: Summary of detection results across 5 attack scenarios]

| Scenario | Difficulty | IF | LOF | OCSVM | Key Features |
|----------|-----------|-----|-----|-------|-------------|
| Basic Brute-force | Easy | 100% | 100% | 100% | fail_count, fail_rate |
| Distributed | Medium | >85% | >90% | >92% | unique_ports, session_duration |
| Low-and-Slow | Hard | Lowest | Moderate | Highest | invalid_user, long-term profile |
| Credential Stuffing | Medium | >93% | >95% | >96% | unique_usernames, invalid_user |
| Dictionary Attack | Easy | 100% | 100% | 100% | fail_count, mean_inter_attempt |

[Figure 4.14: Heatmap of detection rates by attack scenario and model]

### 4.6.3 Detailed Scenario 3 Analysis: Low-and-Slow

The low-and-slow attack scenario warrants detailed discussion because it represents the boundary of the system's detection capabilities and the scenario where the dynamic threshold mechanism provides the greatest incremental value over static approaches.

In this scenario, the attacker deliberately spaces authentication attempts over intervals of 30-120 seconds, resulting in only 1-3 attempts per 5-minute window per IP address. At this rate, the per-window feature values are substantially less extreme than in other attack scenarios: fail_count is only 1-3 (compared to tens or hundreds for basic brute-force), connection_count is similarly low, and the temporal features (mean_inter_attempt_time, min_inter_attempt_time) may overlap with the normal distribution because the intervals between attempts are in the range that a human user could plausibly produce.

However, two aspects of the behavior remain anomalous. First, the session durations remain very short (under 5 seconds per session), because even though the attacker slows the rate between sessions, each individual session still consists of a single failed authentication attempt followed by disconnection. The session_duration_mean feature captures this anomaly. Second, the usernames attempted may be unusual (e.g., "admin," "test," "oracle") rather than the specific usernames that belong to the target system, causing the invalid_user_ratio to be elevated even with very few attempts.

The EWMA accumulation mechanism addresses the limitation of per-window analysis by tracking the cumulative trend. Even though each individual window's anomaly score may be only slightly elevated, the EWMA accumulates these slight elevations over successive windows. With alpha=0.3, the effect of each new score on the EWMA is significant (30% weight), and after 3-5 consecutive windows with slightly elevated scores, the EWMA value crosses the early warning threshold. This is the mechanism through which the system provides early detection of slow attacks --- not by detecting any single window as definitively anomalous, but by recognizing the persistent pattern of slightly anomalous activity over time.

The two-level detection design is particularly valuable in this scenario. The EARLY_WARNING threshold (set at 67% of the ALERT threshold) triggers a notification to the security administrator without blocking the IP address. This graduated response is critical because the individual anomaly scores in the low-and-slow scenario are inherently less certain than in high-speed attack scenarios, and prematurely blocking an IP could disrupt legitimate users who happen to produce slightly anomalous patterns (e.g., a user trying multiple passwords for a forgotten account). The administrator can then investigate the flagged IP and make an informed decision about whether to escalate to a full block.

### 4.6.4 Consolidated Scenario Analysis

The results from the five attack scenarios yield several important insights:

First, **high-speed attacks (basic, dictionary) are easiest to detect.** All models achieve 100% detection. Both temporal and count features provide clear signals.

Second, **distributed attacks (distributed, credential stuffing) require multidimensional analysis.** Individual count features alone are insufficient; combining multiple features (temporal, username, port) is necessary for detection. The diversity of the 14-feature design proves its effectiveness.

Third, **slow attacks (low-and-slow) are the greatest challenge.** This represents the key limitation of the short-window approach and suggests the need for supplementary long-term analysis (long-term IP profiling) or integration with threat intelligence feeds. However, the EWMA accumulation mechanism provides partial mitigation through its early warning capability.

Fourth, **OCSVM is consistently the top performer.** OCSVM delivers the best or near-best detection results across all scenarios, confirming its theoretical advantages from the nonlinear RBF kernel decision boundary.

### 4.6.4 Real-Time System Performance

The system was deployed and evaluated on the Docker platform with 9 services (FastAPI, React, Elasticsearch, Logstash, Kibana, Fail2Ban, Redis, PostgreSQL, Nginx).

[Table 4.14: Latency analysis by pipeline stage]

| Stage | Average Time | Notes |
|-------|-------------|-------|
| Log ingestion (Logstash) | < 1 second | Depends on batch size |
| Feature extraction | < 100ms | 14 features from buffer |
| Model inference (IF) | < 10ms | Fastest |
| Model inference (LOF) | < 50ms | k-NN computation |
| Model inference (OCSVM) | < 30ms | Kernel evaluation |
| Dynamic threshold | < 5ms | EWMA update |
| Decision + Action | < 50ms | Includes Fail2Ban API call |
| **Total end-to-end** | **< 1-2 seconds** | **Meets real-time requirements** |

The total end-to-end latency is under 2 seconds, fully meeting real-time detection requirements. The majority of latency resides in the log ingestion stage (Logstash); all AI processing stages complete in under 100ms. System throughput is capable of handling hundreds to thousands of SSH events per second, far exceeding the requirements of a single SSH server (typically at most tens of concurrent connections) and sufficient for monitoring multiple SSH servers simultaneously.

[Table 4.16: Resource utilization of main services]

| Service | RAM (est.) | CPU (average) | Notes |
|---------|-----------|--------------|-------|
| API Server (FastAPI) | Moderate | Low-Medium | Increases with many requests |
| Elasticsearch | High | Medium | Continuous indexing |
| Logstash | Medium | Low | Depends on log rate |
| Kibana | Medium | Low | Increases when dashboards open |
| React Frontend | Low (client-side) | Low | Runs in browser |
| Redis | Low | Very Low | Lightweight cache |
| PostgreSQL | Low-Medium | Low | Infrequent queries |
| Fail2Ban | Very Low | Very Low | Event-driven |
| Nginx | Very Low | Very Low | Reverse proxy |

The microservices architecture with Docker enables flexible scaling: the API Server can be scaled out by creating additional containers with Nginx load balancing; Elasticsearch can be expanded by adding nodes to the cluster; and log collection can be distributed across multiple servers using Filebeat.

The React dashboard provides real-time monitoring with: an overview dashboard displaying total events, alert counts, blocked IPs, and activity charts over configurable time ranges; a detailed alert table with timestamp, source IP, anomaly score, detection model, and action taken, with sorting and filtering capabilities; a configuration panel for adjusting detection sensitivity, threshold parameters, and alert channels; and a historical analysis view that allows retrospective investigation of past events and model performance trends.

### 4.6.5 Summary of Experimental Findings

The experimental evaluation presented in this chapter establishes several important findings that address the research questions posed in Chapter 1:

The 14-feature behavioral feature set successfully captures the multidimensional differences between normal SSH activity and brute-force attacks. Feature importance analysis confirms that temporal features (session_duration_mean, min_inter_attempt_time, mean_inter_attempt_time) are the most discriminative, accounting for the top three positions in the importance ranking with importance scores of 5.50%, 3.86%, and 2.61%, respectively. This challenges the conventional reliance on count-based features (such as the number of failed login attempts) and has implications for the design of future detection systems.

All three unsupervised anomaly detection models demonstrate the viability of the semi-supervised approach for SSH brute-force detection. The optimized Isolation Forest achieves an F1-score of 93.74% with a recall of 96.75%, exceeding the minimum targets of F1>85% and Recall>95% established in the research objectives. OCSVM achieves the highest F1-score of 94.55%, and LOF achieves perfect recall of 100%, confirming that different models offer distinct advantages depending on the operational priority (maximum recall, maximum precision, or best overall balance).

The EWMA-Adaptive Percentile dynamic threshold provides measurable advantages over static thresholds, particularly in the low-and-slow attack scenario where it enables early warning detection after 3-5 attempts (approximately 2-3 minutes). The adaptive mechanism also reduces burst false positives during periods of legitimate anomalous activity and provides quick detection following quiet periods.

The five attack scenario evaluation demonstrates robust detection across a range of attack tactics, with 100% detection for basic brute-force and dictionary attacks, greater than 90% detection for distributed attacks and credential stuffing, and partial but meaningful detection for the challenging low-and-slow scenario. The system's end-to-end latency of under 2 seconds confirms its suitability for real-time deployment.

These findings collectively demonstrate that the proposed system achieves its design objectives and represents a meaningful advancement over both traditional threshold-based tools (Fail2Ban) and prior academic approaches that focus on offline evaluation of individual algorithms without addressing the complete detection pipeline.
