# CHAPTER 3: METHODOLOGY

## 3.1 Research Design

### 3.1.1 Overall System Architecture

The SSH brute-force attack detection and prevention system is designed following a microservices architecture, deployed on Docker with a total of 9 services operating in coordination. This architecture ensures scalability, maintainability, and flexible deployment in real-world environments.

[Figure 3.1: Overall system architecture for SSH brute-force attack detection]

The principal components of the system are organized into five functional layers:

**Data Collection Layer.** This layer is responsible for collecting authentication logs from SSH servers through log tailing and event forwarding mechanisms. Log data is standardized and ingested into the ELK Stack (Elasticsearch, Logstash, Kibana) for storage and indexing.

**Processing and Analysis Layer.** The central layer of the system comprises the data preprocessing module, the feature extraction module, and the AI model inference module. These modules are implemented as RESTful APIs using the FastAPI framework, enabling real-time request processing with high performance.

**Decision Layer.** This layer implements the dynamic threshold algorithm based on the EWMA-Adaptive Percentile method, combining anomaly scores from the AI models to render classification decisions: normal or attack.

**Response Layer.** Fail2Ban is integrated to automatically execute prevention measures upon attack detection, including IP address banning, email or webhook alert notifications, and event logging to the monitoring system.

**Presentation Layer.** A web interface developed in React provides a real-time monitoring dashboard displaying detection events, attack statistics, and administrative configuration controls.

[Table 3.1: List of 9 Docker services in the system]

| No. | Service | Technology | Function |
|-----|---------|-----------|----------|
| 1 | API Server | FastAPI (Python) | Business logic, model inference |
| 2 | Frontend | React | Monitoring and administration interface |
| 3 | Elasticsearch | ELK Stack | Log storage and indexing |
| 4 | Logstash | ELK Stack | Log collection and normalization |
| 5 | Kibana | ELK Stack | Data visualization |
| 6 | Fail2Ban | Fail2Ban | Automated IP blocking |
| 7 | Redis | Redis | Cache and message queue |
| 8 | Database | PostgreSQL | Configuration and results storage |
| 9 | Nginx | Nginx | Reverse proxy and load balancing |

[Figure 3.2: Data flow pipeline of the system]

The data processing pipeline operates as follows: (1) SSH authentication logs from the server are collected by Logstash; (2) Logstash parses and forwards the normalized logs to Elasticsearch; (3) the API Server periodically queries Elasticsearch or receives events via webhook to obtain new log data; (4) the preprocessing module performs feature extraction over the sliding time window; (5) the AI model computes anomaly scores; (6) the dynamic threshold algorithm compares the anomaly score against the current threshold; (7) if an attack is detected, the system triggers Fail2Ban and dispatches alerts; (8) results are displayed on the React dashboard.

### 3.1.2 Semi-Supervised Anomaly Detection Approach

The research adopts the semi-supervised anomaly detection paradigm, in which models are trained exclusively on normal data and subsequently identify patterns that deviate from the normal distribution as anomalies. This approach was selected for three reasons:

First, **practicality.** In practice, normal data is far easier to collect than labeled attack data. Organizations can readily collect logs of normal operations but cannot feasibly obtain samples of every possible attack type.

Second, **detection of novel attacks.** Semi-supervised models can detect attack types never previously encountered (zero-day attacks), provided that the attack behavior deviates from the learned normal patterns.

Third, **avoidance of class imbalance issues.** Supervised methods frequently suffer from class imbalance when the proportion of attacks is low. The semi-supervised approach is unaffected by this issue.

## 3.2 Data Collection Methods

### 3.2.1 Data Sources

The research employs two primary data sources to construct training and test datasets. The dual-source approach is a deliberate methodological choice that addresses the fundamental data challenge in anomaly detection: obtaining both clean normal data (for training) and diverse attack data (for evaluation). By combining a controlled simulation environment (which provides guaranteed-clean normal data) with a honeypot deployed on the public Internet (which provides authentic attack data), the study achieves a dataset that is both methodologically sound and practically representative.

The two data sources are described in detail below:

**Source 1 --- Honeypot data (honeypot_auth.log).** This authentication log was collected from an SSH honeypot server deployed on the public Internet. A honeypot is a system specifically designed to attract and record real-world attack activity, providing highly representative attack data.

- **Log lines:** 119,729
- **Collection duration:** 5 continuous days
- **Unique IP addresses:** 679
- **Failed password events:** 29,301
- **Accepted root logins (from admin IPs):** 532 from 6 verified administrative IP addresses
- **Hostname:** "mail"

The honeypot server was configured with SSH open on the default port (port 22), using the hostname "mail" to simulate a real email server and attract more brute-force attacks. During operation, only 6 administrative IP addresses were confirmed as legitimate; all other connections were classified as attack activity.

**Source 2 --- Simulation data (simulation_auth.log).** This authentication log was generated from a controlled simulation environment representing normal daily SSH activity within an organization.

- **Log lines:** 54,521
- **User accounts:** 64
- **Successful logins (Accepted):** 4,205
- **Failed authentication events (Failed):** 177
- **Hostname:** "if"

The simulation data was designed to reflect the behavioral patterns of legitimate users, including: logins during business hours, logins from multiple devices, accidental password mistyping, and sessions of varying duration.

[Table 3.2: Summary of two data sources]

| Attribute | honeypot_auth.log | simulation_auth.log |
|-----------|-------------------|---------------------|
| Log lines | 119,729 | 54,521 |
| Collection duration | 5 days | Continuous |
| Unique IPs | 679 | -- |
| User accounts | -- | 64 |
| Successful logins | 532 (root) | 4,205 |
| Failed logins | 29,301 | 177 |
| Hostname | "mail" | "if" |
| Data nature | Predominantly attack | Entirely normal |

### 3.2.2 Log Data Format

SSH log data conforms to the standard Linux syslog format, recorded in /var/log/auth.log. Each log line contains: timestamp, hostname, service name, process PID, and message content. The principal event types include:

- **Failed password:** Failed password authentication, containing username, source IP, and connection port.
- **Accepted password / Accepted publickey:** Successful authentication with analogous information.
- **Invalid user:** The attempted username does not exist on the system.
- **Connection closed / Connection reset:** Connection termination events.
- **PAM authentication failure:** Pluggable Authentication Module failure.
- **Maximum authentication attempts exceeded:** The per-session authentication limit was reached.

### 3.2.3 Labeling Strategy

Given the semi-supervised anomaly detection paradigm, the labeling strategy was carefully designed to ensure accuracy and compatibility with the training methodology:

**For simulation data (simulation_auth.log):** All data is labeled as **normal**. The simulation environment is fully controlled, and all activities are performed by legitimate users, including accidental password mistyping. This accurately reflects the reality that occasional password errors constitute normal user behavior.

**For honeypot data (honeypot_auth.log):** The labeling strategy is based on the list of 6 verified administrative IP addresses:
- Successful root login events (Accepted root) from the 6 admin IPs are labeled **normal**.
- All remaining events (including failed passwords, invalid users, and logins from unverified IPs) are labeled **attack**.

### 3.2.4 Data Splitting

Data is split following the semi-supervised learning paradigm:

**Training set:**
- Size: **7,212 samples**
- Composition: **100% normal** (exclusively normal samples)
- Source: 70% of simulation_auth.log data
- Purpose: Train models to learn normal behavior characteristics

**Test set:**
- Size: **15,184 samples**
- Composition: 3,796 normal + 11,388 attack samples
- Normal-to-attack ratio: **1:3**
- Source: Remaining 30% of simulation_auth.log (normal) + honeypot_auth.log data (attack and normal from admin IPs)

[Table 3.3: Dataset split summary]

| Dataset | Samples | Normal | Attack | Ratio |
|---------|---------|--------|--------|-------|
| Training | 7,212 | 7,212 (100%) | 0 (0%) | -- |
| Test | 15,184 | 3,796 (25%) | 11,388 (75%) | 1:3 |
| Total | 22,396 | 11,008 | 11,388 | -- |

## 3.3 Sampling Data Analysis Techniques

### 3.3.1 Feature Extraction via Sliding Window

Features are extracted using the sliding window method with the following parameters:

- **Window size:** 5 minutes
- **Stride:** 1 minute
- **Aggregation unit:** Per source IP address

Each 5-minute window for each IP address produces a 14-dimensional feature vector. The 5-minute window size was selected based on the following observations: it is sufficiently short to enable early detection of rapid brute-force attacks; it is sufficiently long to accumulate statistically meaningful behavioral information; and the 1-minute stride ensures high temporal resolution, allowing detection with a maximum delay of 1 minute.

[Figure 3.3: Illustration of the sliding window method (window=5 min, stride=1 min)]

### 3.3.2 Description of the 14 Features

The research designs 14 features reflecting different aspects of SSH authentication behavior within each time window, organized into five functional groups:

**Group 1: Authentication Count and Rate Features**

**1. fail_count (Number of failed authentication attempts).** The total number of failed password events from a given IP within the time window. This is the most fundamental and direct feature for identifying brute-force attacks, as attackers typically generate a large volume of incorrect password attempts.

**2. success_count (Number of successful authentication events).** The total number of successful authentication events. Legitimate users typically have a high success rate, while brute-force attackers rarely succeed.

**3. fail_rate (Failure rate).** The ratio of failed attempts to total authentication attempts: fail_rate = fail_count / (fail_count + success_count). Values approaching 1.0 indicate that nearly all attempts failed, characteristic of brute-force attacks. Normal users typically have fail_rate below 0.3.

**Group 2: Username-Related Features**

**4. unique_usernames (Number of distinct usernames).** The number of different usernames used in authentication attempts. Credential stuffing and dictionary attacks typically try many different usernames (root, admin, test, oracle, etc.), while legitimate users typically use only 1-2 accounts.

**5. invalid_user_count (Number of invalid user attempts).** The total number of login attempts with usernames that do not exist on the system. This is a clear indicator of an attack, as legitimate users know their own account names.

**6. invalid_user_ratio (Invalid user ratio).** The ratio of invalid user attempts to total authentication attempts. A high ratio indicates that the attacker is scanning the system with random or common username lists.

**Group 3: Connection and Temporal Features**

**7. connection_count (Total number of connections).** The total number of SSH connections (both successful and failed) from a given IP. Automated brute-force attacks typically generate a very large number of connections in a short period.

**8. mean_inter_attempt_time (Mean time between attempts, in seconds).** The average interval between consecutive authentication attempts. Automated attack tools typically have very short and uniform intervals (often under 1 second), while manual human users have longer and more variable intervals.

**9. std_inter_attempt_time (Standard deviation of inter-attempt time, in seconds).** A low standard deviation indicates a uniform behavioral pattern, characteristic of automated tools. A high standard deviation indicates irregular behavior, more likely from a manual human user.

**10. min_inter_attempt_time (Minimum time between attempts, in seconds).** The smallest interval between any two consecutive attempts. A value near zero indicates that at least one pair of attempts occurred nearly simultaneously, a hallmark of automated attacks.

**Group 4: Network and Session Features**

**11. unique_ports (Number of distinct source ports).** The number of different source ports used in connections from a given IP. Each new TCP connection typically uses a different random source port. A large number of unique ports correlates with a large number of distinct connections, reflecting the activity level of the IP.

**12. session_duration_mean (Mean session duration, in seconds).** The average duration of SSH sessions. Legitimate users typically have sessions lasting minutes to hours, while brute-force attacks produce very short sessions (under a few seconds), because each failed password attempt results in rapid disconnection.

**Group 5: Attack Indicator Features**

**13. pam_failure_escalation (PAM failure escalation).** A binary variable (0 or 1) indicating whether a continuously escalating sequence of PAM failures occurred within the time window. A value of 1 indicates systematic brute-force attack behavior with progressively increasing PAM failures.

**14. max_retries_exceeded (Maximum retries exceeded).** A binary variable indicating whether a "maximum authentication attempts exceeded" event occurred within the time window. This is a direct indicator of brute-force attacks, when the attacker attempts multiple passwords within a single connection session until the SSH server terminates the connection.

[Table 3.4: Summary of 14 features and their significance]

| No. | Feature | Data Type | Detection Significance |
|-----|---------|-----------|----------------------|
| 1 | fail_count | Integer | Number of incorrect password attempts |
| 2 | success_count | Integer | Number of successful logins |
| 3 | fail_rate | Float [0,1] | Failure-to-total ratio |
| 4 | unique_usernames | Integer | Diversity of attempted usernames |
| 5 | invalid_user_count | Integer | Non-existent username attempts |
| 6 | invalid_user_ratio | Float [0,1] | Proportion of invalid usernames |
| 7 | connection_count | Integer | Total SSH connections |
| 8 | mean_inter_attempt_time | Float (seconds) | Average speed between attempts |
| 9 | std_inter_attempt_time | Float (seconds) | Variability of attempt speed |
| 10 | min_inter_attempt_time | Float (seconds) | Fastest speed between attempts |
| 11 | unique_ports | Integer | Diversity of source ports |
| 12 | session_duration_mean | Float (seconds) | Average session length |
| 13 | pam_failure_escalation | Binary {0,1} | Escalating PAM failure sequence |
| 14 | max_retries_exceeded | Binary {0,1} | Maximum retry limit reached |

### 3.3.3 Temporal Feature Engineering Rationale

The design of the 14 features reflects a deliberate balance between comprehensiveness and computational efficiency. The features were selected to capture the four fundamental dimensions of SSH authentication behavior that differ between normal users and automated attack tools: the volume dimension (how many attempts are made), the diversity dimension (how varied the attempts are), the temporal dimension (how fast the attempts occur), and the session dimension (how long the connections last).

The temporal features (mean_inter_attempt_time, std_inter_attempt_time, min_inter_attempt_time) deserve particular attention because they capture the most fundamental difference between human and automated behavior. Human users interact with SSH servers at human timescales: typing a password takes several seconds, deciding to retry after a failure takes additional seconds, and the variability between attempts is high because human cognition is inherently inconsistent. Automated attack tools, in contrast, operate at machine timescales: password attempts are dispatched in milliseconds, the intervals between attempts are uniform (determined by network latency rather than human thought), and there is virtually no variability unless the tool is specifically configured to introduce randomization.

The session_duration_mean feature captures a related but distinct aspect of behavior. When a legitimate user connects via SSH, the session typically lasts from several minutes (for a quick administrative task) to several hours (for a development or deployment session). A brute-force attack, however, produces sessions of only a few seconds: the attacker connects, the authentication fails, the server terminates the connection, and the attacker immediately reconnects to try again. This extremely short session duration is a reliable indicator of automated attack behavior that is difficult for attackers to disguise, because the session duration is determined by the server's response time rather than the attacker's configuration.

The attack indicator features (pam_failure_escalation, max_retries_exceeded) provide binary signals that complement the continuous features. These features are based on specific events in the SSH authentication log that are almost exclusively associated with attack activity: an escalating sequence of PAM failures indicates a systematic brute-force attempt, and exceeding the maximum authentication retry limit indicates that the attacker is exhausting all permitted attempts within a single connection before reconnecting.

### 3.3.4 Feature Scaling

After extraction, features are normalized using **RobustScaler** from the scikit-learn library. RobustScaler was selected over StandardScaler or MinMaxScaler for the following reasons:

First, **robustness to outliers.** RobustScaler uses the median and interquartile range (IQR) rather than the mean and standard deviation, reducing the influence of outlier values in the data.

Second, **suitability for attack data.** Brute-force attack data frequently contains extreme values (e.g., fail_count can reach thousands while the normal value is 0-2). RobustScaler is unaffected by these extreme values.

The RobustScaler normalization formula is:

$$x_{scaled} = \frac{x - Q_2(x)}{Q_3(x) - Q_1(x)}$$

where Q1, Q2, and Q3 are the 25th, 50th (median), and 75th percentiles of the feature x, respectively. The scaler is fit on the training set (containing only normal data) and applied to transform both the training and test sets, ensuring no data leakage.

### 3.3.4 Model Selection and Configuration

Three anomaly detection models are selected and compared:

**Isolation Forest (IF).** Based on the isolation principle, where anomalous points are isolated more rapidly than normal points in random decision trees. The algorithm constructs an ensemble of isolation trees with random feature splits. The anomaly score is inversely proportional to the average path length from root to leaf. Advantages: high computational efficiency (O(n log n) complexity), suitability for high-dimensional data, and no distributional assumptions.

Optimized hyperparameters (baseline): n_estimators=300, max_samples=512, max_features=0.5 (7 of 14 features per tree).

Optimized hyperparameters (optimized configuration): contamination=0.01, max_features=0.75, max_samples=512, n_estimators=500.

**Local Outlier Factor (LOF).** Based on local density comparison, comparing the local density of each point with its k-nearest neighbors. Points with significantly lower local density than their neighbors are classified as anomalies. Hyperparameters: n_neighbors=30, novelty=True, metric=Minkowski.

**One-Class SVM (OCSVM).** Extends SVM for one-class classification by finding a maximum-margin hyperplane in the kernel-mapped feature space that separates training data from the origin. Hyperparameters: kernel=RBF, gamma=auto (1/14 approximately 0.0714), nu=0.01.

[Table 3.5: Comparison of characteristics of three models]

| Characteristic | Isolation Forest | LOF | OCSVM |
|---------------|-----------------|-----|-------|
| Principle | Isolation | Local density | Maximum-margin hyperplane |
| Complexity | O(n log n) | O(n^2) | O(n^2 to n^3) |
| Large data suitability | Excellent | Moderate | Moderate |
| Local anomaly detection | Moderate | Excellent | Good |
| Distributional assumptions | None | None | None (with kernel) |
| Interpretability | Moderate | Low | Low |

### 3.3.5 Dynamic Threshold Algorithm

The EWMA-Adaptive Percentile dynamic threshold algorithm is designed to address the limitations of static thresholds. The algorithm parameters are:

- alpha = 0.3: EWMA smoothing factor
- base_percentile = 95: Base percentile
- sensitivity_factor = 1.5: Sensitivity factor
- lookback = 100: Number of recent data points for computation

**Step 1: Compute EWMA of anomaly scores.** Given the anomaly score time series s_1, s_2, ..., s_t, the EWMA at time t is:

$$\mu_t^{EWMA} = \alpha \cdot s_t + (1 - \alpha) \cdot \mu_{t-1}^{EWMA}$$

with initialization mu_0 = s_1. The alpha=0.3 value ensures the EWMA responds quickly to recent changes while remaining robust to transient noise.

**Step 2: Compute the adaptive percentile.** Using a lookback window of L=100 most recent anomaly scores, compute the 95th percentile:

$$P_t = Percentile(\{s_{t-L+1}, ..., s_t\}, 95)$$

**Step 3: Compute the dynamic threshold.**

$$\theta_t = \mu_t^{EWMA} + sensitivity\_factor \times (P_t - \mu_t^{EWMA})$$

$$\theta_t = \mu_t^{EWMA} + 1.5 \times (P_t - \mu_t^{EWMA})$$

This formula places the threshold at the EWMA mean plus 1.5 times the distance from the EWMA to the 95th percentile, ensuring: the threshold lies above the vast majority (>95%) of normal scores when the distribution is stable; the EWMA rises during attack waves, pulling the threshold upward and preventing continuous false alarms; and the EWMA decreases after attacks subside, returning the threshold to normal levels.

**Step 4: Classification decision.** A sample at time t is classified as attack if s_t > theta_t, and normal otherwise.

[Figure 3.5: Illustration of the EWMA-Adaptive Percentile dynamic threshold algorithm]

[Table 3.6: Dynamic threshold algorithm parameters and their meanings]

| Parameter | Value | Meaning | Effect |
|-----------|-------|---------|--------|
| alpha | 0.3 | EWMA response speed | Large: fast response, more noise; Small: slow response, stable |
| base_percentile | 95 | Base percentile threshold | High: fewer FP, may miss attacks; Low: more FP, better detection |
| sensitivity_factor | 1.5 | Detection sensitivity | High: higher threshold, fewer alerts; Low: lower threshold, more alerts |
| lookback | 100 | Recent sample count | Large: stable, slow adaptation; Small: responsive, fast adaptation |

### 3.3.6 Training Process

The training process follows the semi-supervised novelty detection paradigm in four sequential steps:

**Step 1 --- Data preparation.** Only the 7,212 normal samples from 70% of the simulation data are used for training. This ensures that the models learn exclusively from legitimate behavior patterns, with no contamination from attack data.

**Step 2 --- Normalization.** The RobustScaler is fit on the training set, and the transformation is applied to both the training and test sets. This approach prevents data leakage: the scaler parameters are derived solely from the training data, and the same transformation is applied consistently to all data.

**Step 3 --- Model training.** Each of the three models (IF, LOF, OCSVM) is fit on the normalized training set. The Isolation Forest constructs 300 isolation trees (baseline) or 500 trees (optimized), each using 512 sub-samples and 50% (baseline) or 75% (optimized) of the 14 features. The LOF model computes the local reachability density for each training point using 30 nearest neighbors. The OCSVM model solves the quadratic optimization problem to find the maximum-margin hyperplane in the RBF kernel space.

**Step 4 --- Prediction and evaluation.** Anomaly scores are computed for each of the 15,184 test samples. The scores are then compared against the classification threshold (either static or dynamic) to produce binary predictions (normal/attack). Performance is evaluated using the five metrics defined in Section 3.3.5 (Accuracy, Precision, Recall, F1-Score, ROC-AUC).

The hyperparameter optimization process uses grid search combined with cross-validation on the training set. Since the training set contains only normal data, the optimization criterion is based on the model's ability to reconstruct the normal data distribution and the ROC-AUC score on a small validation set containing a subset of attack samples.

For the Isolation Forest, the grid search explores: n_estimators in {100, 200, 300, 500}, max_samples in {256, 512, 1024}, max_features in {0.25, 0.5, 0.75, 1.0}, and contamination in {auto, 0.01, 0.05, 0.1}. The use of max_features=0.5 (baseline) or 0.75 (optimized) increases diversity among the trees in the ensemble, reducing the risk of overfitting. The max_samples=512 parameter limits the sub-sample size per tree, which accelerates training and improves anomaly detection according to Isolation Forest theory (anomalous points are more easily isolated in smaller samples). The n_estimators=300 (baseline) or 500 (optimized) ensures sufficient tree count to stabilize the anomaly score.

For LOF, the n_neighbors=30 value balances between local anomaly detection sensitivity (lower k) and estimation stability (higher k). The novelty=True setting enables the model to predict on new data points not seen during training. For OCSVM, the nu=0.01 parameter sets the upper bound on the outlier fraction at 1%, consistent with the assumption that the training set is purely normal and allows at most 1% of samples to be misclassified. The gamma=auto setting automatically computes gamma = 1/n_features = 1/14, approximately 0.0714.

## 3.4 Limitations of the Methodology

### 3.4.1 Real-Time Detection Pipeline

The real-time detection pipeline is designed for continuous processing of SSH log event streams with minimal latency. The pipeline comprises five stages:

The pipeline is designed to process SSH log events as they arrive with minimal latency, ensuring that detection and response occur within seconds of the original authentication event. Each stage is optimized for its specific computational requirements, with I/O-bound stages using asynchronous processing and CPU-bound stages using parallel execution.

**Stage 1 --- Ingestion.** Logstash tails the auth.log file on SSH servers, parses each new log line, and sends structured events to Elasticsearch. Simultaneously, a webhook/event stream forwards events to the API Server.

**Stage 2 --- Aggregation.** The API Server maintains per-IP sliding window buffers. At each 1-minute stride, the system aggregates events from the most recent 5-minute window to compute the 14 features.

**Stage 3 --- Scoring.** The feature vector is normalized using the pre-fitted RobustScaler and fed into the AI model to compute the anomaly score. All three models (IF, LOF, OCSVM) can operate in parallel or in an ensemble configuration.

**Stage 4 --- Decision.** The anomaly score is compared against the current dynamic threshold theta_t. Simultaneously, the EWMA-Adaptive Percentile algorithm updates the threshold based on the newly received score.

**Stage 5 --- Action.** If an attack is detected, the system triggers prevention actions.

[Figure 3.6: Five-stage real-time detection pipeline]

To ensure real-time performance, the pipeline employs: asynchronous processing (async/await) via FastAPI for I/O-bound tasks such as Elasticsearch queries and database writes; parallel processing through thread pools or process pools for CPU-bound tasks such as model computation; and Redis caching for intermediate results including scaler parameters, model objects, and per-IP sliding window states.

### 3.4.2 Fail2Ban Integration and Alert System

When the detection module identifies an IP as conducting a brute-force attack, the system invokes the Fail2Ban API to: (1) ban the IP address, blocking all new connections from that IP; (2) apply a configurable ban duration based on the severity of the attack; and (3) implement progressive banning, where repeated offenders receive exponentially increasing ban durations.

The multi-channel alert system supports: real-time alert display on the React dashboard with IP information, timestamp, anomaly score, predicted attack type, and action taken; webhook notifications to external services (Slack, Telegram, etc.); and comprehensive logging of all detection events and response actions to Elasticsearch for post-incident analysis.

An administrator feedback mechanism allows security personnel to mark alerts as true positive or false positive through the React interface. This feedback is stored and can be used for future model refinement or threshold parameter adjustment.

### 3.4.3 Evaluation Metrics

Performance evaluation is based on the standard binary classification confusion matrix (normal vs. attack):

**Accuracy** = (TP + TN) / (TP + TN + FP + FN), measuring the overall correct classification rate. In imbalanced scenarios, accuracy may not accurately reflect model performance.

**Precision** = TP / (TP + FP), measuring the proportion of predicted attacks that are actual attacks. High precision indicates few false alarms.

**Recall (Sensitivity)** = TP / (TP + FN), measuring the proportion of actual attacks that are detected. In cybersecurity, recall is particularly critical because missing an attack (false negative) can have severe consequences.

**F1-Score** = 2 * (Precision * Recall) / (Precision + Recall), the harmonic mean of Precision and Recall, providing a balanced measure.

**ROC-AUC**, the area under the Receiver Operating Characteristic curve, measures the model's ability to discriminate between normal and attack classes across all classification thresholds. ROC-AUC=1.0 is ideal; ROC-AUC=0.5 is equivalent to random classification.

[Table 3.7: Summary of evaluation metrics and their security significance]

| Metric | Security Significance | Priority |
|--------|----------------------|----------|
| Accuracy | Overall performance | Medium |
| Precision | Reducing false alarms (alert fatigue) | High |
| Recall | Not missing attacks | Very High |
| F1-Score | Precision-Recall balance | High |
| ROC-AUC | General discriminative ability | High |

Additionally, system-level performance metrics are evaluated: latency (time from log event receipt to classification decision), throughput (events processed per unit time), memory usage, and CPU usage. These metrics ensure the system can operate under real-world production requirements.

### 3.4.4 Experimental Design for Attack Scenario Evaluation

To evaluate the system comprehensively, five attack scenarios were designed to cover the major categories of SSH brute-force attacks observed in the wild. Each scenario is defined by a specific set of parameters that control the attack behavior, including the rate of attempts, the number of source IP addresses, the username selection strategy, and the password selection strategy.

**Scenario 1: Basic Brute-Force.** A single IP address attempts to authenticate as root (or another target account) at the maximum possible rate. The attacker uses a systematically generated list of passwords, sending attempts as fast as the network and SSH server will permit. This scenario produces the most extreme feature values and serves as the baseline for evaluating detection capability. The expected detection rate is 100% for all models.

**Scenario 2: Distributed Attack.** Multiple IP addresses (simulating a botnet) each attempt a small number of authentication attempts, distributing the total attack volume across many sources. Each IP may attempt only 2-5 passwords before moving on to the next target server, or cycling back at a later time. The challenge for the detection system is that per-IP feature values may fall within the range of normal behavior. Detection relies on the temporal and session features that remain anomalous even at low per-IP volumes, because automated tools still produce characteristically short sessions and machine-speed timing patterns.

**Scenario 3: Low-and-Slow.** A single IP address spaces its authentication attempts over long intervals (30-120 seconds between attempts), deliberately staying below traditional rate-limiting thresholds. This is the most sophisticated evasion technique in the brute-force attacker's repertoire, and it represents the greatest challenge for any detection system based on short-term behavioral analysis. The EWMA accumulation mechanism is specifically designed to address this scenario by detecting the cumulative build-up of anomalous activity over multiple detection windows.

**Scenario 4: Credential Stuffing.** The attacker uses a database of username-password pairs leaked from breaches at other services, testing each pair against the target SSH server. The distinguishing characteristic of this attack is the large number of unique usernames, many of which do not exist on the target system. The unique_usernames and invalid_user_ratio features are expected to be the primary discriminators.

**Scenario 5: Dictionary Attack.** A single IP address targets a specific account (typically root) using a dictionary of common passwords. This scenario is similar to basic brute-force but more realistic, as real-world attackers typically use curated password lists rather than exhaustive enumeration. The attack proceeds at high speed with a single username.

The scenarios were implemented as Python scripts using the Paramiko SSH library, which provides programmatic control over SSH client connections and enables precise manipulation of timing, username selection, and password selection parameters. Each scenario was executed against the test environment and the resulting SSH log data was processed through the complete detection pipeline.

### 3.4.5 Ethical Considerations

The data collection methodology raises several ethical considerations that were addressed in the research design. The honeypot data was collected from a purpose-built honeypot server specifically designed to attract and record attack traffic. No legitimate user data was collected or compromised during the honeypot operation. The 6 administrative IP addresses that produced legitimate traffic on the honeypot were under the full control of the research team, and all data was handled in accordance with responsible research practices.

The simulation data was generated synthetically, with no real user data involved. The 64 simulated user accounts and their behavioral patterns were designed to represent realistic but entirely fictional usage scenarios. No actual user credentials, IP addresses, or session data from real individuals were used in the simulation.

The attack scenario testing was conducted entirely within a controlled test environment isolated from production systems. No unauthorized access attempts were made against any external systems. The attack simulation scripts are documented for reproducibility but are not distributed publicly in executable form to prevent misuse.

### 3.4.6 Methodological Constraints

The methodology has several inherent constraints that should be noted. The 5-minute sliding window, while effective for detecting rapid and moderate-speed attacks, may be insufficient for detecting extremely slow attacks where the attacker spaces attempts over intervals exceeding the window size. This limitation suggests the need for supplementary long-term IP profiling or integration with threat intelligence feeds.

The semi-supervised training approach assumes that the training data is purely normal. Any contamination of the training set with attack samples could degrade model performance. The labeling strategy was designed to minimize this risk, but absolute purity cannot be guaranteed in all deployment scenarios.

The RobustScaler normalization is fit on the training data, which represents a single operational environment. When deploying to a new environment with different usage patterns, the scaler and model should be retrained on data representative of that environment.

Finally, the evaluation is conducted on a specific dataset with a fixed normal-to-attack ratio of 1:3. Performance may vary under different ratios or in environments with significantly different traffic patterns. The dynamic threshold mechanism is designed to mitigate this sensitivity, but comprehensive evaluation across diverse environments remains an area for future work.
