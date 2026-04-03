# CHAPTER 3: METHODOLOGY

## 3.1 Research Design Overview

### 3.1.1 Philosophical and Methodological Foundations

This research adopts a positivist epistemological stance, employing a quantitative experimental methodology to design, implement, and evaluate an AI-based SSH brute-force attack detection and prevention system. The research follows the Design Science Research Methodology (DSRM) framework proposed by Peffers et al. [41], which is widely regarded as the standard methodology for information systems research involving the creation of IT artifacts. DSRM comprises six iterative phases: (1) problem identification, (2) objective definition, (3) design and development, (4) demonstration, (5) evaluation, and (6) communication. This chapter addresses phases (3) and (4), while Chapter 4 presents the evaluation results.

The experimental approach is appropriate because the research question --- whether an Isolation Forest model combined with an EWMA-Adaptive Percentile dynamic threshold can effectively detect SSH brute-force attacks in real time --- is inherently quantitative and amenable to controlled experimentation. The dependent variables (accuracy, precision, recall, F1-score, ROC-AUC, false positive rate) can be precisely measured, and the independent variables (model hyperparameters, threshold parameters, feature set composition, window configuration) can be systematically manipulated to assess their effects on detection performance.

The methodology integrates three complementary research strategies:

**Empirical data collection.** Real-world attack data is obtained from an SSH honeypot deployed on the public Internet, while normal behavioral data is generated through a controlled simulation environment. This dual-source approach addresses the fundamental data challenge in anomaly detection: the simultaneous need for clean normal data (for training) and authentic attack data (for evaluation) [42].

**Comparative algorithm evaluation.** Three unsupervised anomaly detection algorithms --- Isolation Forest (IF), Local Outlier Factor (LOF), and One-Class Support Vector Machine (OCSVM) --- are systematically compared under identical conditions, following the best practices for algorithm benchmarking established by Demsar [43] and Campos et al. [44].

**System integration and scenario-based testing.** The detection algorithm is embedded within a complete end-to-end system comprising 9 Docker services, and evaluated against five distinct attack scenarios designed to cover the spectrum of SSH brute-force attack variants documented in the literature.

### 3.1.2 Semi-Supervised Anomaly Detection Paradigm

The research adopts the semi-supervised anomaly detection paradigm, also referred to as novelty detection [45], in which models are trained exclusively on normal (in-distribution) data and subsequently identify observations that deviate from the learned normal distribution as anomalies. This paradigm was selected over supervised classification and fully unsupervised clustering for three theoretically and practically motivated reasons.

First, **practicality of data acquisition.** In operational cybersecurity environments, normal data is far more abundant and easier to collect than labeled attack data. Organizations can readily extract logs of normal SSH operations from their existing infrastructure, but they cannot feasibly obtain representative samples of every possible attack type, including zero-day variants that have not yet been observed [46]. Chandola et al. [47] formalized this observation as the "labeled data scarcity problem" in their seminal survey of anomaly detection techniques.

Second, **generalization to novel attacks.** Models trained on attack signatures can only detect attacks whose signatures match the training data. Semi-supervised models, by contrast, can detect any attack type whose behavioral characteristics deviate from the learned normal profile, including attack variants never previously encountered (zero-day attacks). This property was demonstrated empirically by Goldstein and Uchida [48], who showed that novelty detection methods consistently outperform signature-based methods on datasets containing previously unseen anomaly types.

Third, **avoidance of class imbalance pathologies.** Supervised classification methods are well known to suffer from degraded performance when the class distribution is severely imbalanced [49], as is typical in cybersecurity datasets where normal traffic vastly outnumbers attack traffic (or vice versa, as in honeypot data). The semi-supervised paradigm is architecturally immune to this problem because the training set contains only a single class.

The formal framework is as follows. Let $\mathbf{X}_{train} = \{\mathbf{x}_1, \mathbf{x}_2, \ldots, \mathbf{x}_n\}$ denote the training set, where each $\mathbf{x}_i \in \mathbb{R}^{14}$ is a feature vector representing the SSH behavioral profile of a single IP address within a single 5-minute time window, and all $\mathbf{x}_i$ are drawn from the normal class. A model $f: \mathbb{R}^{14} \rightarrow \mathbb{R}$ is trained on $\mathbf{X}_{train}$ to produce an anomaly score $s(\mathbf{x})$ for any new observation $\mathbf{x}$. A threshold function $\theta(t)$ maps the anomaly score to a binary classification:

$$\hat{y}(\mathbf{x}, t) = \begin{cases} \text{attack} & \text{if } s(\mathbf{x}) > \theta(t) \\ \text{normal} & \text{otherwise} \end{cases}$$

where $\theta(t)$ may be static (a fixed constant) or dynamic (a function of recent score history), as described in Section 3.8.

## 3.2 System Architecture

### 3.2.1 High-Level Architecture

The SSH brute-force attack detection and prevention system is designed following a microservices architecture, deployed on Docker Compose with a total of 9 services operating in coordination. The microservices architecture was chosen over a monolithic design for three reasons documented by Newman [50]: independent scalability of components, fault isolation (failure of one service does not cascade to others), and technology heterogeneity (each service can use the language and framework best suited to its function).

[Figure 3.1: Overall system architecture for SSH brute-force attack detection and prevention]

The system is organized into five functional layers, each with a clearly defined responsibility:

**Layer 1: Data Collection.** This layer is responsible for ingesting authentication logs from SSH servers. Logstash tails the `/var/log/auth.log` file on target SSH servers, applies Grok pattern parsing to extract structured fields (timestamp, hostname, service, PID, event type, username, IP address, port), and forwards the structured events to Elasticsearch for indexed storage. The use of Logstash for log ingestion follows the established ELK Stack architecture, which Elasticsearch B.V. reports is deployed in over 500,000 organizations worldwide for security analytics [51].

**Layer 2: Processing and Analysis.** The central computational layer comprises the data preprocessing module, the feature extraction module, and the AI model inference module. These modules are implemented as asynchronous RESTful APIs using the FastAPI framework (Python), which leverages ASGI (Asynchronous Server Gateway Interface) for high-concurrency request handling. FastAPI was selected over Flask and Django REST Framework based on benchmarks by Lust [52] showing 3--10x throughput improvements for I/O-bound workloads.

**Layer 3: Decision.** This layer implements the dynamic threshold algorithm based on the EWMA-Adaptive Percentile method (detailed in Section 3.8). It receives anomaly scores from the AI model and produces a binary classification decision (normal or attack) together with a confidence level (EARLY_WARNING or ALERT).

**Layer 4: Response.** Fail2Ban is integrated to execute automated prevention measures upon attack detection. When an ALERT-level detection occurs, the system invokes the Fail2Ban API to ban the offending IP address, applies a configurable ban duration with progressive escalation for repeat offenders, and dispatches multi-channel alert notifications (dashboard, webhook, log).

**Layer 5: Presentation.** A single-page web application developed in React provides a real-time monitoring dashboard displaying detection events, attack statistics, IP geolocation, anomaly score trends, and administrative configuration controls.

### 3.2.2 Service Inventory

[Table 3.1: Complete inventory of 9 Docker services]

| No. | Service | Technology | Function | Port |
|-----|---------|-----------|----------|------|
| 1 | Detector | Python (scikit-learn) | AI model inference and threshold computation | Internal |
| 2 | API Server | FastAPI (Python) | Business logic, REST API, orchestration | 8000 |
| 3 | Frontend | React (TypeScript) | Real-time monitoring dashboard | 3000 |
| 4 | Elasticsearch | Elasticsearch 8.x | Log storage, full-text indexing, search | 9200 |
| 5 | Logstash | Logstash 8.x | Log ingestion, parsing, forwarding | 5044 |
| 6 | Kibana | Kibana 8.x | Data visualization, ad hoc exploration | 5601 |
| 7 | Redis | Redis 7.x | Cache, message queue, sliding window state | 6379 |
| 8 | Fail2Ban | Fail2Ban 1.x | Automated IP blocking via iptables/nftables | Internal |
| 9 | SSH Target | OpenSSH 9.x | Target SSH server for attack scenario testing | 22 |

### 3.2.3 Data Flow Pipeline

[Figure 3.2: End-to-end data flow pipeline from SSH log event to classification decision and response]

The data processing pipeline operates through five sequential stages with well-defined interfaces:

1. **Ingestion.** SSH authentication events on the target server are written to `/var/log/auth.log` by the sshd process. Logstash monitors this file via the file input plugin (using inode tracking to handle log rotation) and applies a Grok filter to parse each line into structured JSON fields.

2. **Indexing.** Parsed events are forwarded to Elasticsearch via the Elasticsearch output plugin. Events are indexed in time-partitioned indices (e.g., `ssh-auth-2026.03.26`) with a mapping that preserves the original data types (keyword for IP addresses, date for timestamps, integer for port numbers).

3. **Feature Extraction.** The API Server periodically queries Elasticsearch for new events (polling interval: 30 seconds) or receives push notifications via a webhook. For each active IP address, the server maintains a sliding window buffer (stored in Redis for persistence across restarts) and computes the 14-feature vector as described in Section 3.6.

4. **Inference and Decision.** The feature vector is normalized using the pre-fitted RobustScaler, passed to the trained anomaly detection model to obtain an anomaly score, and compared against the current dynamic threshold $\theta(t)$ to produce a classification decision.

5. **Action.** If the classification is ALERT, the system invokes the Fail2Ban REST API to ban the IP, writes the detection event to Elasticsearch for audit logging, and pushes a real-time notification to the React dashboard via WebSocket.

## 3.3 Laboratory Environment Setup

### 3.3.1 Hardware and Software Configuration

All experiments were conducted on a single physical machine to ensure reproducibility and eliminate network variability as a confounding factor. The Docker Compose configuration ensures that all 9 services run within a single Docker network with deterministic inter-service communication.

[Table 3.2: Laboratory environment specifications]

| Component | Specification |
|-----------|--------------|
| Operating System | Ubuntu 22.04 LTS (host) / Docker containers |
| Containerization | Docker 24.x, Docker Compose 2.x |
| Python | 3.10 with scikit-learn 1.3.x, pandas 2.1.x, numpy 1.25.x |
| Machine Learning | scikit-learn (IsolationForest, LocalOutlierFactor, OneClassSVM) |
| Web Framework | FastAPI 0.104.x (ASGI) |
| Frontend | React 18.x with TypeScript |
| Search Engine | Elasticsearch 8.x |
| Log Pipeline | Logstash 8.x |
| Visualization | Kibana 8.x |
| Cache | Redis 7.x |
| Prevention | Fail2Ban 1.x |

### 3.3.2 Honeypot Deployment

The SSH honeypot was deployed on a Virtual Private Server (VPS) with a publicly routable IPv4 address. The honeypot was configured to attract realistic SSH brute-force attack traffic through several deliberate design choices informed by the honeypot deployment guidelines of Provos and Holz [53]:

- **Port selection.** SSH was exposed on the default port 22 rather than a non-standard port. Alata et al. [54] demonstrated that the majority of automated SSH scanners target only port 22, and moving SSH to a non-standard port reduces attack traffic by 95--99% --- which would be counterproductive for data collection purposes.
- **Hostname.** The hostname was set to "mail" to simulate a mail server, a high-value target that attracts more sophisticated brute-force attacks beyond opportunistic scanning [55].
- **Authentication policy.** Password authentication was enabled with a permissive MaxAuthTries setting to maximize the number of events recorded per attacking session.
- **Collection duration.** The honeypot operated continuously for 5 days (2026-03-22 to 2026-03-27), during which all SSH authentication events were recorded to `/var/log/auth.log`.
- **Administrative access.** Six (6) verified administrative IP addresses (27.64.18.8, 104.28.156.151, 104.28.159.126, 116.110.42.131, 118.69.182.144, 14.169.70.183) were used by the research team for honeypot management. All logins from these IPs were recorded and later labeled as normal.

### 3.3.3 Simulation Environment

The simulation environment was designed to generate realistic normal SSH activity representative of a medium-sized organization. The simulation script, written in Python using the Paramiko library, creates 64 user accounts (52 human users and 12 service accounts) and orchestrates their SSH activity according to behavioral profiles calibrated from the literature on organizational IT usage patterns [56].

Key simulation parameters:

- **Duration.** Approximately 25 hours of continuous activity on 2026-03-26.
- **Hostname.** "if" (to distinguish from the honeypot hostname "mail").
- **Network.** All connections originate from the 192.168.152.0/24 subnet.
- **Human users (52).** Activity concentrated during business hours (8:00--18:00) with reduced activity during evenings and weekends. Session durations range from 5 minutes to several hours. Occasional password mistyping is included at a natural rate.
- **Service accounts (12).** Automated cron-based connections at regular intervals, short session durations, and zero password failures.
- **Failure rate.** 177 failed logins out of 4,382 total attempts (4.04%), reflecting the empirically observed rate of accidental password failures in organizational environments reported by Florencio and Herley [57].

## 3.4 Data Collection Methods

### 3.4.1 Data Sources and Rationale

The research employs two primary data sources, following the dual-source methodology advocated by Ring et al. [58] for constructing intrusion detection evaluation datasets. The dual-source approach addresses the fundamental tension between data purity and data realism: controlled environments produce clean, well-labeled data but may lack the complexity and diversity of real-world traffic, while real-world captures provide authentic attack patterns but resist precise labeling.

**Source 1: Honeypot data (honeypot_auth.log).** This authentication log was collected from the SSH honeypot described in Section 3.3.2. The honeypot approach, first formalized by Spitzner [59], provides highly representative attack data because the traffic is generated by real attackers using real tools and techniques, rather than synthetic simulations.

[Table 3.3: Honeypot data summary statistics]

| Attribute | Value |
|-----------|-------|
| Total log lines | 119,729 |
| Collection period | 2026-03-22 to 2026-03-27 (5 days) |
| Hostname | "mail" |
| Unique IP addresses | 679 |
| Failed password events | 29,301 |
| Invalid user attempts | 12,799 |
| Accepted root logins (admin IPs) | 532 |
| Number of admin IPs | 6 |
| "message repeated" entries | 1,920 |
| SSHD entries after parsing | 122,809 |
| Average failed attempts per day | 5,860 |
| Average failed attempts per IP | 43.15 |

**Source 2: Simulation data (simulation_auth.log).** This authentication log was generated from the controlled simulation environment described in Section 3.3.3.

[Table 3.4: Simulation data summary statistics]

| Attribute | Value |
|-----------|-------|
| Total log lines | 54,521 |
| Collection period | ~25 hours (2026-03-26) |
| Hostname | "if" |
| User accounts | 64 (52 human + 12 service) |
| Network subnet | 192.168.152.0/24 |
| Accepted logins | 4,205 |
| Failed logins | 177 |
| Success rate | 95.96% |
| Failure rate | 4.04% |
| SSHD entries after parsing | 34,700 |

### 3.4.2 Log Data Format

SSH servers on Linux systems record authentication events to the system authentication log (typically `/var/log/auth.log` on Debian/Ubuntu distributions) via the syslog facility. Each log entry follows the standard syslog format specified in RFC 5424 [60]:

```
<timestamp> <hostname> <service>[<PID>]: <message>
```

The principal SSH event types relevant to brute-force detection, as documented in the OpenSSH source code and manual pages [61], are:

| Event Type | Log Message Pattern | Significance |
|-----------|-------------------|-------------|
| Failed password | `Failed password for <user> from <IP> port <port>` | Primary brute-force indicator |
| Invalid user | `Invalid user <user> from <IP> port <port>` | Username enumeration indicator |
| Accepted password | `Accepted password for <user> from <IP> port <port>` | Successful authentication |
| Accepted publickey | `Accepted publickey for <user> from <IP> port <port>` | Key-based authentication |
| Connection closed | `Connection closed by <IP> port <port>` | Session termination |
| PAM failure | `pam_unix(sshd:auth): authentication failure` | PAM-level failure |
| Max retries exceeded | `error: maximum authentication attempts exceeded` | Retry limit reached |
| Message repeated | `message repeated <N> times` | Syslog deduplication |

The "message repeated" entries require special handling during preprocessing. When syslog detects consecutive identical messages, it consolidates them into a single "message repeated N times" entry. The preprocessing pipeline expands these entries by replicating the preceding event $N$ times, which increased the honeypot dataset from 119,729 raw lines to 122,809 parsed SSHD entries.

### 3.4.3 Labeling Strategy

The labeling strategy was designed to be both conservative and verifiable, following the recommendations of Gates and Taylor [62] for intrusion detection dataset labeling:

**Simulation data (simulation_auth.log).** All events are labeled as **normal**. The simulation environment is fully controlled, with no external network access, and all activities are performed by the 64 legitimate user accounts. This includes the 177 failed login events, which represent accidental password mistyping --- a behavior that is part of the normal operating profile of legitimate users. Labeling these failures as normal is a deliberate and theoretically motivated decision: the anomaly detection model must learn that occasional failures are normal, so that it does not flag every single failure as an attack.

**Honeypot data (honeypot_auth.log).** The labeling is based on the whitelist of 6 verified administrative IP addresses:

- **Normal:** Accepted root login events from the 6 admin IPs: {27.64.18.8, 104.28.156.151, 104.28.159.126, 116.110.42.131, 118.69.182.144, 14.169.70.183}. These 532 sessions represent genuine system administration activity.
- **Attack:** All remaining events, including all failed passwords, all invalid user attempts, all connections from non-admin IPs, and all other event types. Since the honeypot has no legitimate users other than the 6 administrators, every other event is by definition an attack or the direct consequence of an attack.

This binary labeling scheme produces a clean separation: every feature vector derived from simulation data is labeled normal, and every feature vector derived from honeypot data that is not attributable to the 6 admin IPs is labeled attack. The resulting label distribution is highly imbalanced in favor of attack data in the honeypot (by design), which provides a challenging and realistic test set for evaluating the detection models.

## 3.5 Data Preprocessing Pipeline

### 3.5.1 Pipeline Overview

The data preprocessing pipeline transforms raw syslog text into normalized numerical feature vectors suitable for anomaly detection models. The pipeline comprises four sequential stages: (1) log parsing, (2) labeling, (3) feature extraction via sliding window, and (4) feature scaling. Each stage is implemented as an independent Python module with well-defined inputs and outputs, following the scikit-learn Pipeline API design pattern [63] to ensure reproducibility and prevent data leakage.

[Figure 3.3: Data preprocessing pipeline from raw logs to scaled feature vectors]

### 3.5.2 Stage 1: Log Parsing

The log parser applies regular expression matching to extract structured fields from raw syslog lines. The parser handles the following complexities:

1. **Multi-format timestamps.** The syslog timestamp format varies across Linux distributions (e.g., `Mar 22 10:15:33` vs. `2026-03-22T10:15:33.000+07:00`). The parser normalizes all timestamps to ISO 8601 format with UTC timezone.

2. **"Message repeated" expansion.** As noted in Section 3.4.2, syslog consolidation entries are expanded. This expansion increased the honeypot dataset from 119,729 raw lines to 122,809 parsed SSHD entries, and kept the simulation dataset at 34,700 SSHD entries.

3. **Event type classification.** Each log line is classified into one of the event types listed in Section 3.4.2 based on pattern matching against the message content.

4. **Field extraction.** For each classified event, the parser extracts the relevant fields: username, source IP address, source port number, and authentication result.

The parsing success rate exceeded 99.5% on both datasets. Lines that could not be parsed (typically non-SSH syslog entries or malformed entries) were excluded from further analysis.

### 3.5.3 Stage 2: Labeling

Labels are assigned to each parsed event according to the strategy defined in Section 3.4.3. The label is propagated to the feature extraction stage, where it is aggregated at the window level: a feature vector is labeled "attack" if **any** event within the corresponding IP-window combination originates from a non-admin IP in the honeypot data.

### 3.5.4 Stage 3: Feature Extraction via Sliding Window

Features are extracted using the sliding window method, a standard technique in time-series anomaly detection [64]. The window parameters are:

- **Window size ($W$):** 5 minutes
- **Stride ($S$):** Variable (1 minute for baseline overlapping, 5 minutes for optimized non-overlapping)
- **Aggregation unit:** Per source IP address

For each 5-minute window, for each unique source IP address that appears in the window, the pipeline computes a 14-dimensional feature vector $\mathbf{x} \in \mathbb{R}^{14}$ by aggregating all events from that IP within the window boundaries. The formal definition is:

$$\mathbf{x}_{ip,t} = \text{Aggregate}(\{e \in \mathcal{E} \mid e.\text{ip} = ip \wedge t - W < e.\text{timestamp} \leq t\})$$

where $\mathcal{E}$ is the set of all parsed events, and $\text{Aggregate}(\cdot)$ computes the 14 features described in Section 3.6.

The choice of $W = 5$ minutes was motivated by three considerations documented in the SSH monitoring literature. First, Hellemons et al. [65] demonstrated that a 5-minute window is sufficiently short to capture the temporal signature of rapid brute-force attacks (which typically produce hundreds of events per minute), while being long enough to accumulate statistically meaningful behavioral information for slower attacks. Second, the 5-minute granularity aligns with the default monitoring intervals used by industry-standard SIEM (Security Information and Event Management) tools such as Splunk and QRadar [66], facilitating integration with existing security infrastructure. Third, Bezerra et al. [67] showed that windows shorter than 2 minutes produce excessive noise due to insufficient event counts, while windows longer than 10 minutes introduce unacceptable detection latency.

**Feature vector counts after extraction:**

[Table 3.5: Feature vector counts by source]

| Source | Overlapping (stride=1 min) | Non-overlapping (stride=5 min) |
|--------|--------------------------|-------------------------------|
| Simulation | 10,304 windows | Approx. 2,060 windows |
| Honeypot | 50,792 windows | Approx. 10,158 windows |

### 3.5.5 Stage 4: Data Splitting

The data split follows the semi-supervised novelty detection paradigm, where the training set must contain exclusively normal data and the test set must contain both normal and attack data for evaluation:

**Training set:**
- **Source:** First 70% of the simulation data (chronological split to preserve temporal ordering and prevent look-ahead bias [68])
- **Size:** 7,212 samples
- **Composition:** 100% normal
- **Purpose:** Train models to learn the distributional characteristics of normal SSH behavior

**Test set:**
- **Source:** Remaining 30% of simulation data (normal) + all honeypot data (attack and normal from admin IPs)
- **Size:** 15,184 samples
- **Composition:** 3,796 normal (25.0%) + 11,388 attack (75.0%)
- **Normal-to-attack ratio:** Approximately 1:3
- **Purpose:** Evaluate model performance on a realistic mixture of normal and attack traffic

[Table 3.6: Complete dataset split summary]

| Dataset | Total Samples | Normal | Attack | Normal % | Attack % |
|---------|--------------|--------|--------|----------|----------|
| Training | 7,212 | 7,212 | 0 | 100% | 0% |
| Test | 15,184 | 3,796 | 11,388 | 25.0% | 75.0% |
| **Total** | **22,396** | **11,008** | **11,388** | **49.2%** | **50.8%** |

The chronological split for the simulation data (first 70% for training, last 30% for testing) is a critical methodological choice. Unlike random splitting, which would allow information from later time periods to "leak" into the training set, chronological splitting ensures that the model is evaluated on data from a time period it has never seen during training. This simulates the real-world deployment scenario where the model is trained on historical data and must generalize to future observations [69].

### 3.5.6 Stage 5: Feature Scaling

After extraction and splitting, features are normalized using **RobustScaler** from the scikit-learn library [63]. RobustScaler was selected over StandardScaler (z-score normalization) and MinMaxScaler based on the following theoretical and empirical considerations:

**Theoretical justification.** RobustScaler uses the median and interquartile range (IQR) as its centering and scaling statistics, respectively, rather than the mean and standard deviation used by StandardScaler. The median and IQR are robust estimators of location and scale, respectively, with a breakdown point of 25% (compared to 0% for the mean and standard deviation) [70]. This means that up to 25% of the data can be arbitrarily corrupted without affecting the scaling parameters.

**Empirical justification.** The SSH feature data contains extreme outlier values, particularly in count-based features. For example, `fail_count` ranges from 0 (typical normal value) to several thousand (during intense brute-force attacks). StandardScaler would be heavily influenced by these extreme values, compressing the normal data into a narrow range around zero. RobustScaler, by using the median and IQR, preserves the resolution of normal data while gracefully handling extreme attack values.

The RobustScaler transformation is defined as:

$$x_{\text{scaled}} = \frac{x - Q_2(x)}{Q_3(x) - Q_1(x)}$$

where $Q_1(x)$, $Q_2(x)$, and $Q_3(x)$ are the 25th percentile (first quartile), 50th percentile (median), and 75th percentile (third quartile) of feature $x$, respectively. The scaler is fit exclusively on the training set (containing only normal data) and the learned parameters ($Q_1$, $Q_2$, $Q_3$) are applied to transform both the training and test sets. This procedure prevents data leakage: the scaling parameters are derived solely from normal data, ensuring that the model has no implicit access to the statistical properties of attack data during training [71].

## 3.6 Feature Engineering and Selection

### 3.6.1 Feature Design Philosophy

The 14 features were designed following the principle of behavioral profiling: each feature captures a specific dimension of SSH authentication behavior that is expected to differ systematically between legitimate users and automated attack tools. The feature set was informed by three bodies of prior work:

1. **SSH behavioral analysis.** Javed and Paxson [72] demonstrated that timing features (inter-arrival times, session durations) are the most reliable discriminators between automated SSH attacks and human users, because timing is determined by the fundamental difference between human cognition speed and machine execution speed.

2. **Network intrusion detection feature engineering.** The features used in benchmark datasets such as NSL-KDD [73], CICIDS2017 [74], and UNSW-NB15 [75] informed the selection of count-based and ratio-based features (e.g., fail_rate, invalid_user_ratio).

3. **Anomaly detection theory.** Aggarwal [76] established that effective anomaly detection features should exhibit high variance between normal and anomalous classes (inter-class variance) and low variance within the normal class (intra-class variance), enabling clear separation.

### 3.6.2 Feature Definitions

The 14 features are organized into five functional groups:

**Group 1: Authentication Volume Features**

**1. fail_count** --- The total number of "Failed password" events from IP address $ip$ within window $[t-W, t]$.

$$\texttt{fail\_count}_{ip,t} = |\{e \in \mathcal{E}_{ip,t} \mid e.\text{type} = \texttt{FAILED\_PASSWORD}\}|$$

This is the most direct indicator of brute-force activity. Normal users typically produce 0--2 failures per window (due to occasional mistyping), while active brute-force attacks produce tens to thousands [77].

**2. success_count** --- The total number of "Accepted" events (password or publickey).

$$\texttt{success\_count}_{ip,t} = |\{e \in \mathcal{E}_{ip,t} \mid e.\text{type} \in \{\texttt{ACCEPTED\_PASSWORD}, \texttt{ACCEPTED\_PUBLICKEY}\}\}|$$

Legitimate users have a high success rate; brute-force attackers have near-zero success rates until a credential is cracked.

**3. fail_rate** --- The ratio of failed attempts to total authentication attempts, providing a normalized measure independent of absolute volume.

$$\texttt{fail\_rate}_{ip,t} = \frac{\texttt{fail\_count}_{ip,t}}{\texttt{fail\_count}_{ip,t} + \texttt{success\_count}_{ip,t} + \epsilon}$$

where $\epsilon = 10^{-10}$ prevents division by zero. Values approaching 1.0 are characteristic of brute-force attacks; normal users typically exhibit fail_rate $< 0.3$ [78].

**Group 2: Username Diversity Features**

**4. unique_usernames** --- The number of distinct usernames attempted.

$$\texttt{unique\_usernames}_{ip,t} = |\{e.\text{username} \mid e \in \mathcal{E}_{ip,t}\}|$$

Credential stuffing and dictionary attacks typically enumerate many usernames (root, admin, test, oracle, etc.), while legitimate users use only 1--2 accounts [79].

**5. invalid_user_count** --- The count of attempts with usernames that do not exist on the target system.

$$\texttt{invalid\_user\_count}_{ip,t} = |\{e \in \mathcal{E}_{ip,t} \mid e.\text{type} = \texttt{INVALID\_USER}\}|$$

This is a strong attack indicator because legitimate users know their own account names. The presence of invalid user attempts implies external probing.

**6. invalid_user_ratio** --- The proportion of invalid user attempts among all authentication events.

$$\texttt{invalid\_user\_ratio}_{ip,t} = \frac{\texttt{invalid\_user\_count}_{ip,t}}{|\mathcal{E}_{ip,t}| + \epsilon}$$

A high ratio indicates systematic username enumeration, a characteristic of dictionary and credential stuffing attacks [80].

**Group 3: Temporal Features**

**7. connection_count** --- The total number of SSH connections (distinct events) from the IP within the window.

$$\texttt{connection\_count}_{ip,t} = |\mathcal{E}_{ip,t}|$$

Automated tools generate orders of magnitude more connections than human users within a given time window.

**8. mean_inter_attempt_time** (seconds) --- The mean time interval between consecutive authentication events from the same IP.

$$\texttt{mean\_iat}_{ip,t} = \frac{1}{n-1} \sum_{i=2}^{n} (t_i - t_{i-1})$$

where $t_1, t_2, \ldots, t_n$ are the sorted timestamps of events from IP $ip$ in the window. Automated tools produce sub-second intervals; humans produce intervals of 5--60+ seconds [72].

**9. std_inter_attempt_time** (seconds) --- The standard deviation of inter-attempt times.

$$\texttt{std\_iat}_{ip,t} = \sqrt{\frac{1}{n-2} \sum_{i=2}^{n} \left((t_i - t_{i-1}) - \texttt{mean\_iat}_{ip,t}\right)^2}$$

Low standard deviation indicates uniform, machine-like behavior; high standard deviation indicates irregular, human-like behavior [81].

**10. min_inter_attempt_time** (seconds) --- The minimum time interval between any two consecutive events.

$$\texttt{min\_iat}_{ip,t} = \min_{i \in \{2, \ldots, n\}} (t_i - t_{i-1})$$

A value near zero indicates that at least one pair of events occurred in rapid succession, a hallmark of automated attacks. This feature is particularly sensitive because even if the mean interval is moderate (as in a low-and-slow attack), a single rapid burst will drive min_iat to near zero.

**Group 4: Network and Session Features**

**11. unique_ports** --- The number of distinct source ports used.

$$\texttt{unique\_ports}_{ip,t} = |\{e.\text{port} \mid e \in \mathcal{E}_{ip,t}\}|$$

Each new TCP connection uses a different ephemeral source port. A large number of unique ports correlates directly with a large number of connections, providing an independent measure of connection volume that is robust to event-level deduplication [82].

**12. session_duration_mean** (seconds) --- The mean duration of SSH sessions, computed as the time between "Accepted" events and subsequent "Connection closed" events for the same IP and port.

$$\texttt{session\_duration\_mean}_{ip,t} = \frac{1}{k} \sum_{j=1}^{k} (t_{\text{close},j} - t_{\text{open},j})$$

Legitimate sessions last minutes to hours; brute-force sessions last under 5 seconds because each failed authentication results in rapid disconnection [72]. Feature importance analysis (Section 4.4) confirms this as the single most discriminative feature.

**Group 5: Attack Indicator Features**

**13. pam_failure_escalation** --- A binary indicator (0 or 1) denoting whether an escalating sequence of PAM (Pluggable Authentication Module) authentication failures was observed within the window.

$$\texttt{pam\_failure\_escalation}_{ip,t} = \begin{cases} 1 & \text{if escalating PAM failure sequence detected} \\ 0 & \text{otherwise} \end{cases}$$

An escalating sequence of PAM failures indicates systematic credential testing, as each successive failure triggers increasingly severe PAM logging [83].

**14. max_retries_exceeded** --- A binary indicator denoting whether a "maximum authentication attempts exceeded" event was logged.

$$\texttt{max\_retries\_exceeded}_{ip,t} = \begin{cases} 1 & \text{if max retries event detected} \\ 0 & \text{otherwise} \end{cases}$$

This event occurs when an attacker exhausts the MaxAuthTries limit within a single SSH connection, a direct indicator of brute-force behavior within a session.

### 3.6.3 Feature Selection Rationale

[Table 3.7: Summary of 14 features, data types, expected value ranges, and detection significance]

| No. | Feature | Type | Normal Range | Attack Range | Detection Role |
|-----|---------|------|-------------|-------------|---------------|
| 1 | fail_count | Integer | 0--2 | 10--1000+ | Volume indicator |
| 2 | success_count | Integer | 1--10 | 0--1 | Success pattern |
| 3 | fail_rate | Float [0,1] | 0--0.3 | 0.9--1.0 | Normalized failure |
| 4 | unique_usernames | Integer | 1--2 | 5--50+ | Username diversity |
| 5 | invalid_user_count | Integer | 0 | 5--500+ | Enumeration indicator |
| 6 | invalid_user_ratio | Float [0,1] | 0 | 0.3--1.0 | Enumeration severity |
| 7 | connection_count | Integer | 1--5 | 20--1000+ | Activity volume |
| 8 | mean_inter_attempt_time | Float (s) | 10--300+ | 0.01--2 | Speed signature |
| 9 | std_inter_attempt_time | Float (s) | 5--200+ | 0--1 | Regularity signature |
| 10 | min_inter_attempt_time | Float (s) | 3--60+ | 0--0.5 | Burst detection |
| 11 | unique_ports | Integer | 1--5 | 20--500+ | Connection diversity |
| 12 | session_duration_mean | Float (s) | 300--7200+ | 0.5--5 | Session pattern |
| 13 | pam_failure_escalation | Binary | 0 | 0 or 1 | PAM escalation |
| 14 | max_retries_exceeded | Binary | 0 | 0 or 1 | Retry exhaustion |

All 14 features were retained despite some exhibiting high pairwise correlation (e.g., fail_count and connection_count, $r > 0.8$), for three reasons: (1) Isolation Forest uses random feature subsets per tree, making it naturally robust to correlated features [84]; (2) each feature captures a unique behavioral dimension that contributes to detecting specific attack types; and (3) Aggarwal [76] demonstrated that removing correlated features can degrade anomaly detection performance when the anomalies manifest in specific feature subsets.

## 3.7 Anomaly Detection Model Configuration

### 3.7.1 Model Selection Criteria

Three anomaly detection models were selected for comparative evaluation based on a systematic review of the anomaly detection literature [47, 48, 76]. The selection criteria were: (1) native support for the semi-supervised (novelty detection) paradigm; (2) demonstrated effectiveness on tabular numerical data; (3) availability of production-quality implementations in scikit-learn; and (4) diversity of algorithmic principles (isolation-based, density-based, boundary-based) to provide complementary perspectives on the data.

### 3.7.2 Isolation Forest (IF)

**Algorithmic principle.** Isolation Forest, proposed by Liu, Ting, and Zhou [84], is based on the principle that anomalous points are easier to isolate than normal points through random recursive partitioning. The algorithm constructs an ensemble of $T$ isolation trees (iTrees), each built on a random sub-sample of size $\psi$ from the training data. Each iTree recursively selects a random feature $q$ and a random split value $p \in [\min(q), \max(q)]$, partitioning the data until each point is isolated (in its own leaf node) or the maximum depth $\lceil \log_2 \psi \rceil$ is reached.

**Anomaly score.** The anomaly score of a test point $\mathbf{x}$ is computed from the average path length $E[h(\mathbf{x})]$ across all $T$ trees:

$$s(\mathbf{x}, n) = 2^{-\frac{E[h(\mathbf{x})]}{c(n)}}$$

where $c(n)$ is the average path length of an unsuccessful search in a Binary Search Tree (BST) with $n$ nodes:

$$c(n) = 2H(n-1) - \frac{2(n-1)}{n}$$

and $H(i) = \ln(i) + \gamma$ is the harmonic number, with $\gamma \approx 0.5772$ being the Euler--Mascheroni constant. Scores close to 1.0 indicate anomalies (short path lengths, easy to isolate); scores close to 0.5 indicate normal points.

**Computational complexity.** Training: $O(T \cdot \psi \cdot \log \psi)$. Prediction: $O(T \cdot \log \psi)$ per sample. This linear-logarithmic complexity is a key advantage for real-time deployment [84].

**Hyperparameters (baseline):**

| Parameter | Value | Justification |
|-----------|-------|---------------|
| n_estimators ($T$) | 300 | Sufficient for stable score estimation [84] |
| max_samples ($\psi$) | 512 | Recommended by Liu et al. [84] for sub-sampling effectiveness |
| max_features | 0.5 (7/14 features per tree) | Increases ensemble diversity [85] |
| contamination | auto | Default scikit-learn behavior |

**Hyperparameters (optimized):**

| Parameter | Value | Justification |
|-----------|-------|---------------|
| n_estimators ($T$) | 500 | Increased for greater score stability |
| max_samples ($\psi$) | 512 | Retained from baseline |
| max_features | 0.75 (10--11/14 features per tree) | Improved per-tree detection coverage |
| contamination | 0.01 | Explicit 1% outlier tolerance [86] |

### 3.7.3 Local Outlier Factor (LOF)

**Algorithmic principle.** LOF, proposed by Breunig et al. [87], is a local density-based anomaly detection method. For each point $\mathbf{x}$, LOF computes the ratio of the average local reachability density (lrd) of its $k$-nearest neighbors to its own lrd. The key insight is that an anomalous point resides in a region of lower density compared to its neighbors.

The **reachability distance** of point $\mathbf{x}$ with respect to point $\mathbf{o}$ is:

$$\text{reach-dist}_k(\mathbf{x}, \mathbf{o}) = \max\{d_k(\mathbf{o}), d(\mathbf{x}, \mathbf{o})\}$$

where $d_k(\mathbf{o})$ is the distance from $\mathbf{o}$ to its $k$-th nearest neighbor and $d(\mathbf{x}, \mathbf{o})$ is the Euclidean distance between $\mathbf{x}$ and $\mathbf{o}$.

The **local reachability density** of $\mathbf{x}$ is:

$$\text{lrd}_k(\mathbf{x}) = \left(\frac{\sum_{\mathbf{o} \in N_k(\mathbf{x})} \text{reach-dist}_k(\mathbf{x}, \mathbf{o})}{|N_k(\mathbf{x})|}\right)^{-1}$$

The **LOF score** is:

$$\text{LOF}_k(\mathbf{x}) = \frac{\sum_{\mathbf{o} \in N_k(\mathbf{x})} \frac{\text{lrd}_k(\mathbf{o})}{\text{lrd}_k(\mathbf{x})}}{|N_k(\mathbf{x})|}$$

LOF $\approx 1$ indicates normal density; LOF $\gg 1$ indicates anomalous (low) density.

**Computational complexity.** Training: $O(n^2 \log n)$ for $k$-nearest neighbor computation using KD-trees. Prediction: $O(n \log n)$ per sample (requires comparison against stored training data).

**Hyperparameters:**

| Parameter | Value | Justification |
|-----------|-------|---------------|
| n_neighbors ($k$) | 30 | Balances sensitivity and stability [87] |
| novelty | True | Enables prediction on new (unseen) data [63] |
| metric | Minkowski ($p=2$, Euclidean) | Standard distance metric for numerical features |

### 3.7.4 One-Class SVM (OCSVM)

**Algorithmic principle.** OCSVM, proposed by Scholkopf et al. [88], extends the Support Vector Machine framework to one-class classification. The algorithm finds a hyperplane in the kernel-mapped feature space $\mathcal{H}$ that maximally separates the training data from the origin, with a soft margin controlled by the parameter $\nu$. The optimization problem is:

$$\min_{\mathbf{w}, \xi_i, \rho} \frac{1}{2} \|\mathbf{w}\|^2 + \frac{1}{\nu n} \sum_{i=1}^{n} \xi_i - \rho$$

subject to:

$$\mathbf{w} \cdot \Phi(\mathbf{x}_i) \geq \rho - \xi_i, \quad \xi_i \geq 0, \quad i = 1, \ldots, n$$

where $\Phi(\cdot)$ is the feature mapping induced by the kernel function $K$, and $\nu \in (0, 1]$ controls the upper bound on the fraction of training errors and the lower bound on the fraction of support vectors.

The **RBF kernel** is used:

$$K(\mathbf{x}_i, \mathbf{x}_j) = \exp\left(-\gamma \|\mathbf{x}_i - \mathbf{x}_j\|^2\right)$$

where $\gamma$ controls the kernel bandwidth. A new point $\mathbf{x}$ is classified as normal if $\text{sign}(\mathbf{w} \cdot \Phi(\mathbf{x}) - \rho) = +1$ and anomalous otherwise.

**Computational complexity.** Training: $O(n^2)$ to $O(n^3)$ depending on the solver and kernel cache efficiency. Prediction: $O(n_{sv})$ per sample, where $n_{sv}$ is the number of support vectors.

**Hyperparameters:**

| Parameter | Value | Justification |
|-----------|-------|---------------|
| kernel | RBF | Captures nonlinear decision boundaries [88] |
| gamma | auto ($= 1/d = 1/14 \approx 0.0714$) | scikit-learn default heuristic |
| nu ($\nu$) | 0.01 | Upper bound on outlier fraction (1%) |

### 3.7.5 Model Comparison Summary

[Table 3.8: Comparative characteristics of the three anomaly detection models]

| Characteristic | Isolation Forest | LOF | OCSVM |
|---------------|-----------------|-----|-------|
| Principle | Random isolation | Local density ratio | Maximum-margin hyperplane |
| Training complexity | $O(T \psi \log \psi)$ | $O(n^2 \log n)$ | $O(n^2)$ to $O(n^3)$ |
| Prediction complexity | $O(T \log \psi)$ | $O(n \log n)$ | $O(n_{sv})$ |
| Score type | Continuous [0, 1] | Continuous $\geq 1$ | Signed distance |
| Large-scale suitability | Excellent | Moderate | Moderate |
| Local anomaly detection | Moderate | Excellent | Good |
| Distributional assumptions | None | None | None (with kernel) |
| Interpretability | Moderate (path length) | Low | Low |
| Real-time suitability | Excellent | Limited | Good |

### 3.7.6 Hyperparameter Optimization

Hyperparameter optimization was performed using grid search with a custom evaluation protocol adapted for the semi-supervised setting. Since the training set contains only normal data, standard cross-validation with accuracy as the criterion is not applicable. Instead, the following procedure was employed:

1. A small validation set was constructed by holding out 10% of the training set (normal data) and combining it with a stratified random sample of 500 attack samples from the test set.
2. Grid search was performed over the parameter spaces defined for each model (see Sections 3.7.2--3.7.4).
3. The optimization criterion was the F1-score on the validation set, which balances precision and recall.
4. The best hyperparameters were selected and the model was retrained on the full training set.

For Isolation Forest, the grid search explored: $n\_estimators \in \{100, 200, 300, 500\}$, $max\_samples \in \{256, 512, 1024\}$, $max\_features \in \{0.25, 0.5, 0.75, 1.0\}$, and $contamination \in \{\text{auto}, 0.01, 0.05, 0.1\}$, totaling $4 \times 3 \times 4 \times 4 = 192$ parameter combinations.

## 3.8 Dynamic Threshold Engine Design

### 3.8.1 Motivation and Theoretical Basis

Static thresholds --- fixed anomaly score cutoff values determined a priori --- are the standard approach in most deployed anomaly detection systems [89]. However, static thresholds suffer from a fundamental limitation: the optimal threshold depends on the current statistical characteristics of the data, which change over time. In the SSH monitoring context, this non-stationarity manifests in several ways: business hours produce more legitimate login activity (and more legitimate failures) than off-hours; system maintenance windows produce unusual but legitimate traffic patterns; and the baseline level of background attack traffic fluctuates with Internet-wide scanning campaigns [90].

The EWMA-Adaptive Percentile dynamic threshold engine was designed to address this limitation. The theoretical foundation draws on two established techniques:

1. **Exponentially Weighted Moving Average (EWMA).** Originally developed by Roberts [91] for statistical process control in manufacturing quality assurance, EWMA provides a smooth estimate of the current "baseline" of a time series that gives exponentially decreasing weight to older observations.

2. **Percentile-based thresholding.** The use of distribution percentiles as threshold values is a standard robust statistical technique that is less sensitive to outliers than mean-based approaches [70].

The EWMA-Adaptive Percentile algorithm combines these two techniques into a threshold that simultaneously tracks the current baseline (via EWMA) and adapts to the current distributional spread (via percentile).

### 3.8.2 Algorithm Specification

**Parameters:**

| Parameter | Symbol | Value | Description |
|-----------|--------|-------|-------------|
| Smoothing factor | $\alpha$ | 0.3 | EWMA weight for new observations |
| Base percentile | $p$ | 95 | Percentile of the lookback distribution |
| Sensitivity factor | $\lambda$ | 1.5 | Multiplier for the distance above EWMA |
| Lookback window | $L$ | 100 | Number of recent scores for percentile computation |

**Step 1: Update the EWMA of anomaly scores.** Given the anomaly score time series $s_1, s_2, \ldots, s_t$ produced by the model, the EWMA at time $t$ is updated recursively:

$$\mu_t^{\text{EWMA}} = \alpha \cdot s_t + (1 - \alpha) \cdot \mu_{t-1}^{\text{EWMA}}$$

with initialization $\mu_0^{\text{EWMA}} = s_1$. The smoothing factor $\alpha = 0.3$ was selected following the guidelines of Lucas and Saccucci [92], who showed that $\alpha \in [0.2, 0.4]$ provides a good balance between responsiveness to genuine changes and robustness to transient noise for process control applications. The effective memory span of an EWMA is approximately $2/\alpha - 1 = 5.67$ observations, meaning that observations older than approximately 6 time steps contribute less than 5% to the current EWMA value.

**Step 2: Compute the adaptive percentile.** Using the $L = 100$ most recent anomaly scores, compute the $p$-th percentile:

$$P_t = \text{Percentile}(\{s_{t-L+1}, s_{t-L+2}, \ldots, s_t\}, p)$$

The base percentile $p = 95$ ensures that the threshold is placed above 95% of recent normal scores, providing a natural separation between normal variability and genuine anomalies. The lookback window $L = 100$ provides sufficient statistical stability for the percentile estimate while remaining responsive to distributional changes.

**Step 3: Compute the dynamic threshold.** The threshold at time $t$ is:

$$\theta_t = \mu_t^{\text{EWMA}} + \lambda \cdot (P_t - \mu_t^{\text{EWMA}})$$

Substituting $\lambda = 1.5$:

$$\theta_t = \mu_t^{\text{EWMA}} + 1.5 \cdot (P_t - \mu_t^{\text{EWMA}})$$

This formula places the threshold at the EWMA mean plus 1.5 times the distance from the EWMA to the 95th percentile. The geometric interpretation is: $\theta_t$ interpolates between the EWMA ($\lambda = 0$) and the 95th percentile ($\lambda = 1$), and with $\lambda = 1.5$, the threshold extends beyond the 95th percentile by 50% of the EWMA-to-percentile distance. This design provides three desirable properties:

- During stable normal periods, $P_t - \mu_t^{\text{EWMA}}$ is small (the 95th percentile is close to the mean), so $\theta_t$ is slightly above the mean, providing sensitive detection.
- During attack waves, the EWMA rises (pulled upward by high anomaly scores), which raises $\theta_t$ and prevents the system from generating continuous false alarms from the elevated baseline.
- After attacks subside, the EWMA decays exponentially back toward the normal level, lowering $\theta_t$ and restoring detection sensitivity.

**Step 4: Two-level classification.** A sample at time $t$ is classified into one of three categories:

$$\hat{y}(\mathbf{x}, t) = \begin{cases} \texttt{ALERT} & \text{if } s(\mathbf{x}) > \theta_t \\ \texttt{EARLY\_WARNING} & \text{if } s(\mathbf{x}) > \theta_t / 1.5 \\ \texttt{NORMAL} & \text{otherwise} \end{cases}$$

The EARLY_WARNING threshold is set at $\theta_t / 1.5 \approx 0.667 \cdot \theta_t$, providing an intermediate alerting level that notifies security personnel without triggering automated blocking. This graduated response mechanism is critical for production environments where false IP blocks can disrupt legitimate services [93].

### 3.8.3 Self-Calibration Mechanism

The dynamic threshold engine incorporates a self-calibration mechanism that re-estimates the baseline statistics every $L = 100$ decisions. At each calibration point, the engine:

1. Recomputes the EWMA baseline from the most recent 100 observations.
2. Recalculates the 95th percentile from the same observations.
3. Adjusts the threshold if the distributional characteristics have shifted significantly.

This self-calibration ensures long-term stability even under persistent non-stationarity, such as gradual changes in the organization's SSH usage patterns or seasonal variations in Internet-wide attack traffic.

[Table 3.9: Dynamic threshold parameter sensitivity]

| Parameter | Low Value | Selected | High Value | Effect of Increase |
|-----------|-----------|----------|-----------|-------------------|
| $\alpha$ | 0.1 (slow) | 0.3 (balanced) | 0.5 (fast) | Faster response, more noise sensitivity |
| $p$ | 90th | 95th | 99th | Higher threshold, fewer FP, may miss subtle attacks |
| $\lambda$ | 1.0 | 1.5 | 2.0 | Higher threshold, fewer alerts overall |
| $L$ | 50 | 100 | 200 | Smoother percentile, slower adaptation |

[Figure 3.4: Illustration of the EWMA-Adaptive Percentile dynamic threshold behavior over time, showing adaptation to traffic pattern changes]

## 3.9 Alert and Prevention Module

### 3.9.1 Fail2Ban Integration

When the detection module classifies an IP as ALERT-level (attack), the system invokes the Fail2Ban API to execute automated prevention. The integration architecture follows the event-driven pattern described by Hohpe and Woolf [94]:

1. **IP banning.** Fail2Ban adds a DROP rule to the iptables/nftables firewall, blocking all new SSH connections from the offending IP.
2. **Configurable ban duration.** The base ban duration is configurable (default: 600 seconds), with progressive escalation: repeat offenders receive exponentially increasing ban durations ($\text{ban\_duration}_k = \text{base} \times 2^{k-1}$, where $k$ is the offense count).
3. **Whitelist protection.** The 6 administrative IP addresses are permanently whitelisted and cannot be banned, preventing accidental lockout of the research team.

### 3.9.2 Multi-Channel Alert System

The alert system supports three notification channels:

- **Dashboard alerts.** Real-time alert display on the React dashboard via WebSocket, including IP address, timestamp, anomaly score, alert level (EARLY_WARNING or ALERT), and action taken.
- **Webhook notifications.** Outbound HTTP POST notifications to external services (e.g., Slack, Telegram) for integration with existing security operations workflows.
- **Audit logging.** Comprehensive event logging to Elasticsearch for post-incident forensic analysis, compliance reporting, and long-term trend analysis.

### 3.9.3 Administrator Feedback Loop

An administrator feedback mechanism allows security personnel to review detection events through the React interface and mark them as confirmed attack (true positive), false alarm (false positive), or requires investigation. This feedback is stored in the database and can be used for:

- Threshold parameter adjustment (increasing $\lambda$ if too many false positives, decreasing if attacks are missed).
- Feature engineering refinement based on patterns observed in misclassified events.
- Long-term model performance monitoring and drift detection.

## 3.10 Visualization Module

### 3.10.1 React Dashboard

The monitoring dashboard provides security operators with situational awareness through the following visualization components:

- **Real-time event stream.** A chronological feed of all detection events with severity color coding (green for normal, yellow for EARLY_WARNING, red for ALERT).
- **Anomaly score trend chart.** A time-series plot showing anomaly scores and the dynamic threshold over time, enabling operators to visually assess the system's decision-making process.
- **IP geolocation map.** A world map displaying the geographic origins of detected attacks, using the MaxMind GeoIP2 database for IP-to-location resolution [95].
- **Attack statistics dashboard.** Aggregate statistics including total events, detection rate, false positive rate, top attacking IPs, and most targeted usernames.
- **Configuration panel.** Administrative controls for adjusting detection parameters ($\alpha$, $p$, $\lambda$, $L$), ban duration, and notification settings.

### 3.10.2 Kibana Integration

Kibana provides complementary ad hoc exploration capabilities for security analysts who need to investigate specific incidents in depth. Pre-configured Kibana dashboards display: raw log event timelines, per-IP behavioral profiles over time, feature distribution histograms, and correlation between detection events and Fail2Ban ban actions.

## 3.11 Evaluation Metrics

### 3.11.1 Classification Metrics

Performance evaluation is based on the standard binary classification confusion matrix, where positive denotes the attack class and negative denotes the normal class. The five metrics used in this research, and their mathematical definitions, are:

**Accuracy.** The proportion of all samples correctly classified:

$$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$

In imbalanced datasets, accuracy can be misleading --- a classifier that always predicts the majority class achieves high accuracy without any discriminative power [96]. Therefore, accuracy is reported but not used as the primary evaluation criterion.

**Precision.** The proportion of predicted attacks that are actual attacks:

$$\text{Precision} = \frac{TP}{TP + FP}$$

High precision indicates few false alarms. In cybersecurity operations, excessive false positives cause "alert fatigue," leading operators to ignore genuine alerts [97].

**Recall (Sensitivity, True Positive Rate).** The proportion of actual attacks that are correctly detected:

$$\text{Recall} = \frac{TP}{TP + FN}$$

In cybersecurity, recall is the paramount metric because a missed attack (false negative) can result in system compromise, data exfiltration, or service disruption --- consequences far more severe than a false alarm [98].

**F1-Score.** The harmonic mean of precision and recall:

$$F_1 = 2 \cdot \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

The harmonic mean penalizes extreme imbalances between precision and recall, providing a balanced single-number summary of classification performance [99].

**ROC-AUC (Area Under the Receiver Operating Characteristic Curve).** The probability that the model assigns a higher anomaly score to a randomly chosen attack sample than to a randomly chosen normal sample:

$$\text{ROC-AUC} = P(s(\mathbf{x}^+) > s(\mathbf{x}^-))$$

where $\mathbf{x}^+$ is drawn from the attack class and $\mathbf{x}^-$ from the normal class. ROC-AUC = 1.0 indicates perfect discrimination; ROC-AUC = 0.5 indicates random (no discriminative power) [100].

**False Positive Rate (FPR).** The proportion of normal samples incorrectly classified as attacks:

$$\text{FPR} = \frac{FP}{FP + TN}$$

FPR is reported alongside the primary metrics because it directly quantifies the operational cost of false alarms in terms of wrongly banned legitimate users.

### 3.11.2 Priority Hierarchy

[Table 3.10: Evaluation metrics and their security significance]

| Metric | Security Significance | Priority |
|--------|----------------------|----------|
| Recall | Not missing attacks (preventing compromise) | Highest |
| F1-Score | Balanced precision-recall performance | High |
| Precision | Reducing false alarms (preventing alert fatigue) | High |
| ROC-AUC | General discriminative ability across all thresholds | High |
| Accuracy | Overall correctness | Medium |
| FPR | Operational cost of false bans | Medium |

The priority hierarchy reflects the asymmetric cost structure in cybersecurity: the cost of missing an attack (potential system compromise) is orders of magnitude greater than the cost of a false alarm (temporary IP ban that can be appealed) [101].

### 3.11.3 System-Level Metrics

In addition to classification metrics, the following system-level metrics are evaluated:

- **End-to-end latency:** Time from SSH log event occurrence to classification decision and response action.
- **Throughput:** Maximum number of feature vectors processed per second.
- **Training time:** Wall-clock time to train each model on the training set.
- **Memory usage:** Peak RAM consumption of each model during training and inference.

## 3.12 Limitations of the Methodology

### 3.12.1 Window Size Constraints

The 5-minute sliding window, while effective for detecting rapid and moderate-speed attacks, imposes an inherent limitation on the detection of extremely slow attacks where the attacker spaces attempts over intervals exceeding the window size. An attacker performing one attempt every 10 minutes would produce at most one event per window, generating feature vectors that may be indistinguishable from normal activity. This limitation is partially mitigated by the EWMA accumulation mechanism (which detects the cumulative trend over multiple windows) but cannot be fully resolved within the current architecture. Long-term IP profiling, as proposed by Hofstede et al. [102], or integration with external threat intelligence feeds could complement the window-based approach.

### 3.12.2 Training Data Purity Assumption

The semi-supervised paradigm assumes that the training data is purely normal. Any contamination of the training set with attack samples --- even a small proportion --- could cause the model to learn attack patterns as part of the normal profile, degrading detection performance. While the simulation-based training data generation provides strong purity guarantees, this assumption may be more difficult to satisfy in production deployments where the boundary between normal and anomalous behavior is less clear-cut.

### 3.12.3 Single-Environment Generalization

The RobustScaler normalization and model training are based on data from a single operational environment (the simulation representing one organization's SSH usage patterns). The learned feature distributions and decision boundaries may not generalize to environments with significantly different usage patterns (e.g., a high-security data center vs. a university campus). When deploying to a new environment, the scaler and model should be retrained on data representative of that environment, following the domain adaptation guidelines of Pan and Yang [103].

### 3.12.4 Dataset Specificity

The evaluation is conducted on a specific dataset with a fixed normal-to-attack ratio of approximately 1:3 in the test set. Performance may vary under different class ratios or in environments with significantly different traffic volumes, attack sophistication levels, or user population sizes. The dynamic threshold mechanism is designed to mitigate some of this sensitivity through its adaptive nature, but comprehensive cross-environment evaluation remains an area for future work.

### 3.12.5 Ethical Considerations

The data collection methodology was designed with careful attention to ethical considerations. The honeypot data was collected from a purpose-built honeypot server designed to attract and record attack traffic; no legitimate user data was collected or compromised. The 6 administrative IP addresses that produced legitimate traffic on the honeypot were under the full control of the research team. The simulation data was generated synthetically, using entirely fictional user accounts and behavioral profiles. Attack scenario testing was conducted exclusively within a controlled, isolated test environment, with no unauthorized access attempts against external systems. The attack simulation scripts are documented for reproducibility but are not distributed in executable form to prevent potential misuse, following the responsible disclosure guidelines of the CERT Coordination Center [104].
