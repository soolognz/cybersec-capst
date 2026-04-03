# CHAPTER 5: DISCUSSION

## 5.1 Restatement of Research Problem

The proliferation of Internet-facing SSH services has made brute-force login attacks one of the most persistent threats to server infrastructure worldwide. According to Rapid7 [4], SSH (port 22) consistently ranks among the top three targeted services, with brute-force attempts accounting for a substantial proportion of all observed malicious traffic. Conventional countermeasures such as Fail2Ban [27] employ static, count-based thresholds --- typically blocking an IP address after a fixed number of failed login attempts within a predefined time window. While effective against naive, high-speed attacks, this paradigm suffers from three fundamental limitations: (i) it cannot detect low-and-slow attacks in which the adversary deliberately spaces attempts below the threshold rate; (ii) it is blind to distributed attacks that spread attempts across multiple source IPs; and (iii) it offers no predictive capability, responding only after the threshold has already been exceeded.

This thesis was motivated by the question: *How can an AI-based SSH brute-force detection and prevention system be constructed that provides early attack prediction, adapts dynamically to changing traffic patterns, and integrates fully into modern security monitoring infrastructure?* Five specific objectives were formulated to operationalize this question:

1. Design a comprehensive behavioral feature set that captures the multidimensional differences between legitimate SSH activity and brute-force attacks.
2. Train and systematically evaluate three unsupervised anomaly detection models --- Isolation Forest, Local Outlier Factor, and One-Class SVM --- on real-world SSH data.
3. Develop an adaptive EWMA-Adaptive Percentile dynamic threshold that enables early warning and self-calibration.
4. Build a complete, containerized end-to-end system integrating log ingestion, feature extraction, anomaly scoring, dynamic thresholding, and automated response within a 9-service Docker architecture.
5. Validate the system against five realistic attack scenarios of escalating difficulty.

Four subsidiary research questions (RQ1--RQ4) were posed in Chapter 1. The following sections evaluate the extent to which each objective was met, interpret the principal findings, position the results within the existing literature, discuss practical deployment implications, and identify limitations and threats to validity.

## 5.2 Achievement of Research Objectives

### 5.2.1 Objective 1: Behavioral Feature Set Design

The 14-feature behavioral feature set described in Chapter 3 (Table 3.4) was successfully designed, implemented, and validated. The features span five functional groups --- authentication count and rate, username-related, connection and temporal, network and session, and attack indicator features --- extracted over 5-minute sliding windows per source IP address. Feature importance analysis using permutation importance on the optimized Isolation Forest model (Section 4.3) confirmed that the feature set provides strong discriminative power, with the top five features collectively accounting for more than 15% of total importance. Crucially, the analysis revealed that temporal features dominate discrimination: session_duration_mean (5.50%), min_inter_attempt_time (3.86%), mean_inter_attempt_time (2.61%), and std_inter_attempt_time (1.64%) occupy four of the top five positions (Table 4.5, Figure 4.6). This result validates the design decision to include fine-grained timing statistics alongside the count-based features traditionally used in tools such as Fail2Ban.

### 5.2.2 Objective 2: Model Training and Evaluation

Three unsupervised anomaly detection algorithms were implemented, optimized, and systematically compared on a hybrid dataset of 174,250 SSH log lines (119,729 honeypot attack lines and 54,521 simulated normal lines), yielding 22,396 processed samples. After optimization (non-overlapping windows, derived features, contamination tuning), the following results were obtained:

| Model | Accuracy | F1-Score | Recall | FPR |
|-------|----------|----------|--------|------|
| Isolation Forest | 90.31% | 93.74% | 96.75% | 29.00% |
| LOF | 83.22% | 89.94% | 100.00% | 67.10% |
| OCSVM | 91.38% | 94.55% | 100.00% | 33.42% |

All three models exceed the minimum targets of F1 > 85% and Recall > 95% established in Section 1.5. The Isolation Forest was selected as the primary production model for reasons elaborated in Section 5.3.2 below. The systematic three-model comparison on the same real-world SSH dataset --- rather than on synthetic benchmarks such as NSL-KDD [53] or CICIDS2017 [32] --- constitutes an empirical contribution to the algorithm selection literature for SSH anomaly detection.

### 5.2.3 Objective 3: Dynamic Threshold

The EWMA-Adaptive Percentile dynamic threshold (alpha = 0.3, base_percentile = 95, sensitivity_factor = 1.5, lookback = 100) was successfully developed and evaluated (Section 4.4, Table 4.9, Figure 4.12). Compared with a static threshold at the 95th percentile, the dynamic threshold reduced burst false positives while maintaining equivalent recall. Most importantly, the EWMA accumulation mechanism enables early warning for low-and-slow attacks after only 3--5 attempts (approximately 2--3 minutes), whereas Fail2Ban with default settings (maxretry = 5, findtime = 600 s) fails to detect such attacks entirely when attempts are spaced at intervals of 30--120 seconds [27]. The two-level detection mechanism (EARLY_WARNING at 67% of the ALERT threshold, ALERT triggering Fail2Ban) provides graduated response, avoiding unnecessary service disruption.

### 5.2.4 Objective 4: Integrated System

The complete system was implemented as a Docker Compose deployment comprising 9 services: FastAPI (API server and ML inference), React (monitoring dashboard), Elasticsearch (storage and indexing), Logstash (log normalization), Kibana (visualization), Fail2Ban (automated IP blocking), Redis (caching and session management), PostgreSQL (configuration persistence), and Nginx (reverse proxy and load balancing). The five-stage real-time detection pipeline (Ingestion, Aggregation, Scoring, Decision, Action) achieves an end-to-end latency of under 2 seconds, with AI processing stages completing in under 100 ms (Table 4.14). The system is portable, reproducible, and deployable with a single command (`docker-compose up`), directly addressing the research-to-deployment gap identified by Sommer and Paxson [13] as a persistent barrier to practical ML adoption in network security.

### 5.2.5 Objective 5: Attack Scenario Evaluation

Five attack scenarios were designed, executed, and analyzed (Table 4.10, Table 4.12, Figure 4.14): (1) basic brute-force, (2) distributed brute-force, (3) low-and-slow, (4) credential stuffing, and (5) dictionary attacks. Basic brute-force and dictionary attacks were detected immediately (100% detection within the first 1-minute window). Distributed attacks and credential stuffing achieved detection rates exceeding 90% and 95%, respectively. The low-and-slow scenario --- the most challenging case --- was partially addressed through the EWMA accumulation mechanism, with early warnings issued after 3--5 attempts. Additionally, 51 unit tests across all system components passed, confirming functional correctness and integration integrity.

## 5.3 Interpretation of Key Findings

### 5.3.1 Why Timing Features Dominate

The finding that temporal features outperform count-based features for SSH brute-force detection (Section 4.3, Table 4.5) is both statistically robust and intuitively grounded. Session_duration_mean (importance = 5.50%) is the single most discriminative feature because brute-force sessions are inherently short: each failed password attempt results in rapid disconnection, producing session durations typically under 5 seconds, while legitimate interactive sessions last minutes to hours. This bimodal gap is a structural property of the SSH protocol [2, 15] and cannot be eliminated by the attacker without fundamentally changing the attack strategy.

Min_inter_attempt_time (3.86%) captures the minimum spacing between consecutive authentication attempts from a single IP. Automated tools such as Hydra and Medusa generate attempts at machine speed, producing inter-attempt intervals of milliseconds to low seconds, whereas human operators exhibit intervals of seconds to minutes with high variance. Even sophisticated attackers who introduce random delays to evade count-based detection find it difficult to perfectly mimic the stochastic temporal signature of legitimate users [20, 62].

The low importance of traditional count-based features (fail_count, connection_count) is explained by the training methodology: the model is trained exclusively on normal data where these features are consistently near zero. In the anomaly detection paradigm, the model learns the distribution of normal behavior; features with near-zero variance in normal data contribute little to the anomaly score computation because all test points --- both normal and attack --- are evaluated relative to the learned normal distribution. Temporal features, by contrast, exhibit substantial variance even within normal data (different users type at different speeds, maintain different session durations), enabling the model to learn a nuanced boundary.

This finding corroborates and extends the work of Javed and Paxson [62], who demonstrated that timing characteristics are the most effective discriminator for SSH brute-force traffic, and of Starov et al. [54], who showed that temporal behavioral analysis outperforms volume-based features for SSH attack detection. Our contribution is the quantification of specific feature importance values within an Isolation Forest framework, providing actionable guidance for feature engineering in future detection systems.

### 5.3.2 Why Isolation Forest Is Chosen Despite OCSVM Having Higher F1

The OCSVM achieved the highest F1-score (94.55%) and accuracy (91.38%) among the three models evaluated. Nevertheless, the Isolation Forest (F1 = 93.74%, accuracy = 90.31%) was selected as the primary production model. This decision was driven by three operational considerations that outweigh the 0.81 percentage-point F1 gap.

First, **computational efficiency**. Isolation Forest operates in O(n log n) time for both training and inference, compared with O(n^2) to O(n^3) for OCSVM [35, 39]. In a production system processing hundreds or thousands of SSH sessions per minute, this difference translates directly into lower latency and reduced resource consumption. Table 4.15 confirms that IF achieves substantially higher throughput than OCSVM.

Second, **anomaly score properties**. Isolation Forest produces smooth, continuous anomaly scores derived from the average path length across the tree ensemble [36]. These scores are well-suited for input to the EWMA-Adaptive Percentile dynamic threshold, which requires a continuous signal to track trends and compute running percentiles. OCSVM, by contrast, produces a signed distance to the decision boundary that is less granular near the boundary region, reducing the sensitivity of the dynamic threshold to subtle shifts in traffic patterns.

Third, **distributional assumptions**. OCSVM with an RBF kernel implicitly assumes that normal data forms a single compact region in the kernel-mapped feature space [39, 40]. This assumption holds for the current dataset but may be violated in heterogeneous production environments where normal SSH behavior spans multiple distinct clusters (e.g., administrators, automated scripts, interactive users). Isolation Forest makes no distributional assumptions, operating purely on the isolability principle [35], making it more robust to multimodal normal distributions.

This reasoning aligns with the recommendations of Goldstein and Uchida [41], whose comparative evaluation of unsupervised anomaly detection algorithms concluded that Isolation Forest offers the best trade-off between detection performance and computational cost for datasets with moderate dimensionality.

### 5.3.3 Dynamic Threshold vs. Static Threshold Advantage

Static thresholds, as employed by Fail2Ban and most rule-based intrusion detection systems [27, 29], create a fixed decision boundary that does not respond to changes in the underlying data distribution. Three specific failure modes of static thresholds were identified in this research.

First, **baseline drift**. SSH traffic patterns vary systematically between business hours and off-hours, between weekdays and weekends, and across organizational events (onboarding, audits, system migrations). A static threshold calibrated for average conditions produces excessive false positives during high-activity periods and may miss attacks during low-activity periods. The EWMA component (alpha = 0.3) tracks the moving baseline, automatically widening the threshold during periods of legitimately elevated activity and narrowing it during quiet periods.

Second, **burst false positives**. Legitimate but anomalous events (a new employee's first SSH session, an automated script changing execution timing) produce transient anomaly score spikes that exceed static thresholds. The Adaptive Percentile component computes the threshold from the recent score distribution (lookback = 100), absorbing individual spikes without triggering alerts unless the elevated pattern persists.

Third, **low-and-slow evasion**. Adversaries who space attempts below the static threshold rate (e.g., one attempt every 2 minutes against Fail2Ban's default of 5 attempts in 10 minutes) evade count-based detection entirely. The EWMA accumulation mechanism provides a fundamentally different detection modality: each anomalous score, even if individually below the alert threshold, incrementally raises the EWMA value. After 3--5 successive anomalous attempts (approximately 2--3 minutes), the accumulated EWMA value crosses the early warning threshold, triggering notification. This capability was confirmed experimentally in Scenario 3 (Table 4.11) and represents the most significant practical advantage of the dynamic threshold approach.

The dynamic threshold also supports the two-level graduated response mechanism, where EARLY_WARNING events (EWMA exceeding 67% of the alert threshold) are logged and reported without blocking, while ALERT events trigger automated IP blocking via Fail2Ban. This graduated response addresses the operational concern that overly aggressive blocking disrupts legitimate services --- a concern frequently cited by security operations teams [49].

### 5.3.4 FPR Analysis and Acceptable Trade-off in Security Context

The optimized Isolation Forest model exhibits a false positive rate of 29.00%, meaning approximately 29 out of every 100 normal SSH sessions are incorrectly flagged as anomalous. In many machine learning application domains (e.g., spam filtering, fraud detection), an FPR of this magnitude would be unacceptable. However, in the cybersecurity context, the cost asymmetry between false positives and false negatives must be considered [8, 13].

The cost of a false negative --- a missed attack that allows an adversary to gain unauthorized access --- includes potential data exfiltration, lateral movement, ransomware deployment, regulatory penalties, and reputational damage. According to Morgan [1], cybercrime damages were projected to reach $10.5 trillion annually by 2025. The cost of a false positive, by contrast, is an unnecessary security alert that consumes analyst time and may temporarily inconvenience a legitimate user.

Given this asymmetry, the operating point of 96.75% recall and 29.00% FPR is defensible. Moreover, the two-level detection mechanism mitigates the practical impact of false positives: EARLY_WARNING events are logged without blocking, and only high-confidence ALERT events result in IP blocking. The dynamic threshold's self-calibration further reduces effective FPR over time as the system adapts to the specific deployment environment's normal baseline.

Several avenues exist for further FPR reduction. Ensemble methods combining IF, LOF, and OCSVM through majority voting could reduce individual model biases [41]. Deep learning approaches such as LSTM-Autoencoders [57] can model complex temporal dependencies that tree-based methods may miss. Integration of external threat intelligence [28] would provide additional classification context, effectively lowering the threshold for known malicious IPs while raising it for IPs with clean reputations. Active learning, in which administrator feedback on alerts is used to iteratively refine the decision boundary, represents another promising direction [63].

## 5.4 Comparison with Existing Literature

This section positions the results of the current study against the findings reported in the existing literature. Table 5.2 provides a systematic comparison.

**Sperotto et al. (2010) [21].** Proposed flow-based intrusion detection using IP flow records from the DARPA dataset. Their approach achieved moderate detection rates but operated in an offline, batch-processing mode without real-time capability or early prediction. Our system advances beyond flow-based methods by operating on raw SSH authentication logs, enabling extraction of fine-grained temporal features (e.g., session_duration_mean, min_inter_attempt_time) that are unavailable in aggregated flow records. Furthermore, our system provides real-time detection with sub-2-second latency.

**Najafabadi et al. (2015) [7].** Employed aggregated NetFlow data with machine learning for SSH brute-force detection, reporting detection rates above 90%. However, their approach required labeled training data (supervised learning) and did not address low-and-slow or distributed attack variants. Our semi-supervised approach, requiring only normal data for training, eliminates the dependence on labeled attack samples and demonstrates detection capability across five attack scenarios including low-and-slow.

**Buczak and Guven (2016) [8].** Surveyed data mining and machine learning methods for intrusion detection, identifying the lack of real-world evaluation datasets, the absence of real-time deployment, and concept drift as the three principal challenges. The current study addresses the first two challenges directly: the evaluation uses real honeypot data rather than synthetic benchmarks, and the system operates in real-time with demonstrated sub-2-second latency. Concept drift is acknowledged as a limitation and addressed in the future work directions.

**Kim et al. (2019) [31].** Achieved an F1-score of 0.92 using Random Forest on the NSL-KDD dataset for network intrusion detection. The current study achieves a comparable F1-score of 0.9374 with Isolation Forest on real SSH data, without requiring labeled attack samples for training. Moreover, the NSL-KDD dataset has been criticized for lack of representativeness of modern attack patterns [53]; our use of contemporary honeypot data provides a more ecologically valid evaluation.

**Tsai et al. (2019) [6].** Studied SSH brute-force defense mechanisms and proposed a hybrid approach combining rate limiting with behavioral analysis. Their system achieved effective detection for high-speed attacks but did not address low-and-slow variants. Our EWMA-Adaptive Percentile threshold directly addresses this gap, detecting low-and-slow attacks after 3--5 attempts.

**Ahmed et al. (2020) [32].** Applied autoencoder-based anomaly detection to the CICIDS2017 dataset, achieving an F1-score of 0.89 with real-time processing capability. The current study achieves a higher F1-score (0.9374) using a computationally simpler model (Isolation Forest vs. autoencoder) and additionally provides the early prediction capability through the dynamic threshold that Ahmed et al. did not investigate.

**Nassif et al. (2021) [31].** Conducted a comprehensive ML survey for intrusion detection, noting that the gap between experimental performance and production deployment remains the principal obstacle. The current study directly addresses this gap by delivering a complete, containerized, deployable system rather than an offline experimental evaluation.

**Pang et al. (2021) [33].** Reviewed deep learning for anomaly detection, recommending that future systems combine traditional ML efficiency with deep learning expressiveness. The current study demonstrates that traditional ML (Isolation Forest) achieves competitive performance (F1 = 93.74%) with significantly lower computational requirements than deep learning, while the future work section (Chapter 6) outlines how deep learning can be integrated for further improvement.

**Satoh et al. (2022) [57].** Applied LSTM-based deep learning to SSH dictionary attack detection, achieving a recall of 97.2%. The current study achieves comparable recall (96.75%) with a significantly simpler model that does not require GPU resources or sequential training. However, the LSTM approach's ability to model long-range temporal dependencies suggests that deep learning could complement the current system for improved detection of sophisticated attack patterns.

**Kumari and Jain (2022) [52].** Applied Isolation Forest for IoT anomaly detection, reporting accuracy above 90%. The current study extends the IF methodology to the SSH domain with three specific enhancements: the 14-feature behavioral feature set tailored to SSH semantics, the EWMA-Adaptive Percentile dynamic threshold for adaptive detection, and the complete integrated system architecture.

**Javed and Paxson (2013) [62].** Demonstrated that timing characteristics are the most effective factor for detecting stealthy, distributed SSH brute-forcing. Our feature importance analysis (Table 4.5) empirically corroborates this finding within the Isolation Forest framework, with four of the top five features being temporal. We extend their work by quantifying specific importance values and embedding the temporal features within a dynamic thresholding system that enables early prediction.

**Starov et al. (2019) [54].** Proposed temporal behavioral analysis for SSH brute-force detection and showed that temporal features outperform volume-based features. The current study confirms this finding and advances it by implementing a complete detection pipeline with automated response and by evaluating against five attack scenarios of varying sophistication.

The following table consolidates the comparison:

| Study | Method | Dataset | Labeled Data Required | Early Prediction | Real-time | F1-Score |
|-------|--------|---------|----------------------|-----------------|-----------|----------|
| Sperotto et al. [21] | Flow-based | DARPA | Yes | No | No | -- |
| Najafabadi et al. [7] | ML + NetFlow | NetFlow | Yes | No | No | >0.90 |
| Kim et al. [31] | Random Forest | NSL-KDD | Yes | No | No | 0.92 |
| Ahmed et al. [32] | Autoencoder | CICIDS2017 | No | No | Yes | 0.89 |
| Tsai et al. [6] | Hybrid | Custom | -- | No | Yes | -- |
| Satoh et al. [57] | LSTM | SSH logs | Yes | No | Yes | -- (R=0.972) |
| Kumari & Jain [52] | IF | IoT | No | No | No | >0.90 |
| Javed & Paxson [62] | Statistical | SSH traces | No | No | Offline | -- |
| **This study** | **IF + EWMA** | **Real SSH** | **No** | **Yes** | **Yes** | **0.9374** |

Three distinguishing aspects position this work relative to the literature. First, **dataset realism**: the use of real SSH honeypot data (119,729 log lines from 679 unique IPs) rather than synthetic benchmarks. Second, **methodological novelty**: the combination of Isolation Forest with EWMA-Adaptive Percentile dynamic thresholding for SSH early prediction has not been previously reported. Third, **engineering completeness**: the system is implemented as a deployable, containerized end-to-end solution, not merely an offline experimental prototype.

## 5.5 Practical Implications

### 5.5.1 Deployment Considerations

The experimental results carry several direct implications for security operations teams evaluating AI-based SSH monitoring solutions.

**Feature engineering priorities.** The demonstrated primacy of temporal features (Section 5.3.1) implies that security monitoring infrastructure must preserve fine-grained timing information in SSH logs. Many current logging configurations aggregate or discard timing details, retaining only count-based summaries (e.g., "X failed logins from IP Y in Z minutes"). Organizations adopting the proposed approach should ensure that authentication timestamps are logged at second or sub-second granularity, that session start and end times are recorded, and that log rotation policies do not truncate these fields. The standard OpenSSH syslog format on Debian/Ubuntu (/var/log/auth.log) and CentOS/RHEL (/var/log/secure) provides sufficient detail for the 14-feature extraction pipeline [18].

**Integration with existing infrastructure.** The Docker-based architecture was designed for compatibility with existing security monitoring stacks. Organizations already using the ELK Stack for log management can integrate the detection system by adding the FastAPI service and configuring Logstash to forward SSH events to both Elasticsearch and the detection API. The Fail2Ban integration leverages the existing Fail2Ban installation, adding a custom jail configuration for AI-triggered bans. This design philosophy --- augmenting rather than replacing existing tools --- lowers the adoption barrier.

**Alert management and SOC workflows.** The two-level detection mechanism (EARLY_WARNING and ALERT) maps naturally to SOC triage workflows. EARLY_WARNING events can be routed to Tier 1 analysts for monitoring, while ALERT events trigger automated response and are escalated to Tier 2 for investigation. The React-based monitoring dashboard provides real-time visibility into detection events, anomaly score trends, and threshold behavior, supporting the analyst's decision-making process. Security operations centers frequently cite alert fatigue as a primary obstacle to effective monitoring [49]; the dynamic threshold's self-calibration and graduated response directly address this concern.

**Resource requirements.** The system was evaluated on a standard server configuration (Table 4.13), with the AI processing stages completing in under 100 ms. The Docker-based deployment requires approximately 4 GB of RAM for all 9 services (Table 4.16), well within the capacity of a modest virtual machine or cloud instance. For organizations with limited infrastructure budgets, the system can be co-hosted on the SSH server itself, although dedicated deployment is recommended for production use to avoid resource contention during attack surges.

### 5.5.2 Scalability Considerations

The current architecture is designed for monitoring a single SSH server or a small cluster of servers. For organizations with larger SSH infrastructure, several scaling strategies are available:

- **Horizontal scaling.** Multiple FastAPI instances can be deployed behind the Nginx reverse proxy to distribute the detection workload across processing nodes.
- **Centralized log collection.** Filebeat or Logstash agents deployed on multiple SSH servers can forward logs to a centralized Elasticsearch cluster, enabling the detection system to monitor multiple servers from a single deployment.
- **Cloud-native deployment.** The Docker Compose configuration can be adapted for Kubernetes orchestration, enabling elastic scaling based on detection workload. Elasticsearch, the most resource-intensive component, can be deployed as a managed service (e.g., Elastic Cloud, Amazon OpenSearch) to offload operational overhead.

When the number of actively monitored IPs scales to thousands, architectural refinements become necessary: replacing in-memory deques with Redis Streams for per-IP window management, implementing batch scoring instead of per-IP individual scoring, and deploying horizontal scaling of detection workers.

### 5.5.3 Cost-Benefit Analysis

The total cost of deploying the system is dominated by infrastructure costs (server provisioning, cloud instance fees) rather than software licensing, as all components are open-source. For a typical single-server deployment monitoring SSH on a Linux server with moderate traffic (hundreds of sessions per day), a cloud instance with 4 vCPUs, 8 GB RAM, and 50 GB storage is sufficient, costing approximately $30--$60/month on major cloud providers. The operational cost of the 29% FPR --- primarily analyst time spent reviewing false positives --- can be estimated at approximately 15--30 minutes per day for a moderate-traffic server, assuming manual review of ALERT-level events. This cost is substantially lower than the potential impact of a successful SSH compromise, which can reach hundreds of thousands of dollars in incident response, remediation, and business disruption costs [1].

## 5.6 Limitations and Threats to Validity

Six principal limitations and threats to validity must be acknowledged.

**L1: Concept drift.** The model is trained on a fixed dataset collected over 5 days. Attack patterns evolve as adversaries develop new tools and strategies, and normal user behavior shifts with organizational changes [8]. The current model will gradually lose effectiveness as the data distribution drifts. Mitigation: periodic retraining on recently collected normal data. Future work (Section 6.2) investigates online learning and incremental Isolation Forest techniques for continuous adaptation without full retraining.

**L2: SSH key-based attacks.** This research focuses exclusively on password-based brute-force attacks. Attacks using stolen SSH keys produce "Accepted publickey" log entries rather than "Failed password" patterns and are therefore invisible to the current feature extraction pipeline [15]. In environments where key-based authentication is the primary method, the system would need to be extended with features capturing key-based anomalies (logins from new IPs, unusual times, newly created key pairs).

**L3: Log format dependency.** The log parser is designed for the standard syslog format used by OpenSSH on Debian/Ubuntu and CentOS/RHEL [18]. Systems using non-standard log formats, alternative SSH implementations (e.g., Dropbear), or centralized log management systems that reformat entries would require parser adaptation. The modular architecture isolates the parsing layer from feature extraction and detection, so adaptation requires modifying only one component.

**L4: Training data diversity.** The training data is derived from a single simulation source with 64 users exhibiting specific behavioral patterns. The diversity of normal SSH behavior in production environments --- including variations in work schedules, geographical distribution, device diversity, and organizational policies --- exceeds what a single simulation captures. In production deployments, collecting normal behavior data from the target environment for a period of 1--2 weeks before activating detection is recommended to improve model generalization.

**L5: False positive rate.** The 29.00% FPR, while acceptable given the cost asymmetry discussed in Section 5.3.4, remains a significant rate of false alarms. In high-traffic environments processing thousands of SSH sessions daily, this would generate a substantial alert volume. The two-level detection mechanism mitigates operational impact, but further FPR reduction through ensemble methods, deep learning, or threat intelligence integration is a priority for future work.

**L6: Evaluation scope.** The evaluation was conducted on data from a single honeypot server over 5 days, with five designed attack scenarios. While the attack scenarios cover the major categories of SSH brute-force attacks (basic, distributed, low-and-slow, credential stuffing, dictionary), the space of possible attack strategies is vast, and novel techniques not represented in the evaluation could potentially evade the system. A multi-site, longitudinal evaluation spanning weeks or months would provide stronger evidence of robustness and generalizability. The 51 unit tests confirm functional correctness but do not substitute for extended operational validation.

**Threats to internal validity.** The primary threat is potential data leakage between training and test sets. This was mitigated by strict temporal separation: the RobustScaler was fit exclusively on the training set (normal data) and applied to transform both training and test sets. Non-overlapping windows in the optimized configuration further reduce temporal correlation between consecutive feature vectors.

**Threats to external validity.** The generalizability of the results to SSH environments with substantially different user populations, usage patterns, or network configurations is unknown. The semi-supervised approach requires that the training data be representative of the target environment's normal behavior; deploying the model trained on our simulation data in a radically different environment without retraining would likely degrade performance. This is a general limitation of all anomaly detection systems, not specific to this work [9, 34].

**Threats to construct validity.** The evaluation metrics (accuracy, F1-score, recall, FPR, ROC-AUC) are standard in the anomaly detection literature [34] and appropriate for the binary classification task. However, these metrics do not fully capture operational utility. Metrics such as mean time to detection (MTTD), analyst investigation time per alert, and the false discovery rate under realistic traffic volumes would provide a more comprehensive operational assessment.

## 5.7 Chapter Summary

This chapter has discussed the experimental results presented in Chapter 4 in the context of the research objectives, the existing literature, and practical deployment considerations. The five research objectives have been achieved: (1) the 14-feature behavioral feature set was designed and validated, with temporal features demonstrated to be the most discriminative; (2) three unsupervised models were trained and compared, with IF selected as the primary model for its balance of performance and operational properties; (3) the EWMA-Adaptive Percentile dynamic threshold was developed and shown to enable early prediction of low-and-slow attacks after 3--5 attempts; (4) the 9-service Docker architecture was built with sub-2-second end-to-end latency; and (5) five attack scenarios were evaluated with robust detection across all types. The comparison with 12 existing studies positions this work as a contribution to the field through its combination of dataset realism, methodological novelty, and engineering completeness. Six limitations were identified, motivating the future work directions presented in Chapter 6.
