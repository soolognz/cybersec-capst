# CHAPTER 5: DISCUSSION

## 5.1 Restate the Research Problem or Objectives

This research set out to answer the central question: *How can an AI-based SSH brute-force attack detection and prevention system be constructed that is capable of early attack prediction, dynamically adapts to changes in traffic patterns, and integrates fully into modern security monitoring infrastructure?* Five specific objectives were formulated to address this question: (1) designing a comprehensive 14-feature SSH behavioral feature set; (2) training and evaluating three unsupervised anomaly detection models; (3) developing an adaptive EWMA-Adaptive Percentile dynamic threshold; (4) building a complete integrated system with 9 Docker services; and (5) evaluating the system against five realistic attack scenarios. The following sections discuss the extent to which each objective was achieved and the broader implications of the findings.

The thesis also posed four subsidiary research questions:

**RQ1:** *How effectively does the Isolation Forest algorithm detect SSH brute-force attacks compared to LOF and One-Class SVM?* The experimental results demonstrate that all three models achieve near-perfect recall (96.75%-100%), confirming the viability of the semi-supervised anomaly detection approach for SSH brute-force detection. After optimization, Isolation Forest achieved an accuracy of 90.31%, an F1-score of 93.74%, a recall of 96.75%, and a false positive rate of 29.00%. While OCSVM achieved a marginally higher F1-score of 94.55%, IF was selected as the primary model due to its computational efficiency (O(n log n)), its production of smooth continuous anomaly scores suitable for the dynamic threshold, and its lack of distributional assumptions.

**RQ2:** *To what extent does the EWMA-Adaptive Percentile dynamic threshold improve detection performance relative to traditional static thresholds?* The dynamic threshold demonstrated three principal advantages: adaptation to distribution shifts in traffic patterns, reduction of burst false positives during periods of legitimate anomalous activity, and rapid detection following quiet periods. Most critically, the EWMA accumulation mechanism enables early warning for low-and-slow attacks after only 3-5 attempts (approximately 2-3 minutes), whereas Fail2Ban with default settings (maxretry=5, findtime=600s) would fail to detect such attacks entirely if attempts are sufficiently spaced.

**RQ3:** *What degree of early prediction does the system achieve across different attack scenarios?* The system was evaluated against five attack scenarios of varying difficulty. Basic brute-force and dictionary attacks were detected immediately (within the first 1-minute window). Distributed attacks and credential stuffing were detected with rates exceeding 90% and 95%, respectively. The low-and-slow scenario, the most challenging case, was detected through the EWMA accumulation mechanism, with early warnings issued after 3-5 attempts. This represents a significant advancement over purely reactive systems.

**RQ4:** *Can the integrated architecture meet real-time monitoring and automated response requirements?* The end-to-end latency of under 2 seconds, with AI processing stages completing in under 100ms, demonstrates that the system fully meets real-time requirements. The Docker-containerized architecture with 9 services provides a production-ready deployment solution that is portable, reproducible, and scalable.

The experimental evaluation described in Chapter 4 provided extensive data on model performance, feature importance, dynamic threshold behavior, and attack scenario detection rates. The following sections discuss the principal findings in detail, examine their implications for the field, compare the results with the existing literature, and identify areas requiring further investigation. The discussion is organized around the key findings that emerged from the experimental evaluation, with emphasis on the practical implications for real-world deployment and the theoretical contributions to the anomaly detection literature.

## 5.2 Summarize Key Findings

### 5.2.1 Overall Model Performance Assessment

The experimental results demonstrate that the semi-supervised anomaly detection approach --- training exclusively on normal data without requiring labeled attack samples --- is both effective and practical for SSH brute-force detection. All three evaluated models achieve near-perfect recall after optimization, confirming that the fundamental premise of the approach is sound: by learning the characteristics of normal SSH behavior, the models can reliably identify deviations that correspond to attack activity.

The optimized Isolation Forest model achieves an accuracy of 90.31%, an F1-score of 93.74%, a recall of 96.75%, and a false positive rate of 29.00%. These results represent a dramatic improvement over the baseline configuration, with accuracy increasing by 9.55 percentage points and FPR decreasing by 47.92 percentage points. The improvement is primarily attributable to three optimization strategies: the use of non-overlapping windows to reduce temporal correlation between consecutive feature vectors, the addition of derived features that increase the discriminative capacity of the feature set, and the careful tuning of the contamination parameter to 0.01 with max_features=0.75 and n_estimators=500.

The One-Class SVM achieves the highest overall F1-score of 94.55% and accuracy of 91.38%, demonstrating the effectiveness of the RBF kernel in capturing the complex, nonlinear decision boundary between normal and attack patterns in the 14-dimensional feature space. However, the computational cost of OCSVM (O(n^2) to O(n^3) for training) and the lack of smooth continuous anomaly scores make it less suitable for the real-time dynamic thresholding architecture.

The LOF model achieves a perfect recall of 100% but exhibits the highest false positive rate of 67.10%, indicating that while it detects every attack, it also generates an excessive number of false alarms. The local density-based approach of LOF is highly sensitive to any deviation from the learned density profile, which produces excellent recall but poor specificity. The ROC-AUC of 65.24% after optimization further confirms that LOF's overall discriminative ability is limited compared to IF and OCSVM.

### 5.2.2 The Primacy of Temporal Features

Perhaps the most significant finding of this research is the demonstrated primacy of temporal features in distinguishing automated brute-force attacks from normal SSH activity. Feature importance analysis using permutation importance on the Isolation Forest model revealed that 4 of the top 5 most important features belong to the temporal and session feature groups: session_duration_mean (5.50%), min_inter_attempt_time (3.86%), mean_inter_attempt_time (2.61%), and std_inter_attempt_time (1.64%).

This finding has important implications for the design of future detection systems. Traditional approaches such as Fail2Ban rely primarily on count-based features (the number of failed login attempts within a time window). However, the experimental results demonstrate that traditional count-based features such as fail_count and invalid_user_count have feature importance values near zero. The reason is that the model is trained on normal data (from the simulation), where these features are consistently low; consequently, the model learns to detect anomalies primarily through temporal variability and connection patterns.

The primacy of session_duration_mean is particularly intuitive: brute-force attacks produce extremely short SSH sessions (typically under 5 seconds, as each failed password attempt results in rapid disconnection), while legitimate users maintain sessions lasting minutes to hours. The bimodal gap between these two distributions is the most reliable discriminator, more robust than count-based features that can be manipulated by attackers through rate control.

This finding aligns with the work of Javed and Paxson (2013), who demonstrated that timing characteristics are the most effective factor for distinguishing SSH brute-force attacks from normal SSH activity, and extends it by quantifying the relative importance of specific temporal features in the context of unsupervised anomaly detection.

### 5.2.2 The Value of Dynamic Thresholding for Early Prediction

The EWMA-Adaptive Percentile dynamic threshold represents a methodological contribution that addresses a fundamental limitation of static threshold approaches. Static thresholds, as employed by Fail2Ban and similar tools, create an inherent trade-off: a low threshold increases sensitivity but generates excessive false positives; a high threshold reduces false positives but misses sophisticated attacks.

The dynamic threshold resolves this trade-off by continuously adapting to the current traffic baseline. The EWMA component (alpha=0.3) tracks the trend of anomaly scores, while the Adaptive Percentile component (base_percentile=95) captures the current distributional characteristics. The sensitivity_factor (1.5) modulates the gap between the baseline and the threshold.

The most compelling evidence for the value of this approach comes from the low-and-slow attack scenario (Scenario 3). In this scenario, the attacker spaces attempts over intervals of 30-120 seconds, deliberately staying below traditional rate-limiting thresholds. The EWMA accumulation mechanism detects the progressive build-up of anomalous activity: each individual anomaly score may not exceed the threshold, but the cumulative effect on the EWMA value pushes it upward. After 3-5 attempts (approximately 2-3 minutes), the EWMA value exceeds the early warning threshold (set at 67% of the alert threshold), triggering an EARLY_WARNING notification. This capability is absent from all purely reactive systems reviewed in the literature.

The two-level detection mechanism (EARLY_WARNING and ALERT) provides operational flexibility. The EARLY_WARNING level only logs the event and notifies administrators without blocking the IP, avoiding service disruption for potentially legitimate users. Only the ALERT level triggers Fail2Ban for active IP blocking. This graduated response is critical in production environments where overly aggressive blocking can disrupt legitimate services.

### 5.2.3 The Trade-Off Between False Positive Rate and Security

The optimized Isolation Forest model achieves a false positive rate of 29.00%, meaning approximately 29% of normal activity is incorrectly classified as attack activity. While this may appear high in absolute terms, it must be evaluated in the context of cybersecurity operations, where the cost asymmetry between false positives and false negatives is extreme.

The cost of a false negative (a missed attack that results in system compromise) far exceeds the cost of a false positive (an unnecessary alert that is reviewed and dismissed). In this framework, a FPR of 29% combined with a recall of 96.75% represents an acceptable operating point, particularly given the system's two-level detection mechanism: EARLY_WARNING events are logged without blocking, and only high-confidence ALERT events trigger active IP blocking.

Furthermore, the self-calibration capability of the dynamic threshold provides a mechanism for reducing FPR over time. As the system accumulates operational data and administrators provide feedback (marking alerts as true or false positives), the threshold parameters can be refined to better reflect the specific environment's baseline behavior.

The FPR of 29% can be further reduced through several approaches: ensemble methods combining multiple models, deep learning techniques (e.g., LSTM-Autoencoders) that can model more complex temporal patterns, and hybrid approaches integrating threat intelligence feeds to provide additional context for classification decisions.

### 5.2.4 Comparative Positioning in the Literature

The systematic comparison with prior works positions this study as a significant contribution to the field:

| Study | Method | Dataset | Early Prediction | Real-time | F1 |
|-------|--------|---------|-----------------|-----------|------|
| Sperotto et al. (2010) | Flow-based | DARPA | No | No | -- |
| Kim et al. (2019) | Random Forest | NSL-KDD | No | No | 0.92 |
| Ahmed et al. (2020) | Autoencoder | CICIDS | No | Yes | 0.89 |
| Nassif et al. (2021) | ML Survey | Multiple | No | Varies | -- |
| **This study** | **IF + EWMA** | **Real SSH** | **Yes** | **Yes** | **0.9374** |

Three aspects distinguish this work from prior research. First, the dataset: this study uses real SSH log data from a honeypot rather than synthetic benchmark datasets (NSL-KDD, CICIDS), providing more representative evaluation conditions. Second, the methodological innovation: the combination of Isolation Forest with EWMA-Adaptive Percentile dynamic thresholding for SSH early prediction has not been previously investigated. Third, the engineering contribution: the system is implemented as a complete end-to-end solution from log parsing to automated blocking, not merely an offline experimental evaluation.

### 5.2.5 Practical Implications for Security Operations

The experimental results have several direct implications for security operations teams considering the deployment of AI-based SSH monitoring solutions.

First, the finding that temporal features are more discriminative than count-based features suggests that security tools should prioritize the collection and analysis of timing information in SSH logs. Many current security monitoring configurations discard or aggregate timing information, retaining only count-based summaries (e.g., "X failed logins from IP Y in Z minutes"). The results of this study indicate that detailed timing information --- inter-attempt intervals, session durations, and their statistical properties --- contains the most valuable signals for attack detection.

Second, the EWMA-Adaptive Percentile dynamic threshold addresses a persistent operational challenge: the need to balance detection sensitivity with false positive control in environments where traffic patterns vary over time. Security operations centers (SOCs) frequently report alert fatigue as a primary obstacle to effective security monitoring, and the dynamic threshold mechanism directly addresses this by automatically adjusting sensitivity based on current conditions. The two-level detection approach (EARLY_WARNING and ALERT) further supports operational workflows by providing graduated response options.

Third, the Docker-containerized architecture addresses the deployment barrier that frequently prevents research prototypes from being adopted in production. The nine-service Docker Compose configuration can be deployed on any server with Docker support, requires no custom infrastructure, and can be started with a single command. This engineering contribution is as important as the algorithmic contribution for practical impact.

Fourth, the system's modular architecture facilitates customization and extension. The log parser, feature extractor, anomaly detection model, dynamic threshold, and response mechanism are implemented as independent modules that can be modified, replaced, or extended without affecting the other components. This modularity supports adaptation to different organizational requirements, SSH configurations, and security policies.

### 5.2.6 System Scalability and Deployment Considerations

The Docker-containerized microservices architecture (9 services) provides a foundation for production deployment with several scalability options:

- **Horizontal scaling.** Multiple API Server instances can be deployed behind the Nginx load balancer to handle increased detection workloads.
- **Cloud deployment.** Docker images can be deployed to Kubernetes or cloud platforms for elastic scaling.
- **Multi-server monitoring.** Filebeat agents can be deployed on multiple SSH servers to collect logs centrally.

The system has been tested with the dataset described in this thesis, handling the detection workload without performance degradation. The sub-2-second end-to-end latency confirms that the current architecture is more than adequate for monitoring a single SSH server or a small cluster of servers. For organizations with moderate SSH infrastructure (up to tens of servers), the current single-instance deployment is likely sufficient.

However, when the number of actively monitored IPs scales to thousands, several architectural refinements would be necessary: replacing in-memory deques with Redis Streams for per-IP window management; implementing batch scoring rather than per-IP individual scoring; and horizontal scaling of detection workers.

### 5.2.6 Attack Scenario Implications

The five-scenario evaluation provides important insights into the operational strengths and weaknesses of the system. The results can be organized into three tiers of detection difficulty:

**Tier 1 (Easy detection): Basic brute-force and dictionary attacks.** These high-speed, single-source attacks produce extreme values across multiple features simultaneously (very high fail_count, fail_rate near 1.0, very low mean_inter_attempt_time, very short session_duration_mean). All three models detect 100% of these attacks immediately, within the first 1-minute detection window. These are the attack types that traditional tools like Fail2Ban handle adequately, and the AI-based system provides no significant advantage for this tier.

**Tier 2 (Moderate detection): Distributed attacks and credential stuffing.** These attacks distribute their activity to avoid triggering per-IP thresholds. For distributed attacks, the detection rate exceeds 90% (OCSVM), with the temporal features (particularly session_duration_mean and min_inter_attempt_time) providing the discriminative signal even when per-IP count features are not anomalous. For credential stuffing, the unique_usernames feature becomes critical, as the attack uses many different usernames that do not exist on the target system. These are attack types where the AI-based system provides clear advantages over traditional threshold-based tools.

**Tier 3 (Difficult detection): Low-and-slow attacks.** These attacks represent the greatest challenge, as the attacker deliberately manipulates temporal features by spacing attempts over intervals of 30-120 seconds. The EWMA accumulation mechanism provides partial mitigation, issuing early warnings after 3-5 attempts, but the detection rate is lower than for other scenarios. This tier identifies the boundary of the current system's capabilities and motivates the future work directions described in Chapter 6, particularly long-term IP profiling and threat intelligence integration.

The tiered analysis reveals an important design principle: the feature set must be broad enough to provide discriminative signals for attacks that manipulate one dimension of behavior (e.g., temporal features for slow attacks) while remaining effective for attacks that are clearly anomalous across all dimensions (e.g., basic brute-force). The 14-feature design achieves this balance, but the results suggest that additional features --- particularly long-term behavioral profiles and external threat intelligence --- could further improve detection across all tiers.

### 5.2.7 Limitations of the Research

Five principal limitations should be acknowledged:

**Concept drift.** Attack patterns evolve over time as adversaries develop new tools, adopt different strategies, and respond to defensive measures. The current model, trained on a fixed dataset, will gradually lose effectiveness as the distribution of both normal behavior and attack behavior shifts. This phenomenon, known as concept drift in the machine learning literature, is a fundamental challenge for all deployed anomaly detection systems. The model's performance should be monitored continuously in production, and periodic retraining should be scheduled based on observed detection metrics. Future work could apply online learning or incremental learning techniques to enable continuous model adaptation without full retraining, potentially using algorithms such as Incremental Isolation Forest that can incorporate new data points without rebuilding the entire ensemble from scratch.

**SSH key-based attacks.** This research focuses exclusively on password-based brute-force attacks. Attacks using stolen SSH keys do not produce "Failed password" log patterns and are therefore invisible to this system. In environments where SSH key authentication is the primary method, the detection system would need to be extended with additional features that capture key-based authentication anomalies, such as logins from previously unseen IP addresses, logins at unusual times, or the use of newly created or recently modified key pairs. This represents a significant extension that is beyond the scope of the current research but constitutes an important direction for future work.

**Log format dependency.** The log parser is designed for the standard syslog format used by OpenSSH on Debian/Ubuntu (/var/log/auth.log) and CentOS/RHEL (/var/log/secure). Systems using custom log formats, alternative SSH implementations, or non-standard logging configurations would require parser adjustments before the system can be deployed. This dependency on specific log format conventions may limit the immediate applicability of the system in heterogeneous environments without customization. However, the modular architecture separates the parsing layer from the feature extraction and detection layers, so adaptation to new log formats requires only modification of the parser component.

**Training data diversity.** The training data is derived from a single simulation source representing a specific organizational environment with 64 users exhibiting particular behavioral patterns. The diversity of normal SSH behavior in the real world --- including variations in work schedules, geographical distribution, device diversity, and organizational policies --- is considerably greater than what any single simulation can capture. In production deployments, collecting normal behavior data from multiple servers with diverse usage patterns is strongly recommended to improve model generalization. The semi-supervised approach inherently supports this: the training set can be expanded simply by collecting additional normal operational data from the target deployment environment.

**FPR improvement potential.** Although the FPR was reduced from 76.92% (baseline) to 29.00% (optimized), this remains a significant rate of false alarms. In a production environment processing thousands of SSH sessions daily, a 29% FPR would generate a substantial number of false alerts, potentially causing alert fatigue among security operations personnel. Several avenues for further FPR reduction exist: ensemble methods that combine the predictions of multiple models through majority voting or weighted averaging; deep learning techniques (such as LSTM-Autoencoders) that can model more complex temporal patterns and potentially achieve better normal-attack separation; hybrid approaches that integrate external threat intelligence feeds to provide additional context for classification decisions; and active learning approaches where administrator feedback on false positives is used to iteratively refine the model's decision boundary.

**Evaluation scope.** The evaluation was conducted on a dataset collected over 5 days from a single honeypot server, which may not fully represent the diversity of attack patterns observed over longer time periods or across different geographic regions. Additionally, the five attack scenarios were designed to represent the major categories of SSH brute-force attacks, but the space of possible attack strategies is vast, and novel attack techniques not represented in the evaluation could potentially evade the system. A longer-term, multi-site evaluation would provide stronger evidence of the system's robustness and generalizability.
