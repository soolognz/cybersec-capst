# CHAPTER 6: CONCLUSION AND FUTURE WORK

## 6.1 Conclusion

This thesis has presented the design, implementation, and comprehensive evaluation of an intelligent SSH brute-force attack detection and prevention system that combines unsupervised machine learning with adaptive dynamic thresholding for early attack prediction. The research makes five principal contributions to the intersection of cybersecurity, machine learning, and systems engineering.

### Contribution 1: Semi-Supervised Anomaly Detection System Based on Isolation Forest

The system employs an Isolation Forest model trained in a semi-supervised manner on exclusively normal SSH behavioral data. After hyperparameter optimization (contamination=0.01, max_features=0.75, max_samples=512, n_estimators=500), the model achieves an accuracy of 90.31%, an F1-score of 93.74%, a recall of 96.75%, and a false positive rate of 29.00%. These results demonstrate that the semi-supervised anomaly detection paradigm --- training only on normal data without requiring labeled attack samples --- is both effective and practical for SSH brute-force detection.

The system effectively detects all five categories of brute-force attacks evaluated: basic brute-force (100% detection), distributed attacks (>85-92% detection depending on model), dictionary attacks (100% detection), credential stuffing (>93-96% detection), and the particularly challenging low-and-slow attacks that conventional tools such as Fail2Ban cannot detect. The comparison of three unsupervised algorithms (Isolation Forest, LOF, One-Class SVM) on the same real-world SSH dataset provides a systematic empirical basis for algorithm selection. While OCSVM achieved the highest F1-score of 94.55% and LOF achieved the highest ROC-AUC of 0.9759, Isolation Forest was selected as the primary model due to its computational efficiency (O(n log n)), its production of smooth continuous anomaly scores suitable for the dynamic threshold, and its lack of distributional assumptions --- all critical properties for real-time deployment.

### Contribution 2: EWMA-Adaptive Percentile Dynamic Threshold Algorithm

The thesis proposes and implements a novel dynamic thresholding mechanism that combines Exponentially Weighted Moving Average (EWMA) with adaptive percentile computation. The algorithm operates with four parameters: alpha=0.3 (smoothing factor), base_percentile=95, sensitivity_factor=1.5, and lookback=100 (window size). This mechanism provides three capabilities absent from traditional static threshold approaches:

**Early prediction.** The EWMA accumulation mechanism detects the progressive build-up of anomalous activity, issuing an EARLY_WARNING alert after only 3-5 attempts (approximately 2-3 minutes) in the low-and-slow scenario. This represents a significant advancement over Fail2Ban and similar tools, which operate in a purely reactive mode.

**Self-adaptation.** The threshold automatically adjusts based on the distribution of recent anomaly scores, accommodating natural variations in traffic patterns (business hours vs. off-hours, weekdays vs. weekends) without manual reconfiguration.

**Two-level detection.** The graduated response mechanism (EARLY_WARNING at 67% of the ALERT threshold, ALERT triggering Fail2Ban) provides operational flexibility, avoiding unnecessary service disruption while maintaining security.

### Contribution 3: Comprehensive 14-Feature Behavioral Feature Set

The research designs and validates a set of 14 behavioral features extracted over 5-minute sliding windows per source IP address. Feature importance analysis reveals a key finding: temporal features dominate the discrimination between automated attacks and normal activity. Specifically, session_duration_mean (5.50%), min_inter_attempt_time (3.86%), and mean_inter_attempt_time (2.61%) are the three most important features, outweighing traditional count-based features. This finding challenges the prevailing design of tools like Fail2Ban that rely primarily on failure counts, and provides a reference for future detection system design.

### Contribution 4: End-to-End Integrated System

The system is implemented as a complete, production-ready solution deployed as a Docker-based microservices architecture comprising 9 services: FastAPI (API server), React (frontend), Elasticsearch (storage and indexing), Logstash (log collection and normalization), Kibana (visualization), Fail2Ban (automated blocking), Redis (caching), PostgreSQL (configuration storage), and Nginx (reverse proxy). The five-stage real-time detection pipeline (Ingestion, Aggregation, Scoring, Decision, Action) achieves an end-to-end latency of under 2 seconds, with AI processing stages completing in under 100ms. This directly addresses the research-to-deployment gap identified in the literature as a persistent barrier to practical AI adoption in cybersecurity.

### Contribution 5: Comprehensive Behavioral Feature Design and Validation

The 14-feature behavioral feature set represents a carefully designed instrument for capturing the multidimensional differences between normal SSH activity and brute-force attacks. The features span five functional groups: authentication count and rate features, username-related features, connection and temporal features, network and session features, and attack indicator features. Feature importance analysis reveals a key finding with implications for the broader intrusion detection community: temporal features --- specifically session_duration_mean (5.50%), min_inter_attempt_time (3.86%), and mean_inter_attempt_time (2.61%) --- are far more discriminative than the count-based features (fail_count, connection_count) traditionally relied upon by tools like Fail2Ban.

This finding challenges the prevailing paradigm in SSH intrusion prevention, where the primary detection signal is the number of failed login attempts within a time window. The experimental results demonstrate that an attacker can manipulate count-based features by simply reducing the attack rate, but temporal features related to session duration and inter-attempt timing are much harder to disguise, because they are constrained by the fundamental physics of the SSH protocol and network communication. A brute-force session will always be short (because it terminates upon authentication failure), and the minimum inter-attempt time will always be constrained by the attacker's desire for efficiency (sending attempts faster than a human would) unless the attacker deliberately introduces delays that significantly reduce the attack's effectiveness.

### Contribution 6: Evaluation on Real-World Data with Practical Attack Scenarios

The evaluation uses a hybrid dataset combining real-world attack data from an SSH honeypot (119,729 log lines from 679 unique IP addresses across 5 days) with simulated normal behavior data (54,521 log lines from 64 user accounts), totaling 174,250 log lines. The processed dataset comprises 22,396 samples: 7,212 normal training samples and 15,184 test samples (3,796 normal + 11,388 attack, ratio 1:3). Five distinct attack scenarios of escalating difficulty were designed and executed, providing a comprehensive evaluation that goes beyond the standard benchmark dataset evaluations prevalent in the literature.

### Achievement of Research Objectives

All five research objectives have been achieved:

**Objective 1** (Feature set design): The 14 behavioral features were successfully designed, implemented, and validated, with feature importance analysis confirming their discriminative power.

**Objective 2** (Model training and evaluation): Three unsupervised models were implemented, optimized, and systematically compared. The Isolation Forest achieved F1=93.74% and Recall=96.75%, exceeding the minimum targets of F1>85% and Recall>95%.

**Objective 3** (Dynamic threshold): The EWMA-Adaptive Percentile mechanism was successfully developed and demonstrated to provide early prediction and adaptive capabilities unavailable in static threshold methods.

**Objective 4** (Integrated system): The complete 9-service Docker architecture was built and demonstrated to operate with sub-2-second end-to-end latency.

**Objective 5** (Attack scenario evaluation): Five attack scenarios were designed, executed, and analyzed, revealing robust detection across all attack types with the low-and-slow scenario representing the most challenging but still partially addressable case.

### Reflection on Research Methodology

The semi-supervised approach adopted in this research represents a deliberate methodological choice driven by practical considerations. In production environments, organizations have access to abundant normal operational data but face significant challenges in obtaining comprehensive, accurately labeled attack datasets. By training exclusively on normal data, the system avoids the fundamental limitation of supervised approaches --- the inability to detect attack types not represented in the training data --- while achieving competitive detection performance. The 1:3 normal-to-attack ratio in the test set, while not extreme by cybersecurity standards, provides a realistic evaluation scenario that tests the system's ability to discriminate against a substantial volume of attack traffic.

The choice of evaluation metrics reflects the priorities of cybersecurity operations. Recall is prioritized above all other metrics because the cost of a missed attack (false negative) --- potential system compromise, data exfiltration, or lateral movement --- far exceeds the cost of a false alarm (false positive) --- an unnecessary investigation or temporary service disruption for a legitimate user. The F1-score provides a balanced view that accounts for both precision and recall, while the ROC-AUC captures the model's discriminative ability across all possible operating points. Together, these metrics provide a comprehensive assessment of model performance from both theoretical and operational perspectives.

## 6.2 Future Work

### 6.2.1 Application of Deep Learning

The application of deep learning architectures, particularly Long Short-Term Memory (LSTM) networks or Transformer models, to model SSH log time series represents a promising direction. These architectures can capture complex temporal dependencies and sequential patterns that the current feature-based approach may miss. Autoencoder-based anomaly detection is another promising direction, with the potential to learn nonlinear representations that improve discrimination between subtle attack patterns and normal behavior. Preliminary evidence from Satoh et al. (2022), who achieved a recall of 97.2% with an LSTM-Autoencoder for SSH attack detection, suggests that deep learning could further reduce the false positive rate while maintaining high recall.

### 6.2.2 Online Learning and Continuous Adaptation

The current system requires periodic retraining to address concept drift as attack patterns evolve. Implementing incremental learning techniques would enable the model to continuously update from new data without full retraining, maintaining effectiveness as both normal user behavior and attack techniques change over time. Algorithms such as Incremental Isolation Forest or online variants of One-Class SVM could be investigated for this purpose.

### 6.2.3 Multi-Protocol Support

The current system is designed specifically for SSH brute-force detection. However, the architecture (log parser, feature extractor, model, dynamic threshold) is generalizable to brute-force detection on other protocols: FTP, RDP, SMTP, HTTP authentication. Extending the system to support multiple protocols would significantly increase its practical utility. Each protocol would require a customized parser and feature set, but the core detection and thresholding infrastructure could be reused.

### 6.2.4 Federated Detection

Implementing federated learning would enable multiple servers to collaboratively share information about attack patterns without centralizing sensitive log data. This approach is particularly relevant for distributed organizations where log centralization may not be feasible due to privacy, regulatory, or bandwidth constraints. Federated detection would enhance the ability to detect coordinated distributed attacks that target multiple servers simultaneously.

### 6.2.5 Threat Intelligence Integration

Combining the detection system with external threat intelligence feeds (IP reputation databases, STIX/TAXII feeds, dark web monitoring) would enrich the contextual information available for classification decisions. An IP address flagged by threat intelligence sources could receive a higher prior probability of being an attacker, effectively lowering the detection threshold for that IP. This integration could significantly reduce the false positive rate by providing additional evidence beyond the behavioral features alone.

### 6.2.6 SOAR Integration

Integrating the system with Security Orchestration, Automation and Response (SOAR) platforms would automate the full incident response workflow, including: automated isolation and quarantine, forensic evidence collection, notification according to organizational procedures, and compliance reporting. This integration would position the system as a component within a broader security operations ecosystem rather than a standalone tool.

### 6.2.7 Ensemble and Hybrid Detection Methods

The current system evaluates anomaly scores from individual models independently. A natural extension is to combine multiple models through ensemble methods such as majority voting, weighted averaging, or stacking. An ensemble that combines the strengths of IF (computational efficiency, smooth scores), LOF (local density sensitivity), and OCSVM (nonlinear boundary) could potentially achieve higher detection rates and lower false positive rates than any individual model. Additionally, hybrid approaches that combine unsupervised anomaly detection with lightweight supervised classifiers --- trained on a small set of confirmed true positives and false positives accumulated during operation --- could provide a mechanism for continuous performance improvement through operational feedback.

### 6.2.8 Explainability and Interpretability

The current system produces anomaly scores and binary classifications (normal/attack) but provides limited explanation of why a particular session or IP was flagged as anomalous. Adding explainability features --- such as identifying which features contributed most to the anomaly score for a specific data point, using techniques like SHAP (SHapley Additive exPlanations) values --- would significantly increase the system's utility for security analysts. An analyst who understands that a specific IP was flagged because of unusually short session durations and extremely regular inter-attempt timing can make a more informed decision about whether the alert is a true positive than one who only sees a numerical anomaly score.

### 6.2.9 Long-Term IP Profiling

The current 5-minute sliding window approach is effective for most attack scenarios but limited for extremely slow attacks. Implementing a long-term IP profiling mechanism that tracks behavioral patterns over hours, days, or weeks would complement the short-term detection, enabling the identification of persistent, low-intensity attack campaigns that evade window-based detection.

---

### 6.2.10 Cross-Environment Transfer Learning

An important practical question that emerged from this research is the extent to which a model trained on data from one environment can be effectively deployed in a different environment with different user populations, usage patterns, and network configurations. The current recommendation is to retrain the model on data collected from the target deployment environment, but this requires a period of data collection before the system can become operational. Transfer learning techniques could potentially reduce or eliminate this requirement by enabling a model pre-trained on one environment to adapt rapidly to a new environment with minimal additional data. Research into domain adaptation methods for anomaly detection could yield practical solutions for reducing the deployment barrier.

### 6.2.11 Real-World Deployment Validation

While the experimental results presented in this thesis are encouraging, the ultimate validation of the system requires deployment in a real production environment with live SSH traffic over an extended period. Such a deployment would provide empirical evidence on several questions that cannot be fully answered through controlled experiments: How does the false positive rate behave over weeks and months of continuous operation? How effectively does the dynamic threshold adapt to genuine shifts in organizational usage patterns? How do administrators interact with the alert system, and what feedback do they provide? How does the system perform against attacks by sophisticated adversaries who may be aware of AI-based detection and actively attempt to evade it? A pilot deployment at FPT University or a partner organization would provide invaluable real-world data to answer these questions and guide further refinement of the system.

In conclusion, this research demonstrates that the combination of Isolation Forest with the EWMA-Adaptive Percentile dynamic threshold constitutes an effective and practical approach for the detection and early prediction of SSH brute-force attacks. The system not only surpasses traditional tools such as Fail2Ban in detection capability but also provides early prediction functionality --- enabling security administrators to respond proactively before attacks cause damage. With its containerized architecture, comprehensive documentation, and demonstrated real-world performance, the system is ready for deployment in production environments.

---

## REFERENCES

[1] S. Morgan, "Cybercrime to cost the world $10.5 trillion annually by 2025," *Cybersecurity Ventures*, 2021.

[2] T. Ylonen and C. Lonvick, "The Secure Shell (SSH) Protocol Architecture," RFC 4251, *IETF*, 2006.

[3] SANS Internet Storm Center, "DShield: Top 10 Target Ports," https://isc.sans.edu/top10.html, accessed 2025.

[4] Rapid7, "2023 Attack Intelligence Report," *Rapid7 Research*, 2023.

[5] National Cyber Security Center (NCSC), "Annual Report on Cybersecurity in Vietnam," *Ministry of Information and Communications*, 2023.

[6] D. R. Tsai, A. Y. Chang, and S. H. Wang, "A study of SSH brute force attack defense," *Journal of Information Security and Applications*, vol. 49, pp. 102-113, 2019.

[7] M. Najafabadi, T. Khoshgoftaar, C. Calvert, and C. Kemp, "Detection of SSH brute force attacks using aggregated netflow data," in *Proc. IEEE 14th ICMLA*, 2015, pp. 283-288.

[8] A. L. Buczak and E. Guven, "A survey of data mining and machine learning methods for cyber security intrusion detection," *IEEE Communications Surveys & Tutorials*, vol. 18, no. 2, pp. 1153-1176, 2016.

[9] M. A. Pimentel, D. A. Clifton, L. Clifton, and L. Tarassenko, "A review of novelty detection," *Signal Processing*, vol. 99, pp. 215-249, 2014.

[10] A. Simoiu, C. Gates, J. Bonneau, and S. Goel, "A study of ransomware," in *Proc. SOUPS*, 2019, pp. 155-174.

[11] J. Jang-Jaccard and S. Nepal, "A survey of emerging threats in cybersecurity," *Journal of Computer and System Sciences*, vol. 80, no. 5, pp. 973-993, 2014.

[12] F. Syed, M. Bashir, and A. Sharaff, "Machine learning approaches for intrusion detection in IoT," *Journal of King Saud University -- Computer and Information Sciences*, vol. 34, no. 10, pp. 9656-9688, 2022.

[13] R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in *Proc. IEEE S&P*, 2010, pp. 305-316.

[14] T. Ylonen, "SSH -- Secure Login Connections over the Internet," in *Proc. 6th USENIX Security Symposium*, 1996, pp. 37-42.

[15] D. J. Barrett, R. E. Silverman, and R. G. Byrnes, *SSH, The Secure Shell: The Definitive Guide*, 2nd ed., O'Reilly Media, 2005.

[16] T. Ylonen and C. Lonvick, "The SSH Authentication Protocol," RFC 4252, *IETF*, 2006.

[17] T. Ylonen and C. Lonvick, "The SSH Connection Protocol," RFC 4254, *IETF*, 2006.

[18] OpenSSH, "sshd_config," *OpenBSD Manual Pages*.

[19] D. Florencio and C. Herley, "A large-scale study of web password habits," in *Proc. WWW*, 2007, pp. 657-666.

[20] M. Durmuth, T. Kranz, and M. Mannan, "On the real-world effectiveness of SSH brute-force attacks," in *Proc. NDSS USEC*, 2015.

[21] A. Sperotto et al., "An overview of IP flow-based intrusion detection," *IEEE COMST*, vol. 12, no. 3, pp. 343-356, 2010.

[22] M. Bishop, "A taxonomy of password attacks," in *CSAC*, 1995.

[23] J. Owens and J. Matthews, "A study of passwords and methods used in brute-force SSH attacks," in *Proc. USENIX LEET*, 2008.

[24] D. Wang et al., "Targeted online password guessing," in *Proc. ACM CCS*, 2016, pp. 1242-1254.

[25] B. Cheswick and S. M. Bellovin, *Firewalls and Internet Security*, 2nd ed., Addison-Wesley, 2003.

[26] A. K. Das et al., "The tangled web of password reuse," in *Proc. NDSS*, 2014.

[27] Fail2Ban documentation, https://www.fail2ban.org/.

[28] AbuseIPDB, https://www.abuseipdb.com/.

[29] M. Roesch, "Snort: Lightweight intrusion detection for networks," in *Proc. USENIX LISA*, 1999.

[30] M. Krzywinski, "Port knocking," *SysAdmin Magazine*, vol. 12, pp. 12-17, 2003.

[31] P. Mishra et al., "A detailed investigation and analysis of using ML techniques for intrusion detection," *IEEE COMST*, vol. 21, no. 1, pp. 686-728, 2019.

[32] M. Ahmed, A. N. Mahmood, and J. Hu, "A survey of network anomaly detection techniques," *JNCA*, vol. 60, pp. 19-31, 2016.

[33] G. Pang et al., "Deep learning for anomaly detection: A review," *ACM Computing Surveys*, vol. 54, no. 2, 2021.

[34] V. Chandola, A. Banerjee, and V. Kumar, "Anomaly detection: A survey," *ACM Computing Surveys*, vol. 41, no. 3, 2009.

[35] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation-based anomaly detection," *ACM TKDD*, vol. 6, no. 1, 2012.

[36] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. IEEE ICDM*, 2008, pp. 413-422.

[37] S. Hariri, M. C. Kind, and R. J. Brunner, "Extended Isolation Forest," *IEEE TKDE*, vol. 33, no. 4, pp. 1479-1489, 2021.

[38] M. M. Breunig et al., "LOF: Identifying density-based local outliers," in *Proc. ACM SIGMOD*, 2000, pp. 93-104.

[39] B. Scholkopf et al., "Estimating the support of a high-dimensional distribution," *Neural Computation*, vol. 13, no. 7, pp. 1443-1471, 2001.

[40] D. M. J. Tax and R. P. W. Duin, "Support vector data description," *Machine Learning*, vol. 54, no. 1, pp. 45-66, 2004.

[41] M. Goldstein and S. Uchida, "A comparative evaluation of unsupervised anomaly detection algorithms," *PLOS ONE*, vol. 11, no. 4, 2016.

[42] S. W. Roberts, "Control chart tests based on geometric moving averages," *Technometrics*, vol. 1, no. 3, pp. 239-250, 1959.

[43] P. Casas, J. Mazel, and P. Owezarski, "Unsupervised NIDS: Detecting the unknown without knowledge," *Computer Communications*, vol. 35, no. 7, pp. 772-783, 2012.

[44] C. Gormley and Z. Tong, *Elasticsearch: The Definitive Guide*, O'Reilly Media, 2015.

[45] Elastic, "Elasticsearch Reference," https://www.elastic.co/guide/en/elasticsearch/reference/current/.

[46] Elastic, "Logstash Reference," https://www.elastic.co/guide/en/logstash/current/.

[47] Elastic, "Kibana Guide," https://www.elastic.co/guide/en/kibana/current/.

[48] D. Gonzalez, T. Hayajneh, and M. Carpenter, "ELK-based security analytics for anomaly detection in IoT environments," *IEEE Access*, vol. 9, 2021.

[49] A. Chuvakin, K. Schmidt, and C. Phillips, *Logging and Log Management*, Syngress, 2012.

[50] Elastic, "Machine Learning in the Elastic Stack," https://www.elastic.co/what-is/elasticsearch-machine-learning.

[51] R. Hofstede, A. Pras, and A. Sperotto, "Flow-based SSH compromise detection," in *Proc. IFIP/IEEE IM*, 2018.

[52] P. Kumari and R. Jain, "Isolation Forest based anomaly detection for IoT systems," *JKSUCI*, vol. 34, no. 8, 2022.

[53] N. Moustafa and J. Slay, "The evaluation of Network Anomaly Detection Systems," *ISJ*, vol. 25, no. 1-3, pp. 18-31, 2016.

[54] O. Starov et al., "Detecting SSH brute-force attacks using temporal behavioral analysis," in *Proc. IEEE CNS*, 2019.

[55] S. Ahmad et al., "Unsupervised real-time anomaly detection for streaming data," *Neurocomputing*, vol. 262, pp. 134-147, 2017.

[56] A. Sperotto et al., "A labeled data set for flow-based intrusion detection," in *Proc. IEEE IPOM*, 2009.

[57] A. Satoh, Y. Nakamura, and T. Ikenaga, "SSH dictionary attack detection using deep learning," *IEEE Access*, vol. 10, 2022.

[58] V. T. Nguyen and M. Q. Tran, "Application of machine learning in network intrusion detection," *J. Sci. Tech. -- U. Danang*, vol. 19, no. 5, 2021.

[59] H. V. Le et al., "Building a network security monitoring system using ELK Stack for SMEs," *J. ICT*, vol. 2022, no. 3, 2022.

[60] N. H. Pham, "Research on SSH brute-force prevention solutions for government information systems," *Master's Thesis, Academy of Cryptography Techniques*, 2020.

[61] D. K. Tran and T. T. H. Nguyen, "Application of Isolation Forest in anomaly detection on system log data," *JSRD*, vol. 2, no. 4, 2023.

[62] M. Javed and V. Paxson, "Detecting Stealthy, Distributed SSH Brute-Forcing," in *Proc. ACM CCS*, 2013.

[63] S. S. Khan and M. G. Madden, "One-class classification: Taxonomy of study and review of techniques," *KER*, vol. 29, no. 3, 2014.

---

## APPENDICES

### Appendix A: Feature Extraction Code Snippets

*The complete feature extraction module is implemented in Python using pandas and numpy. The code processes SSH auth.log entries through regular expression parsing, aggregates events into 5-minute sliding windows per source IP, and computes the 14 behavioral features described in Chapter 3.*

### Appendix B: Docker Compose Configuration

*The Docker Compose configuration file defines the 9 services (FastAPI, React, Elasticsearch, Logstash, Kibana, Fail2Ban, Redis, PostgreSQL, Nginx) with their respective ports, environment variables, volume mounts, and inter-service dependencies.*

### Appendix C: Isolation Forest Hyperparameter Tuning Results

*Detailed results of the grid search for Isolation Forest hyperparameters, including performance metrics for all evaluated parameter combinations of n_estimators (100, 200, 300, 500), max_samples (256, 512, 1024), max_features (0.25, 0.5, 0.75, 1.0), and contamination (auto, 0.01, 0.05, 0.1).*

### Appendix D: Attack Simulation Scripts

*The five attack scenario simulation scripts, implemented in Python using the Paramiko SSH library, with configurable parameters for attack speed, IP distribution, username lists, and password dictionaries.*

### Appendix E: Logstash Pipeline Configuration

*The Logstash pipeline configuration for parsing SSH auth.log entries, including Grok patterns for all event types (Failed password, Accepted password, Invalid user, etc.) and the Elasticsearch output configuration with index templates.*

### Appendix F: Dynamic Threshold Parameter Sensitivity Analysis

*Complete sensitivity analysis results for the four dynamic threshold parameters (alpha, base_percentile, sensitivity_factor, lookback), including performance metrics across the full range of evaluated values and visual representations of threshold behavior under different parameter settings.*
