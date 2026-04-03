# CHAPTER 6: CONCLUSION AND FUTURE WORK

## 6.1 Conclusion

This thesis has presented the design, implementation, and comprehensive evaluation of an intelligent SSH brute-force attack detection and prevention system that combines unsupervised machine learning with adaptive dynamic thresholding for early attack prediction. The system addresses a well-documented gap in the cybersecurity landscape: the inability of conventional, static-threshold tools such as Fail2Ban [27] to detect sophisticated attack variants --- particularly low-and-slow brute-force, distributed brute-force, and credential stuffing attacks --- and the persistent disconnect between machine learning research prototypes and deployable production systems [13].

The research was guided by four research questions. The answers to each, grounded in the experimental evidence presented in Chapter 4 and discussed in Chapter 5, are summarized below.

**RQ1: How effectively does the Isolation Forest algorithm detect SSH brute-force attacks compared to LOF and One-Class SVM?**

All three unsupervised anomaly detection models achieve high recall (96.75%--100%) on the hybrid dataset of 174,250 SSH log lines, confirming the viability of the semi-supervised paradigm --- training exclusively on normal data without labeled attack samples --- for SSH brute-force detection. After optimization, the Isolation Forest achieves an accuracy of 90.31%, an F1-score of 93.74%, a recall of 96.75%, and a false positive rate of 29.00%. OCSVM achieves the highest F1-score of 94.55% and accuracy of 91.38%, while LOF achieves perfect recall (100%) but exhibits the highest FPR of 67.10%. The Isolation Forest was selected as the primary production model due to its computational efficiency (O(n log n)), its production of smooth continuous anomaly scores suitable for the dynamic threshold, and its lack of distributional assumptions --- properties critical for real-time deployment [35, 36].

**RQ2: To what extent does the EWMA-Adaptive Percentile dynamic threshold improve detection performance relative to traditional static thresholds?**

The dynamic threshold (alpha = 0.3, base_percentile = 95, sensitivity_factor = 1.5) provides three capabilities absent from static thresholds: self-adaptation to traffic pattern changes, reduction of burst false positives during legitimate anomalous activity, and early warning through EWMA accumulation. The most significant advantage is the detection of low-and-slow attacks: the EWMA mechanism issues early warnings after 3--5 attempts (approximately 2--3 minutes), whereas Fail2Ban with default settings (maxretry = 5, findtime = 600 s) fails to detect such attacks when attempts are spaced at intervals exceeding 2 minutes [27].

**RQ3: What degree of early prediction does the system achieve across different attack scenarios?**

Five attack scenarios of escalating difficulty were evaluated. Basic brute-force and dictionary attacks were detected immediately (100% within the first 1-minute window). Distributed attacks and credential stuffing achieved detection rates exceeding 90% and 95%, respectively. Low-and-slow attacks --- the most challenging case --- were detected through EWMA accumulation, with early warnings issued after 3--5 attempts. This graduated detection capability, ranging from immediate response for high-speed attacks to early warning for stealthy attacks, represents a significant advancement over purely reactive systems.

**RQ4: Can the integrated architecture meet real-time monitoring and automated response requirements?**

The 9-service Docker architecture achieves an end-to-end detection latency of under 2 seconds, with AI processing stages completing in under 100 ms (Table 4.14). The five-stage pipeline (Ingestion, Aggregation, Scoring, Decision, Action) processes SSH authentication events from log parsing through anomaly scoring to automated IP blocking via Fail2Ban, operating continuously without manual intervention. The system was validated with 51 passing unit tests across all components and 5 integrated attack scenario evaluations, confirming both functional correctness and operational readiness.

In summary, this research demonstrates that the combination of Isolation Forest with EWMA-Adaptive Percentile dynamic thresholding constitutes an effective and practical approach for SSH brute-force detection and early prediction. The system surpasses traditional tools such as Fail2Ban in detection capability --- particularly for low-and-slow and distributed attacks --- while providing early prediction functionality that enables security administrators to respond proactively before attacks cause damage. The containerized architecture, comprehensive feature engineering, and demonstrated real-world performance position the system for deployment in production environments.

## 6.2 Contributions Summary

The research makes the following five principal contributions:

**Contribution 1: Semi-supervised anomaly detection system for SSH brute-force attacks.** The system employs an Isolation Forest model trained exclusively on normal SSH behavioral data, achieving an F1-score of 93.74%, recall of 96.75%, and FPR of 29.00% after optimization. The systematic comparison of three unsupervised algorithms (IF, LOF, OCSVM) on the same real-world SSH dataset provides an empirical basis for algorithm selection in the SSH anomaly detection domain, demonstrating that IF offers the best trade-off between detection performance and operational properties for real-time deployment [35, 41].

**Contribution 2: EWMA-Adaptive Percentile dynamic threshold algorithm.** The thesis proposes and validates a novel dynamic thresholding mechanism that combines EWMA trend tracking with adaptive percentile computation. The algorithm provides early prediction of low-and-slow attacks (detection after 3--5 attempts, approximately 2--3 minutes), self-adaptation to traffic pattern changes, and graduated two-level response (EARLY_WARNING and ALERT). This mechanism addresses the fundamental limitation of static thresholds and has not been previously applied to SSH brute-force detection [42, 55].

**Contribution 3: Empirical demonstration of temporal feature dominance.** Feature importance analysis reveals that temporal features --- session_duration_mean (5.50%), min_inter_attempt_time (3.86%), mean_inter_attempt_time (2.61%) --- are far more discriminative than the count-based features traditionally relied upon by tools such as Fail2Ban. This finding, corroborating Javed and Paxson [62] and Starov et al. [54], provides quantitative evidence for prioritizing timing information in SSH security monitoring systems.

**Contribution 4: End-to-end integrated system architecture.** The complete detection and prevention system is implemented as a Docker-based microservices architecture comprising 9 services (FastAPI, React, Elasticsearch, Logstash, Kibana, Fail2Ban, Redis, PostgreSQL, Nginx) with sub-2-second end-to-end latency. This engineering contribution directly addresses the research-to-deployment gap identified by Sommer and Paxson [13] and Nassif et al. [31] as a persistent barrier to practical ML adoption in cybersecurity.

**Contribution 5: Evaluation on real-world data with practical attack scenarios.** The evaluation uses a hybrid dataset of 174,250 SSH log lines combining real honeypot attack data (119,729 lines from 679 unique IPs across 5 days) with simulated normal data (54,521 lines from 64 users). Five attack scenarios of escalating difficulty were designed, executed, and analyzed, providing a more ecologically valid evaluation than the synthetic benchmark datasets (NSL-KDD, CICIDS2017) prevalent in the literature [53].

## 6.3 Future Work

The limitations identified in Section 5.6 and the insights gained during this research motivate the following directions for future investigation.

### 6.3.1 Deep Learning for Improved Detection

The application of deep learning architectures to SSH anomaly detection represents the most promising direction for improving detection performance, particularly for reducing the false positive rate while maintaining high recall. Three specific architectures merit investigation.

**LSTM-Autoencoders.** Long Short-Term Memory networks can model sequential dependencies in SSH authentication event streams that the current feature-based approach (which aggregates events into fixed 5-minute windows) may lose. An LSTM-Autoencoder trained on sequences of normal authentication events would learn to reconstruct normal patterns; sequences that produce high reconstruction error would be flagged as anomalous. Satoh et al. [57] achieved a recall of 97.2% with an LSTM approach for SSH dictionary attack detection, suggesting that deep learning could match or exceed the current system's recall while potentially reducing the FPR below 29%.

**Transformer-based models.** The self-attention mechanism of Transformer architectures [33] can capture long-range dependencies between authentication events that are distant in time but semantically related (e.g., reconnaissance probes preceding an attack campaign). Transformers have achieved state-of-the-art results in multiple sequence modeling domains and have recently been applied to anomaly detection in time series data.

**Hybrid ensemble approaches.** Rather than replacing the Isolation Forest entirely, a promising architecture would combine the IF's computational efficiency for initial screening with a deep learning model for refined classification of ambiguous cases. Events with anomaly scores near the decision boundary --- where false positives are most likely --- could be forwarded to a more expressive model for secondary analysis, combining the throughput of IF with the accuracy of deep learning.

### 6.3.2 Online Learning and Continuous Adaptation

The current system requires periodic retraining to address concept drift as both attack patterns and normal user behavior evolve over time [8]. This limitation can be addressed through online or incremental learning techniques.

**Incremental Isolation Forest.** The standard Isolation Forest algorithm does not support incremental updates; adding new training data requires rebuilding the entire ensemble from scratch. Recent work on streaming Isolation Forest variants enables the incorporation of new data points by selectively replacing the oldest trees in the ensemble with trees built on recent data. This approach would enable continuous model adaptation with bounded computational cost.

**Online One-Class SVM.** Online variants of One-Class SVM, such as those based on stochastic gradient descent or incremental support vector updates, can adapt the decision boundary as new normal data arrives. This would complement the Isolation Forest by providing a continuously updated secondary model for ensemble scoring.

**Adaptive retraining policies.** Rather than retraining on a fixed schedule, the system could monitor detection metrics (FPR, alert rate, score distribution statistics) and trigger retraining only when significant distribution shift is detected. Statistical tests such as the Page-Hinkley test or ADWIN (Adaptive Windowing) [55] could be employed to detect distribution shifts in the anomaly score stream.

### 6.3.3 Multi-Protocol Extension

The current system is designed specifically for SSH brute-force detection. However, the architecture --- log parser, feature extractor, anomaly detection model, dynamic threshold, automated response --- is generalizable to brute-force detection on other authentication protocols:

- **RDP (Remote Desktop Protocol).** RDP brute-force attacks target Windows servers and produce Windows Event Log entries (Event IDs 4625, 4624) analogous to SSH auth.log entries. A custom parser and RDP-specific features (e.g., NLA negotiation timing, session type distribution) would enable detection.
- **FTP (File Transfer Protocol).** FTP brute-force attacks produce authentication failure logs (vsftpd, ProFTPD, Pure-FTPd) with timing and count characteristics similar to SSH attacks. The existing feature set would require minimal adaptation.
- **HTTP authentication.** Web application login brute-force attacks produce HTTP 401/403 responses with timing patterns amenable to the same temporal feature analysis. Integration with web server access logs (Apache, Nginx) or web application frameworks would extend the system's coverage.
- **SMTP authentication.** Email server brute-force attacks target SMTP AUTH mechanisms and produce authentication failure logs with similar characteristics.

A multi-protocol system would share the core detection engine (Isolation Forest, dynamic threshold, Fail2Ban integration) while maintaining protocol-specific parsers and feature extractors, significantly increasing practical utility for organizations with diverse service exposure.

### 6.3.4 Federated Detection

Implementing federated learning [33] would enable multiple servers to collaboratively improve detection models without centralizing sensitive log data. This approach is relevant in three scenarios:

- **Distributed organizations.** Organizations with SSH servers in multiple geographic locations or security domains may face privacy, regulatory, or bandwidth constraints that prevent log centralization. Federated learning enables each server to train a local model and share only model parameters (not raw data) with a central aggregator.
- **Industry collaboration.** Multiple organizations facing similar SSH threats could collaboratively train a shared model without exposing their internal traffic patterns, creating a more robust and generalizable detection capability.
- **Coordinated attack detection.** Distributed attacks that simultaneously target multiple servers are difficult to detect from any single server's perspective. Federated detection enables cross-server correlation of anomaly patterns without centralized data collection.

### 6.3.5 Threat Intelligence Integration

Combining the behavioral anomaly detection system with external threat intelligence feeds would provide a multi-evidence classification framework. Specific integration points include:

- **IP reputation databases.** Services such as AbuseIPDB [28], Shodan, and GreyNoise maintain continuously updated databases of IP addresses associated with malicious activity. An IP flagged by multiple reputation services could receive a prior probability adjustment, effectively lowering the anomaly score threshold required to trigger an alert.
- **STIX/TAXII feeds.** Structured Threat Information eXpression (STIX) and Trusted Automated eXchange of Intelligence Information (TAXII) provide standardized formats for sharing cyber threat intelligence. The system could subscribe to SSH-specific STIX feeds to receive indicators of compromise (IoCs) such as attacker IP ranges, username wordlists, and tool signatures.
- **Dark web monitoring.** Credential dumps and SSH key leaks published on dark web forums could inform the system's detection priorities, enabling proactive monitoring for compromised accounts.

This integration would transform the system from a purely behavioral detector into a contextually aware threat assessment platform, potentially reducing the FPR significantly by corroborating behavioral anomalies with external intelligence.

### 6.3.6 SOAR Integration

Integrating the system with Security Orchestration, Automation and Response (SOAR) platforms such as Splunk SOAR, Palo Alto XSOAR, or IBM Security QRadar SOAR would automate the full incident response lifecycle:

- **Automated playbook execution.** Upon detection of an ALERT-level event, the SOAR platform could execute predefined playbooks: blocking the offending IP at the firewall (not just via Fail2Ban), initiating packet capture for forensic analysis, querying threat intelligence APIs for enrichment, and creating a case in the incident management system.
- **Notification and escalation.** Automated notification through email, Slack, PagerDuty, or other channels according to organizational escalation procedures, with severity-based routing (EARLY_WARNING to Tier 1, ALERT to Tier 2).
- **Compliance reporting.** Automated generation of incident reports for regulatory compliance frameworks (ISO 27001, SOC 2, GDPR), including timeline reconstruction, evidence preservation, and response documentation.
- **Feedback loop.** Analyst disposition of alerts (true positive, false positive, inconclusive) could be fed back to the detection model for continuous performance improvement through active learning.

### 6.3.7 Explainability and Interpretability

The current system produces anomaly scores and binary classifications (normal/attack) but provides limited explanation of why a particular session or IP was flagged. Adding explainability features would significantly increase utility for security analysts:

- **SHAP (SHapley Additive exPlanations) values.** Computing SHAP values for each prediction would identify which features contributed most to the anomaly score. An analyst who sees that an IP was flagged because of unusually short session durations (session_duration_mean = 1.2 s vs. normal mean of 340 s) and regular inter-attempt timing (std_inter_attempt_time = 0.3 s vs. normal mean of 45 s) can make a more informed triage decision than one who sees only a numerical score.
- **Natural language explanations.** Translating SHAP-based feature contributions into human-readable explanations (e.g., "This IP was flagged because session durations are 99.6% shorter than normal and inter-attempt timing is 99.3% more regular than normal") would further reduce the cognitive burden on analysts.
- **Visual attention maps.** For deep learning extensions (Section 6.3.1), attention weights from Transformer models could visualize which authentication events in a sequence contributed most to the anomaly decision.

### 6.3.8 Long-Term IP Profiling

The current 5-minute sliding window approach is effective for most attack scenarios but limited for extremely slow attacks that spread over hours or days. A long-term IP profiling mechanism would complement the short-term detection:

- **Behavioral baselines per IP.** Maintaining a historical profile of each IP's SSH behavior (typical session durations, login times, success rates) would enable detection of deviations from that IP's individual baseline, rather than from the global baseline.
- **Reputation scoring.** A continuously updated per-IP reputation score, combining behavioral history with external threat intelligence, would enable risk-based adaptive thresholding: IPs with clean histories receive higher thresholds (fewer false positives), while IPs with suspicious histories receive lower thresholds (higher sensitivity).
- **Campaign detection.** Correlating anomalous events across multiple IPs over extended time windows could reveal coordinated attack campaigns that individual window-based detection misses.

### 6.3.9 Real-World Deployment Validation

While the experimental results are encouraging, the ultimate validation of the system requires deployment in a production environment with live SSH traffic over an extended period. A pilot deployment at FPT University or a partner organization would provide empirical evidence on several questions that controlled experiments cannot fully answer: How does the FPR behave over weeks and months of continuous operation? How effectively does the dynamic threshold adapt to genuine shifts in organizational usage patterns? How do administrators interact with the alert system? How does the system perform against adversaries who actively attempt to evade AI-based detection? A structured pilot program with defined success criteria, instrumented data collection, and periodic review would provide the strongest evidence for production readiness.

---

## REFERENCES

[1] S. Morgan, "Cybercrime to cost the world $10.5 trillion annually by 2025," *Cybersecurity Ventures*, Nov. 2020. [Online]. Available: https://cybersecurityventures.com/cybercrime-damages-6-trillion-by-2021/

[2] T. Ylonen and C. Lonvick, "The Secure Shell (SSH) Protocol Architecture," RFC 4251, Internet Engineering Task Force, Jan. 2006.

[3] SANS Internet Storm Center, "DShield: Top 10 Target Ports," [Online]. Available: https://isc.sans.edu/top10.html. [Accessed: Jan. 2025].

[4] Rapid7, "2023 Attack Intelligence Report," *Rapid7 Research*, 2023.

[5] National Cyber Security Center (NCSC), "Annual Report on Cybersecurity in Vietnam," Ministry of Information and Communications, Hanoi, Vietnam, 2023.

[6] D. R. Tsai, A. Y. Chang, and S. H. Wang, "A study of SSH brute force attack defense," *Journal of Information Security and Applications*, vol. 49, pp. 102--113, Dec. 2019.

[7] M. Najafabadi, T. M. Khoshgoftaar, C. Calvert, and C. Kemp, "Detection of SSH brute force attacks using aggregated netflow data," in *Proc. IEEE 14th Int. Conf. Machine Learning and Applications (ICMLA)*, Miami, FL, USA, 2015, pp. 283--288.

[8] A. L. Buczak and E. Guven, "A survey of data mining and machine learning methods for cyber security intrusion detection," *IEEE Communications Surveys & Tutorials*, vol. 18, no. 2, pp. 1153--1176, 2nd Quart. 2016.

[9] M. A. F. Pimentel, D. A. Clifton, L. Clifton, and L. Tarassenko, "A review of novelty detection," *Signal Processing*, vol. 99, pp. 215--249, Jun. 2014.

[10] A. Simoiu, C. Gates, J. Bonneau, and S. Goel, "I was told to buy a software or lose my computer. I ignored it: A study of ransomware," in *Proc. 15th Symp. Usable Privacy and Security (SOUPS)*, Santa Clara, CA, USA, 2019, pp. 155--174.

[11] J. Jang-Jaccard and S. Nepal, "A survey of emerging threats in cybersecurity," *Journal of Computer and System Sciences*, vol. 80, no. 5, pp. 973--993, Aug. 2014.

[12] F. Syed, M. Bashir, and A. Sharaff, "Machine learning approaches for intrusion detection in IoT: A comprehensive survey," *Journal of King Saud University -- Computer and Information Sciences*, vol. 34, no. 10, pp. 9656--9688, Nov. 2022.

[13] R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in *Proc. IEEE Symp. Security and Privacy (S&P)*, Oakland, CA, USA, 2010, pp. 305--316.

[14] T. Ylonen, "SSH -- Secure login connections over the Internet," in *Proc. 6th USENIX Security Symp.*, San Jose, CA, USA, 1996, pp. 37--42.

[15] D. J. Barrett, R. E. Silverman, and R. G. Byrnes, *SSH, The Secure Shell: The Definitive Guide*, 2nd ed. Sebastopol, CA, USA: O'Reilly Media, 2005.

[16] T. Ylonen and C. Lonvick, "The Secure Shell (SSH) Authentication Protocol," RFC 4252, Internet Engineering Task Force, Jan. 2006.

[17] T. Ylonen and C. Lonvick, "The Secure Shell (SSH) Connection Protocol," RFC 4254, Internet Engineering Task Force, Jan. 2006.

[18] OpenSSH, "sshd_config -- OpenSSH daemon configuration file," *OpenBSD Manual Pages*. [Online]. Available: https://man.openbsd.org/sshd_config

[19] D. Florencio and C. Herley, "A large-scale study of web password habits," in *Proc. 16th Int. Conf. World Wide Web (WWW)*, Banff, AB, Canada, 2007, pp. 657--666.

[20] M. Durmuth, T. Kranz, and M. Mannan, "On the real-world effectiveness of SSH brute-force attacks," in *Proc. NDSS Workshop on Usable Security (USEC)*, San Diego, CA, USA, 2015.

[21] A. Sperotto, G. Schaffrath, R. Sadre, C. Morariu, A. Pras, and B. Stiller, "An overview of IP flow-based intrusion detection," *IEEE Communications Surveys & Tutorials*, vol. 12, no. 3, pp. 343--356, 3rd Quart. 2010.

[22] M. Bishop, "A taxonomy of Unix password attacks," in *Proc. Computer Security Applications Conf. (ACSAC)*, New Orleans, LA, USA, 1995.

[23] J. Owens and J. Matthews, "A study of passwords and methods used in brute-force SSH attacks," in *Proc. USENIX Workshop on Large-Scale Exploits and Emergent Threats (LEET)*, San Francisco, CA, USA, 2008.

[24] D. Wang, Z. Zhang, P. Wang, J. Yan, and X. Huang, "Targeted online password guessing: An underestimated threat," in *Proc. ACM SIGSAC Conf. Computer and Communications Security (CCS)*, Vienna, Austria, 2016, pp. 1242--1254.

[25] B. Cheswick and S. M. Bellovin, *Firewalls and Internet Security: Repelling the Wily Hacker*, 2nd ed. Reading, MA, USA: Addison-Wesley, 2003.

[26] A. K. Das, J. Bonneau, M. Caesar, N. Borisov, and X. Wang, "The tangled web of password reuse," in *Proc. Network and Distributed System Security Symp. (NDSS)*, San Diego, CA, USA, 2014.

[27] Fail2Ban Project, "Fail2Ban documentation," [Online]. Available: https://www.fail2ban.org/. [Accessed: Jan. 2025].

[28] AbuseIPDB, "AbuseIPDB -- IP address threat intelligence," [Online]. Available: https://www.abuseipdb.com/. [Accessed: Jan. 2025].

[29] M. Roesch, "Snort -- Lightweight intrusion detection for networks," in *Proc. USENIX Systems Administration Conf. (LISA)*, Seattle, WA, USA, 1999.

[30] M. Krzywinski, "Port knocking: Network authentication across closed ports," *SysAdmin Magazine*, vol. 12, pp. 12--17, 2003.

[31] P. Mishra, V. Varadharajan, U. Tupakula, and E. S. Pilli, "A detailed investigation and analysis of using machine learning techniques for intrusion detection," *IEEE Communications Surveys & Tutorials*, vol. 21, no. 1, pp. 686--728, 1st Quart. 2019.

[32] M. Ahmed, A. Naser Mahmood, and J. Hu, "A survey of network anomaly detection techniques," *Journal of Network and Computer Applications*, vol. 60, pp. 19--31, Jan. 2016.

[33] G. Pang, C. Shen, L. Cao, and A. van den Hengel, "Deep learning for anomaly detection: A review," *ACM Computing Surveys*, vol. 54, no. 2, Art. no. 38, Mar. 2021.

[34] V. Chandola, A. Banerjee, and V. Kumar, "Anomaly detection: A survey," *ACM Computing Surveys*, vol. 41, no. 3, Art. no. 15, Jul. 2009.

[35] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation-based anomaly detection," *ACM Trans. Knowledge Discovery from Data*, vol. 6, no. 1, Art. no. 3, Mar. 2012.

[36] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. IEEE Int. Conf. Data Mining (ICDM)*, Pisa, Italy, 2008, pp. 413--422.

[37] S. Hariri, M. C. Kind, and R. J. Brunner, "Extended Isolation Forest," *IEEE Trans. Knowledge and Data Engineering*, vol. 33, no. 4, pp. 1479--1489, Apr. 2021.

[38] M. M. Breunig, H.-P. Kriegel, R. T. Ng, and J. Sander, "LOF: Identifying density-based local outliers," in *Proc. ACM SIGMOD Int. Conf. Management of Data*, Dallas, TX, USA, 2000, pp. 93--104.

[39] B. Scholkopf, J. C. Platt, J. Shawe-Taylor, A. J. Smola, and R. C. Williamson, "Estimating the support of a high-dimensional distribution," *Neural Computation*, vol. 13, no. 7, pp. 1443--1471, Jul. 2001.

[40] D. M. J. Tax and R. P. W. Duin, "Support vector data description," *Machine Learning*, vol. 54, no. 1, pp. 45--66, Jan. 2004.

[41] M. Goldstein and S. Uchida, "A comparative evaluation of unsupervised anomaly detection algorithms for multivariate data," *PLOS ONE*, vol. 11, no. 4, Art. no. e0152173, Apr. 2016.

[42] S. W. Roberts, "Control chart tests based on geometric moving averages," *Technometrics*, vol. 1, no. 3, pp. 239--250, Aug. 1959.

[43] P. Casas, J. Mazel, and P. Owezarski, "Unsupervised network intrusion detection systems: Detecting the unknown without knowledge," *Computer Communications*, vol. 35, no. 7, pp. 772--783, Apr. 2012.

[44] C. Gormley and Z. Tong, *Elasticsearch: The Definitive Guide*. Sebastopol, CA, USA: O'Reilly Media, 2015.

[45] Elastic, "Elasticsearch Reference," [Online]. Available: https://www.elastic.co/guide/en/elasticsearch/reference/current/. [Accessed: Jan. 2025].

[46] Elastic, "Logstash Reference," [Online]. Available: https://www.elastic.co/guide/en/logstash/current/. [Accessed: Jan. 2025].

[47] Elastic, "Kibana Guide," [Online]. Available: https://www.elastic.co/guide/en/kibana/current/. [Accessed: Jan. 2025].

[48] D. Gonzalez, T. Hayajneh, and M. Carpenter, "ELK-based security analytics for anomaly detection in IoT environments," *IEEE Access*, vol. 9, pp. 120827--120841, 2021.

[49] A. Chuvakin, K. Schmidt, and C. Phillips, *Logging and Log Management: The Authoritative Guide to Understanding the Concepts Surrounding Logging and Log Management*. Waltham, MA, USA: Syngress, 2012.

[50] Elastic, "Machine Learning in the Elastic Stack," [Online]. Available: https://www.elastic.co/what-is/elasticsearch-machine-learning. [Accessed: Jan. 2025].

[51] R. Hofstede, A. Pras, and A. Sperotto, "Flow-based SSH compromise detection," in *Proc. IFIP/IEEE Int. Symp. Integrated Network Management (IM)*, 2018.

[52] P. Kumari and R. Jain, "Isolation Forest based anomaly detection for IoT systems," *Journal of King Saud University -- Computer and Information Sciences*, vol. 34, no. 8, pp. 5765--5774, Sep. 2022.

[53] N. Moustafa and J. Slay, "The evaluation of Network Anomaly Detection Systems: Statistical analysis of the UNSW-NB15 and the KDD99 data sets," *Information Security Journal: A Global Perspective*, vol. 25, no. 1--3, pp. 18--31, 2016.

[54] O. Starov, Y. Zhu, and N. Nikiforakis, "Detecting SSH brute-force attacks using temporal behavioral analysis," in *Proc. IEEE Conf. Communications and Network Security (CNS)*, Washington, DC, USA, 2019.

[55] S. Ahmad, A. Lavin, S. Purdy, and Z. Agha, "Unsupervised real-time anomaly detection for streaming data," *Neurocomputing*, vol. 262, pp. 134--147, Nov. 2017.

[56] A. Sperotto, R. Sadre, F. van Vliet, and A. Pras, "A labeled data set for flow-based intrusion detection," in *Proc. IEEE Int. Workshop on IP Operations and Management (IPOM)*, Venice, Italy, 2009.

[57] A. Satoh, Y. Nakamura, and T. Ikenaga, "SSH dictionary attack detection based on flow analysis using deep learning," *IEEE Access*, vol. 10, pp. 75614--75627, 2022.

[58] V. T. Nguyen and M. Q. Tran, "Application of machine learning in network intrusion detection for Vietnamese enterprise networks," *Journal of Science and Technology -- University of Danang*, vol. 19, no. 5, pp. 45--51, 2021.

[59] H. V. Le, T. H. Nguyen, and M. D. Pham, "Building a network security monitoring system using ELK Stack for small and medium enterprises in Vietnam," *Journal of Information and Communications Technology*, no. 3, pp. 56--64, 2022.

[60] N. H. Pham, "Research on SSH brute-force prevention solutions for government information systems," M.S. thesis, Academy of Cryptography Techniques, Hanoi, Vietnam, 2020.

[61] D. K. Tran and T. T. H. Nguyen, "Application of Isolation Forest in anomaly detection on system log data," *Journal of Science Research and Development*, vol. 2, no. 4, pp. 112--121, 2023.

[62] M. Javed and V. Paxson, "Detecting stealthy, distributed SSH brute-forcing," in *Proc. ACM SIGSAC Conf. Computer and Communications Security (CCS)*, Berlin, Germany, 2013, pp. 85--96.

[63] S. S. Khan and M. G. Madden, "One-class classification: Taxonomy of study and review of techniques," *Knowledge Engineering Review*, vol. 29, no. 3, pp. 345--374, Sep. 2014.

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
