# FRONT MATTER

---

## ABSTRACT

The rapid growth of digital infrastructure has made cybersecurity an increasingly critical concern for organizations worldwide. Among the most persistent and prevalent threats targeting server infrastructure is the brute-force attack on the Secure Shell (SSH) protocol, which remains one of the most widely used mechanisms for remote system administration. Conventional defense tools such as Fail2Ban rely on static thresholds to detect and block malicious login attempts; however, these approaches are inherently limited in their ability to identify sophisticated attack variants, including slow brute-force, distributed brute-force, and credential stuffing attacks. This thesis presents the design, implementation, and evaluation of an intelligent SSH brute-force attack detection and prevention system that leverages unsupervised machine learning, specifically the Isolation Forest algorithm, combined with a novel EWMA-Adaptive Percentile dynamic thresholding mechanism to enable early prediction of attacks before they escalate to full intensity.

The proposed system was evaluated using a hybrid dataset comprising real-world attack data collected from an SSH honeypot (119,729 log lines from 679 unique IP addresses) and simulated normal behavior data (54,521 log lines from 64 users). A set of 14 behavioral features was engineered and extracted over 5-minute sliding windows per source IP address, capturing temporal, authentication, connection, and session characteristics. Three unsupervised anomaly detection algorithms were systematically compared: Isolation Forest (IF), Local Outlier Factor (LOF), and One-Class Support Vector Machine (OCSVM). After optimization, the Isolation Forest model achieved an accuracy of 90.31%, an F1-score of 93.74%, a recall of 96.75%, and a false positive rate of 29.00%. The OCSVM model achieved the highest accuracy of 91.38% and F1-score of 94.55%, while LOF achieved a perfect recall of 100% but exhibited the highest false positive rate of 67.10%.

The system was deployed as a complete end-to-end solution using a Docker-based microservices architecture comprising 9 services, integrating FastAPI, React, the ELK Stack (Elasticsearch, Logstash, Kibana), and Fail2Ban for automated response. The EWMA-Adaptive Percentile dynamic threshold (alpha=0.3, base_percentile=95, sensitivity_factor=1.5) enables the system to adapt to evolving traffic patterns and provides early warning capabilities, detecting low-and-slow attacks within 3-5 attempts (approximately 2-3 minutes), significantly outperforming traditional static threshold methods. Five attack scenarios were designed and tested, demonstrating robust detection across basic brute-force, distributed, credential stuffing, and dictionary attacks, with the low-and-slow scenario representing the most challenging case.

**Keywords:** SSH brute-force detection, Isolation Forest, anomaly detection, dynamic threshold, EWMA, unsupervised machine learning, ELK Stack, intrusion detection system, cybersecurity, early prediction

---

## ACKNOWLEDGEMENT

I would like to express my deepest gratitude to all those who have supported and guided me throughout the completion of this thesis.

First and foremost, I extend my sincere thanks to my thesis advisor for their invaluable guidance, constructive feedback, and unwavering encouragement throughout the entire research process. Their expertise in cybersecurity and machine learning has been instrumental in shaping the direction and quality of this work.

I am profoundly grateful to the faculty members of the Information Assurance program at FPT University for providing me with a solid foundation in cybersecurity principles, programming, and research methodology. The knowledge and skills I acquired during my studies were essential to the successful completion of this project.

I would also like to thank the members of my thesis committee for their time, insightful comments, and valuable suggestions, which have helped improve the quality and rigor of this research.

Special thanks go to my classmates and colleagues who provided technical assistance, shared their experiences, and offered moral support during challenging phases of the project. The collaborative and stimulating academic environment at FPT University has been a constant source of motivation.

I am grateful to the open-source community for developing and maintaining the tools and frameworks that formed the backbone of this research, including scikit-learn, FastAPI, the Elastic Stack, Docker, and Fail2Ban. Without these freely available and well-documented tools, this work would not have been possible.

Finally, I owe my deepest gratitude to my family for their unconditional love, patience, and support throughout my academic journey. Their belief in my abilities has been a constant source of strength and inspiration.

---

## LIST OF FIGURES

- Figure 1.1: Global trends in SSH brute-force attacks (2018-2025)
- Figure 1.2: Comparison of traditional vs. AI-based attack detection approaches
- Figure 1.3: Overview of the proposed system architecture (block diagram)
- Figure 2.1: Layered architecture of the SSH-2 protocol
- Figure 2.2: Illustration of static threshold vs. dynamic threshold (EWMA, Adaptive Percentile, and hybrid)
- Figure 2.3: Architecture for integrating AI models with the ELK Stack for SSH monitoring
- Figure 2.4: Venn diagram showing the research positioning at the intersection of three domains
- Figure 3.1: Overall system architecture for SSH brute-force attack detection
- Figure 3.2: Data flow pipeline of the system
- Figure 3.3: Illustration of the sliding window method (window=5 min, stride=1 min)
- Figure 3.4: Model training and evaluation workflow
- Figure 3.5: Illustration of the EWMA-Adaptive Percentile dynamic threshold algorithm
- Figure 3.6: Five-stage real-time detection pipeline
- Figure 4.1: Distribution of failed authentication attempts per IP (honeypot)
- Figure 4.2: Comparison of hourly activity distribution between honeypot (attack) and simulation (normal)
- Figure 4.3: Boxplot comparison of key feature distributions between Normal and Attack classes
- Figure 4.4: Histogram distribution of 14 features, separated by normal/attack labels
- Figure 4.5: Pearson correlation matrix heatmap of 14 features
- Figure 4.6: Bar chart of feature importance for 14 features
- Figure 4.7: Anomaly score distribution on the test set for three models
- Figure 4.8: Violin plot comparing anomaly score distributions between normal and attack for three models
- Figure 4.9: Radar chart comparing five performance metrics across three models
- Figure 4.10: ROC curves for three models on the test set
- Figure 4.11: Precision-Recall curves for three models
- Figure 4.12: Anomaly score and dynamic threshold evolution over time on test data
- Figure 4.13: Effect of alpha, base_percentile, and sensitivity_factor on F1-Score
- Figure 4.14: Heatmap of detection rates by attack scenario and model

---

## LIST OF TABLES

- Table 1.1: Summary of research challenges and proposed solutions
- Table 1.2: Research objectives and corresponding approaches
- Table 2.1: Comparison of SSH brute-force attack variants
- Table 2.2: Comparison of advantages and disadvantages of traditional detection methods
- Table 2.3: Comparison of Isolation Forest, LOF, and One-Class SVM characteristics
- Table 2.4: Comparative summary of related research works
- Table 3.1: List of 9 Docker services in the system
- Table 3.2: Summary of two data sources
- Table 3.3: Dataset split summary
- Table 3.4: Summary of 14 features and their significance
- Table 3.5: Comparison of characteristics of three models
- Table 3.6: Dynamic threshold algorithm parameters and their meanings
- Table 3.7: Summary of evaluation metrics and their security significance
- Table 4.1: Overall dataset statistics
- Table 4.2: Detailed honeypot data statistics
- Table 4.3: Detailed simulation data statistics
- Table 4.4: Descriptive statistics of key features by label
- Table 4.5: Feature importance ranking (Top 5)
- Table 4.6: Performance comparison of three models on the test set (baseline)
- Table 4.7: Confusion matrix estimates for three models
- Table 4.8: Comparison with related studies
- Table 4.9: Dynamic threshold vs. static threshold comparison
- Table 4.10: Description of 5 attack scenarios
- Table 4.11: Low-and-Slow detection results by model
- Table 4.12: Summary of detection results across 5 attack scenarios
- Table 4.13: Test environment configuration
- Table 4.14: Latency analysis by pipeline stage
- Table 4.15: Processing throughput by model
- Table 4.16: Resource utilization of main services
- Table 5.1: Optimized model performance comparison
- Table 5.2: Comparison with related works

---

## ABBREVIATIONS

| Abbreviation | Full Form |
|-------------|-----------|
| AI | Artificial Intelligence |
| AUC | Area Under the Curve |
| API | Application Programming Interface |
| BST | Binary Search Tree |
| CPU | Central Processing Unit |
| DNS | Domain Name System |
| ELK | Elasticsearch, Logstash, Kibana |
| EWMA | Exponentially Weighted Moving Average |
| FN | False Negative |
| FP | False Positive |
| FPR | False Positive Rate |
| FTP | File Transfer Protocol |
| HTTP | Hypertext Transfer Protocol |
| IDS | Intrusion Detection System |
| IF | Isolation Forest |
| IETF | Internet Engineering Task Force |
| IoT | Internet of Things |
| IP | Internet Protocol |
| IQR | Interquartile Range |
| LOF | Local Outlier Factor |
| LSTM | Long Short-Term Memory |
| ML | Machine Learning |
| MTTR | Mean Time to Respond |
| NCSC | National Cyber Security Center |
| NIDS | Network Intrusion Detection System |
| OCSVM | One-Class Support Vector Machine |
| PAM | Pluggable Authentication Module |
| RAM | Random Access Memory |
| RBF | Radial Basis Function |
| RDP | Remote Desktop Protocol |
| RFC | Request for Comments |
| ROC | Receiver Operating Characteristic |
| SFTP | SSH File Transfer Protocol |
| SCP | Secure Copy Protocol |
| SIEM | Security Information and Event Management |
| SMTP | Simple Mail Transfer Protocol |
| SOAR | Security Orchestration, Automation and Response |
| SSH | Secure Shell |
| SVM | Support Vector Machine |
| TCP | Transmission Control Protocol |
| TN | True Negative |
| TP | True Positive |
| TPR | True Positive Rate |

---
