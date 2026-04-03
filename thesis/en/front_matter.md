# FRONT MATTER

---

<div align="center">

MINISTRY OF EDUCATION AND TRAINING

**FPT UNIVERSITY**

---

**CAPSTONE PROJECT**

# DESIGN AND IMPLEMENTATION OF AN INTELLIGENT SSH BRUTE-FORCE ATTACK DETECTION AND PREVENTION SYSTEM USING ISOLATION FOREST WITH EWMA-ADAPTIVE PERCENTILE DYNAMIC THRESHOLDING

**Major:** Information Assurance

**Capstone Project Code:**

**Student Name:**

**Student ID:**

**Supervisor:**

**Hanoi, 2025**

</div>

---

## ABSTRACT

The Secure Shell (SSH) protocol is the predominant mechanism for remote administration of Linux and Unix server infrastructure worldwide. SSH brute-force attacks --- in which adversaries systematically attempt large numbers of username--password combinations to gain unauthorized access --- constitute one of the most persistent and prevalent threats to Internet-facing servers. Conventional defense tools such as Fail2Ban employ static, count-based thresholds (e.g., blocking an IP address after five failed login attempts within ten minutes) that are fundamentally unable to detect sophisticated attack variants, including low-and-slow brute-force attacks, distributed attacks that spread attempts across multiple source IP addresses, and credential stuffing attacks that leverage credentials stolen from unrelated breaches. This thesis presents the design, implementation, and comprehensive evaluation of an intelligent SSH brute-force attack detection and prevention system that leverages unsupervised machine learning, specifically the Isolation Forest algorithm, combined with a novel EWMA-Adaptive Percentile dynamic thresholding mechanism to enable early prediction of attacks before they reach full intensity.

The proposed system was evaluated using a hybrid dataset of 174,250 SSH log lines comprising real-world attack data collected from an SSH honeypot (119,729 log lines from 679 unique IP addresses across 5 days of operation) and simulated normal behavior data (54,521 log lines from 64 user accounts). A set of 14 behavioral features was engineered and extracted over 5-minute sliding windows per source IP address, capturing temporal, authentication, connection, and session characteristics. Three unsupervised anomaly detection algorithms were systematically trained, optimized, and compared: Isolation Forest (IF), Local Outlier Factor (LOF), and One-Class Support Vector Machine (OCSVM). After hyperparameter optimization (contamination = 0.01, max_features = 0.75, max_samples = 512, n_estimators = 500), the Isolation Forest model achieved an accuracy of 90.31%, an F1-score of 93.74%, a recall of 96.75%, and a false positive rate of 29.00%. The OCSVM model achieved the highest accuracy of 91.38% and F1-score of 94.55%, while LOF achieved perfect recall of 100% but exhibited the highest false positive rate of 67.10%. Feature importance analysis revealed that temporal features --- session_duration_mean (5.50%), min_inter_attempt_time (3.86%), and mean_inter_attempt_time (2.61%) --- dominate discrimination between automated attacks and normal activity, outperforming the count-based features traditionally relied upon by tools such as Fail2Ban.

The system was deployed as a complete end-to-end solution using a Docker-based microservices architecture comprising 9 services: FastAPI (API server and ML inference), React (monitoring dashboard), Elasticsearch (storage and indexing), Logstash (log normalization), Kibana (visualization), Fail2Ban (automated IP blocking), Redis (caching), PostgreSQL (configuration persistence), and Nginx (reverse proxy). The five-stage real-time detection pipeline achieves an end-to-end latency of under 2 seconds, with AI processing stages completing in under 100 milliseconds. The EWMA-Adaptive Percentile dynamic threshold (alpha = 0.3, base_percentile = 95, sensitivity_factor = 1.5) enables the system to adapt to evolving traffic patterns and provides early warning capabilities, detecting low-and-slow attacks within 3--5 attempts (approximately 2--3 minutes), significantly outperforming traditional static threshold methods. Five attack scenarios of escalating difficulty were designed and tested, demonstrating robust detection across basic brute-force, distributed, dictionary, credential stuffing, and low-and-slow attack types. The system was validated with 51 passing unit tests across all components and 5 integrated attack scenario evaluations.

**Keywords:** SSH brute-force detection, Isolation Forest, anomaly detection, dynamic threshold, EWMA, unsupervised machine learning, ELK Stack, intrusion detection system, cybersecurity, early prediction, Docker microservices, Fail2Ban

---

## ACKNOWLEDGEMENT

I would like to express my sincere gratitude to all those who have contributed to the completion of this thesis.

First and foremost, I extend my deepest thanks to my thesis supervisor for their invaluable guidance, rigorous feedback, and consistent encouragement throughout the entire research process. Their expertise in cybersecurity and machine learning has been instrumental in shaping the direction, methodology, and quality of this work.

I am profoundly grateful to the faculty members of the Information Assurance program at FPT University for providing a solid foundation in cybersecurity principles, software engineering, and research methodology. The knowledge and analytical skills I acquired during my studies were essential to the successful execution of this project.

I would also like to thank the members of the thesis examination committee for their time, careful reading, and constructive suggestions, which have strengthened the rigor and clarity of this research.

Special appreciation goes to my classmates and colleagues who provided technical assistance during the implementation phase, shared their experiences with related tools and frameworks, and offered moral support during the more challenging phases of the project. The collaborative and intellectually stimulating environment at FPT University has been a constant source of motivation.

I gratefully acknowledge the open-source community for developing and maintaining the tools and frameworks that formed the technical backbone of this research, including scikit-learn, FastAPI, the Elastic Stack, Docker, React, and Fail2Ban. Without these freely available, well-documented, and actively maintained projects, this work would not have been possible.

Finally, I owe my deepest gratitude to my family for their unconditional love, patience, and unwavering support throughout my entire academic journey. Their belief in my abilities has been a constant source of strength and inspiration, and this thesis is dedicated to them.

---

## TABLE OF CONTENTS

**ABSTRACT**

**ACKNOWLEDGEMENT**

**TABLE OF CONTENTS**

**LIST OF FIGURES**

**LIST OF TABLES**

**ABBREVIATIONS**

---

**CHAPTER 1: INTRODUCTION** .................................................. 1

1.1 Background and Motivation .................................................. 1

1.2 Problem Statement .................................................. 3

1.3 Research Questions .................................................. 5

1.4 Research Objectives .................................................. 6

1.5 Scope and Delimitations .................................................. 7

1.6 Thesis Contributions .................................................. 8

1.7 Thesis Organization .................................................. 9

---

**CHAPTER 2: LITERATURE REVIEW** .................................................. 11

2.1 The SSH Protocol .................................................. 11

2.1.1 Protocol Architecture and Layers .................................................. 11

2.1.2 Authentication Mechanisms .................................................. 13

2.1.3 SSH Brute-Force Attack Variants .................................................. 14

2.2 Traditional Detection and Prevention Methods .................................................. 16

2.2.1 Fail2Ban and Rate-Limiting Approaches .................................................. 16

2.2.2 Port Knocking and Other Hardening Techniques .................................................. 17

2.2.3 Limitations of Traditional Approaches .................................................. 18

2.3 Machine Learning for Intrusion Detection .................................................. 19

2.3.1 Supervised vs. Unsupervised Approaches .................................................. 19

2.3.2 Isolation Forest .................................................. 21

2.3.3 Local Outlier Factor .................................................. 23

2.3.4 One-Class Support Vector Machine .................................................. 24

2.4 Dynamic Thresholding Methods .................................................. 25

2.4.1 EWMA for Anomaly Detection .................................................. 25

2.4.2 Adaptive Percentile Methods .................................................. 26

2.5 ELK Stack for Security Monitoring .................................................. 27

2.6 Related Work .................................................. 29

2.7 Research Gap and Positioning .................................................. 32

---

**CHAPTER 3: METHODOLOGY** .................................................. 34

3.1 System Architecture .................................................. 34

3.1.1 Overall Architecture .................................................. 34

3.1.2 Docker-Based Microservices Deployment .................................................. 36

3.1.3 Data Flow Pipeline .................................................. 38

3.2 Data Collection and Preparation .................................................. 40

3.2.1 Honeypot Data Collection .................................................. 40

3.2.2 Normal Behavior Simulation .................................................. 42

3.2.3 Data Labeling and Splitting .................................................. 44

3.3 Feature Engineering .................................................. 45

3.3.1 Sliding Window Method .................................................. 45

3.3.2 Feature Definition .................................................. 47

3.3.3 Feature Normalization .................................................. 50

3.3.4 Model Selection and Configuration .................................................. 51

3.4 Dynamic Threshold Design .................................................. 53

3.4.1 EWMA-Adaptive Percentile Algorithm .................................................. 53

3.4.2 Parameter Selection .................................................. 55

3.4.3 Two-Level Detection Mechanism .................................................. 56

3.5 Real-Time Detection Pipeline .................................................. 57

3.6 Evaluation Methodology .................................................. 59

3.6.1 Evaluation Metrics .................................................. 59

3.6.2 Attack Scenario Design .................................................. 61

3.6.3 System Performance Evaluation .................................................. 62

---

**CHAPTER 4: RESULTS AND ANALYSIS** .................................................. 64

4.1 Dataset Analysis .................................................. 64

4.1.1 Overall Statistics .................................................. 64

4.1.2 Honeypot Data Analysis .................................................. 65

4.1.3 Simulation Data Analysis .................................................. 67

4.2 Feature Analysis .................................................. 68

4.2.1 Feature Distributions .................................................. 68

4.2.2 Correlation Analysis .................................................. 70

4.2.3 Feature Importance .................................................. 71

4.3 Model Performance .................................................. 73

4.3.1 Baseline Results .................................................. 73

4.3.2 Anomaly Score Distributions .................................................. 75

4.3.3 ROC and Precision-Recall Analysis .................................................. 76

4.3.4 Confusion Matrix Analysis .................................................. 77

4.3.5 Baseline Summary .................................................. 78

4.4 Interpretation of Results .................................................. 79

4.4.1 Optimized Model Performance .................................................. 79

4.4.2 Dynamic Threshold Evaluation .................................................. 81

4.4.3 Comparison with Related Studies .................................................. 83

4.5 Attack Scenario Evaluation .................................................. 84

4.5.1 Scenario Descriptions .................................................. 84

4.5.2 Detection Results .................................................. 86

4.5.3 Low-and-Slow Detection Analysis .................................................. 87

4.6 System Performance .................................................. 89

4.6.1 Latency Analysis .................................................. 89

4.6.2 Throughput Analysis .................................................. 90

4.6.3 Resource Utilization .................................................. 91

---

**CHAPTER 5: DISCUSSION** .................................................. 93

5.1 Restatement of Research Problem .................................................. 93

5.2 Achievement of Research Objectives .................................................. 95

5.2.1 Objective 1: Behavioral Feature Set Design .................................................. 95

5.2.2 Objective 2: Model Training and Evaluation .................................................. 96

5.2.3 Objective 3: Dynamic Threshold .................................................. 97

5.2.4 Objective 4: Integrated System .................................................. 98

5.2.5 Objective 5: Attack Scenario Evaluation .................................................. 99

5.3 Interpretation of Key Findings .................................................. 100

5.3.1 Why Timing Features Dominate .................................................. 100

5.3.2 Why Isolation Forest Is Chosen Despite OCSVM Having Higher F1 .................................................. 102

5.3.3 Dynamic Threshold vs. Static Threshold Advantage .................................................. 103

5.3.4 FPR Analysis and Acceptable Trade-off in Security Context .................................................. 105

5.4 Comparison with Existing Literature .................................................. 107

5.5 Practical Implications .................................................. 110

5.5.1 Deployment Considerations .................................................. 110

5.5.2 Scalability Considerations .................................................. 112

5.5.3 Cost-Benefit Analysis .................................................. 113

5.6 Limitations and Threats to Validity .................................................. 114

5.7 Chapter Summary .................................................. 116

---

**CHAPTER 6: CONCLUSION AND FUTURE WORK** .................................................. 117

6.1 Conclusion .................................................. 117

6.2 Contributions Summary .................................................. 120

6.3 Future Work .................................................. 122

6.3.1 Deep Learning for Improved Detection .................................................. 122

6.3.2 Online Learning and Continuous Adaptation .................................................. 123

6.3.3 Multi-Protocol Extension .................................................. 124

6.3.4 Federated Detection .................................................. 125

6.3.5 Threat Intelligence Integration .................................................. 126

6.3.6 SOAR Integration .................................................. 127

6.3.7 Explainability and Interpretability .................................................. 128

6.3.8 Long-Term IP Profiling .................................................. 129

6.3.9 Real-World Deployment Validation .................................................. 130

---

**REFERENCES** .................................................. 131

**APPENDICES** .................................................. 137

Appendix A: Feature Extraction Code Snippets .................................................. 137

Appendix B: Docker Compose Configuration .................................................. 139

Appendix C: Isolation Forest Hyperparameter Tuning Results .................................................. 141

Appendix D: Attack Simulation Scripts .................................................. 143

Appendix E: Logstash Pipeline Configuration .................................................. 145

Appendix F: Dynamic Threshold Parameter Sensitivity Analysis .................................................. 147

---

## LIST OF FIGURES

- Figure 1.1: Global trends in SSH brute-force attacks (2018--2025)
- Figure 1.2: Comparison of traditional vs. AI-based attack detection approaches
- Figure 1.3: Overview of the proposed system architecture (block diagram)
- Figure 2.1: Layered architecture of the SSH-2 protocol
- Figure 2.2: Illustration of static threshold vs. dynamic threshold (EWMA, Adaptive Percentile, and hybrid) on the same anomaly score series
- Figure 2.3: Architecture for integrating AI models with the ELK Stack for SSH monitoring
- Figure 2.4: Venn diagram showing the research positioning at the intersection of three domains
- Figure 3.1: Overall system architecture for SSH brute-force attack detection
- Figure 3.2: Data flow pipeline of the system
- Figure 3.3: Illustration of the sliding window method (window = 5 min, stride = 1 min)
- Figure 3.4: Model training and evaluation workflow
- Figure 3.5: Illustration of the EWMA-Adaptive Percentile dynamic threshold algorithm
- Figure 3.6: Five-stage real-time detection pipeline
- Figure 4.1: Distribution of failed authentication attempts per IP (honeypot)
- Figure 4.2: Comparison of hourly activity distribution between honeypot (attack) and simulation (normal)
- Figure 4.3: Boxplot comparison of key feature distributions between Normal and Attack classes
- Figure 4.4: Histogram distribution of 14 features, separated by normal/attack labels
- Figure 4.5: Pearson correlation matrix heatmap of 14 features
- Figure 4.6: Bar chart of feature importance for 14 features (permutation importance on Isolation Forest)
- Figure 4.7: Anomaly score distribution on the test set for three models (IF, LOF, OCSVM)
- Figure 4.8: Violin plot comparing anomaly score distributions between normal and attack for three models
- Figure 4.9: Radar chart comparing five performance metrics across three models
- Figure 4.10: ROC curves for three models on the test set
- Figure 4.11: Precision-Recall curves for three models on the test set
- Figure 4.12: Anomaly score and dynamic threshold evolution over time on test data
- Figure 4.13: Effect of alpha, base_percentile, and sensitivity_factor on F1-Score (parameter sensitivity analysis)
- Figure 4.14: Heatmap of detection rates by attack scenario and model
- Figure 5.1: Comparative positioning of the proposed system against existing studies

---

## LIST OF TABLES

- Table 1.1: Summary of research challenges and proposed solutions
- Table 1.2: Research objectives and corresponding approaches
- Table 2.1: Comparison of characteristics of SSH brute-force attack variants
- Table 2.2: Comparison of advantages and disadvantages of traditional detection methods
- Table 2.3: Comparison of Isolation Forest, LOF, and One-Class SVM characteristics
- Table 2.4: Comparative summary of related research works
- Table 3.1: List of 9 Docker services in the system with ports and roles
- Table 3.2: Summary of two data sources (honeypot and simulation)
- Table 3.3: Dataset split summary (training, testing, normal, attack)
- Table 3.4: Summary of 14 behavioral features and their significance
- Table 3.5: Comparison of characteristics of three anomaly detection models
- Table 3.6: Dynamic threshold algorithm parameters and their meanings
- Table 3.7: Summary of evaluation metrics and their security significance
- Table 4.1: Overall dataset statistics (log lines, samples, labels)
- Table 4.2: Detailed honeypot data statistics (IPs, events, time range)
- Table 4.3: Detailed simulation data statistics (users, events, session types)
- Table 4.4: Descriptive statistics of key features by label (normal vs. attack)
- Table 4.5: Feature importance ranking (Top 5 features by permutation importance)
- Table 4.6: Performance comparison of three models on the test set (baseline configuration)
- Table 4.7: Confusion matrix estimates for three models (TP, TN, FP, FN)
- Table 4.8: Comparison with related studies (method, dataset, metrics)
- Table 4.9: Dynamic threshold vs. static threshold comparison (OCSVM model)
- Table 4.10: Description of 5 attack scenarios (type, speed, IP count, difficulty)
- Table 4.11: Low-and-Slow detection results by model (detection rate, time to first alert)
- Table 4.12: Summary of detection results across 5 attack scenarios (all models)
- Table 4.13: Test environment configuration (hardware, software, versions)
- Table 4.14: Latency analysis by pipeline stage (ingestion, aggregation, scoring, decision, action)
- Table 4.15: Processing throughput by model (events/second, scoring latency)
- Table 4.16: Resource utilization of main Docker services (CPU, RAM, disk)
- Table 5.1: Optimized model performance comparison (IF, LOF, OCSVM after tuning)
- Table 5.2: Comprehensive comparison with related works (12 studies)

---

## ABBREVIATIONS

| Abbreviation | Full Form |
|:------------|:----------|
| AI | Artificial Intelligence |
| API | Application Programming Interface |
| AUC | Area Under the Curve |
| BST | Binary Search Tree |
| CPU | Central Processing Unit |
| CSS | Cascading Style Sheets |
| DNS | Domain Name System |
| ELK | Elasticsearch, Logstash, Kibana |
| EWMA | Exponentially Weighted Moving Average |
| FN | False Negative |
| FP | False Positive |
| FPR | False Positive Rate |
| FTP | File Transfer Protocol |
| GDPR | General Data Protection Regulation |
| GPU | Graphics Processing Unit |
| HTML | Hypertext Markup Language |
| HTTP | Hypertext Transfer Protocol |
| IDS | Intrusion Detection System |
| IF | Isolation Forest |
| IETF | Internet Engineering Task Force |
| IoC | Indicator of Compromise |
| IoT | Internet of Things |
| IP | Internet Protocol |
| IQR | Interquartile Range |
| ISO | International Organization for Standardization |
| LOF | Local Outlier Factor |
| LSTM | Long Short-Term Memory |
| ML | Machine Learning |
| MTTD | Mean Time to Detection |
| MTTR | Mean Time to Respond |
| NCSC | National Cyber Security Center |
| NIDS | Network Intrusion Detection System |
| OCSVM | One-Class Support Vector Machine |
| PAM | Pluggable Authentication Module |
| RAM | Random Access Memory |
| RBF | Radial Basis Function |
| RDP | Remote Desktop Protocol |
| REST | Representational State Transfer |
| RFC | Request for Comments |
| ROC | Receiver Operating Characteristic |
| SCP | Secure Copy Protocol |
| SFTP | SSH File Transfer Protocol |
| SHAP | SHapley Additive exPlanations |
| SIEM | Security Information and Event Management |
| SMTP | Simple Mail Transfer Protocol |
| SOAR | Security Orchestration, Automation and Response |
| SOC | Security Operations Center |
| SSH | Secure Shell |
| STIX | Structured Threat Information eXpression |
| SVM | Support Vector Machine |
| TAXII | Trusted Automated eXchange of Intelligence Information |
| TCP | Transmission Control Protocol |
| TN | True Negative |
| TP | True Positive |
| TPR | True Positive Rate |

---
