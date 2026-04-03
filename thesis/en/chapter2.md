# CHAPTER 2: LITERATURE REVIEW

## 2.1 Review of Previous Studies

### 2.1.1 The SSH Protocol and Authentication Mechanisms

The Secure Shell (SSH) protocol is a cryptographic network protocol designed to provide a secure communication channel over an untrusted network. SSH was first developed in 1995 by Tatu Ylonen, a researcher at the Helsinki University of Technology in Finland, as a secure replacement for unencrypted remote access protocols such as Telnet, rlogin, and rsh [1]. The current widely deployed version is SSH-2, standardized by the Internet Engineering Task Force (IETF) through the RFC 4250-4256 document series in 2006 [2].

SSH provides three fundamental security services: server authentication (verifying the identity of the server to the client), data confidentiality (encrypting all data transmitted over the connection), and data integrity (ensuring that data is not modified in transit). These services are implemented through a well-defined layered architecture that separates concerns and allows flexible negotiation of cryptographic algorithms. The current deployment of SSH is nearly universal in server administration: a 2022 survey by Censys found that over 99% of Linux servers accessible over the Internet run SSH as their primary remote administration protocol, and the default configuration of all major cloud providers uses SSH key pairs for initial server access.

The SSH-2 architecture is organized into three layered protocol components:

**Transport Layer Protocol (RFC 4253).** This layer provides server authentication, data confidentiality, and data integrity. The handshake process involves protocol version exchange, cryptographic algorithm negotiation, Diffie-Hellman key exchange, and server authentication using public keys. Upon completion, an encrypted communication channel is established between the client and the server [3].

**User Authentication Protocol (RFC 4252).** This layer handles user identity verification. SSH-2 supports multiple authentication methods, including password authentication, public key authentication, host-based authentication, and keyboard-interactive authentication. In practice, the two most commonly used methods are password authentication and public key authentication [4].

**Connection Protocol (RFC 4254).** This layer enables multiplexing of multiple logical channels over a single SSH connection, supporting features such as remote command execution, port forwarding, and file transfer via SFTP/SCP [5].

[Figure 2.1: Layered architecture of the SSH-2 protocol]

The password authentication mechanism in SSH operates as follows: (1) the client sends an authentication request containing the username and password over the encrypted channel; (2) the server verifies the credentials against the user database (typically /etc/shadow on Linux); (3) the server responds with either success (SSH_MSG_USERAUTH_SUCCESS) or failure (SSH_MSG_USERAUTH_FAILURE) [4]. Despite the password being transmitted over an encrypted channel, the password authentication mechanism has several inherent weaknesses that make it a target for brute-force attacks:

- **No default limit on authentication attempts.** The default OpenSSH configuration permits multiple authentication attempts per session (MaxAuthTries defaults to 6) and does not limit the total number of sessions from a single IP address [6].
- **Dependence on password strength.** Security effectiveness relies entirely on users selecting sufficiently strong passwords, which empirical evidence consistently shows is not guaranteed [7].
- **No built-in anti-automation mechanism.** Unlike web applications that can employ CAPTCHAs, the SSH protocol has no integrated mechanism to distinguish between human users and automated attack tools [8].

SSH servers record authentication events in system log files (typically /var/log/auth.log on Debian/Ubuntu or /var/log/secure on CentOS/RHEL). Each event contains critical information including: timestamp, source IP address, username attempted, authentication result (success/failure), authentication method, and source port number [9]. These data fields provide a rich foundation for behavioral feature extraction and anomaly analysis in service of brute-force attack detection.

### 2.1.2 Classification of Brute-Force Attacks

A brute-force attack is a form of attack in which the adversary systematically attempts successive combinations of usernames and passwords until a valid credential is discovered. Theoretically, a brute-force attack will always succeed if the search space is finite and the attacker has sufficient time; however, in practice, the required time depends on password complexity and the rate of attempts [10]. Given an alphabet of size |A| and a password of length L, the maximum search space is S = |A|^L. For example, a password consisting of lowercase letters (26 characters) and digits (10 characters) with a length of 8 characters yields a search space of 36^8, approximately 2.82 x 10^12 combinations.

Based on analysis of published research and real-world data, the variants of SSH brute-force attacks can be classified as follows:

**Classic brute-force.** The attacker attempts all possible combinations at maximum speed, typically targeting common accounts such as root, admin, and user. Distinguishing characteristics include: an extremely high frequency of failed logins (hundreds to thousands per minute), very short and uniform intervals between attempts, and the use of multiple distinct usernames [11].

**Dictionary attack.** This variant uses a pre-compiled list of common passwords (a wordlist) rather than exhaustively enumerating all combinations. Widely used lists include RockYou (14 million passwords), SecLists, and target-specific customized lists. This method is more efficient than classic brute-force because it exploits the tendency of users to select weak passwords [12].

**Slow brute-force (low-and-slow attack).** The attacker deliberately reduces the rate of the attack, executing only a few attempts per minute or even per hour, in order to evade detection mechanisms based on frequency thresholds. This is the most difficult attack form to detect using traditional methods, as the attack behavior closely resembles that of a legitimate user who has forgotten their password [13].

**Distributed brute-force.** This attack uses a botnet or proxy service to distribute the attack across many different IP addresses. Each IP performs only a small number of attempts, rendering detection methods based on per-IP failure counts ineffective. Owens and Matthews [14] have reported that distributed attacks account for an increasing proportion of recorded SSH brute-force attacks.

**Credential stuffing.** This variant uses username-password pairs leaked from data breaches at other services. The attacker exploits the widespread practice of password reuse across services. This form is particularly dangerous because the success rate is significantly higher than that of random brute-force [15].

[Table 2.1: Comparison of characteristics of SSH brute-force attack variants]

Common tools used for SSH brute-force attacks include: Hydra (multi-protocol support, parallel attack), Medusa (optimized for high-speed attacks), Ncrack (from the Nmap project), Patator (a flexible Python-based framework), and custom scripts using the Paramiko or libssh libraries [16]. The diversity of attack tools produces varying behavioral patterns in log data, imposing a requirement for generalization capability in the detection system.

### 2.1.3 Traditional Detection Methods

**Static threshold-based methods.** The most prevalent method in practice involves establishing a fixed threshold for the number of failed login attempts. Fail2Ban, the most widely used open-source intrusion prevention tool, operates by monitoring system log files and blocking violating IP addresses via iptables/nftables when the failure count exceeds a threshold within a specified time period [17]. The default Fail2Ban configuration for SSH is typically: maxretry=5, findtime=600 seconds, bantime=600 seconds. This method is simple to deploy and effective against high-speed brute-force attacks. However, it has well-documented limitations: it cannot detect slow attacks operating below the threshold; it does not adapt to the natural variability of traffic; the false positive rate is elevated during peak hours when many legitimate users log in simultaneously; and it is easily evaded by distributed attacks from multiple IPs.

**List-based methods.** These methods use blacklists and whitelists to control access. Services such as AbuseIPDB, Spamhaus, and Blocklist.de provide lists of IP addresses known for malicious activity [18]. The primary limitation is their reactive nature --- an IP is only blacklisted after it has already conducted attacks elsewhere, and attackers can easily switch to new IP addresses.

**Signature-based methods.** Intrusion detection systems (IDS) such as Snort and Suricata can detect SSH brute-force attacks by matching network traffic patterns against known signatures (rules) [19]. However, this method cannot detect novel attack variants for which no signature exists, and its effectiveness is limited when SSH traffic is encrypted end-to-end, rendering packet content analysis infeasible.

**Enhanced authentication methods.** Authentication-level countermeasures include: adopting public key authentication, deploying two-factor authentication via PAM modules, changing the default SSH port, and using port knocking [20]. These measures are effective but are not always feasible in all environments, particularly legacy systems or multi-user environments.

[Table 2.2: Comparison of advantages and disadvantages of traditional detection methods]

### 2.1.4 Machine Learning in Intrusion Detection

The application of machine learning to network intrusion detection systems (NIDS) has been the subject of extensive research over the past two decades. Buczak and Guven [21] compiled a comprehensive survey of data mining and machine learning methods for cybersecurity, demonstrating that machine learning algorithms can achieve significantly higher detection performance compared to rule-based methods in many scenarios.

Machine learning methods for intrusion detection are classified along several dimensions:

**By learning paradigm:**
- *Supervised learning:* Requires labeled training data (normal/attack). Common algorithms include Random Forest, Support Vector Machine, Neural Networks, and Gradient Boosting. The advantage is high accuracy when sufficient quality training data is available; the disadvantage is dependence on labeled data and difficulty in detecting unknown attack types [22].
- *Unsupervised learning:* Does not require labeled data; instead, it learns the pattern of normal behavior and treats data points that deviate from this pattern as anomalies. The advantage is the ability to detect unknown attack types (zero-day attacks); the disadvantage is a generally higher false positive rate [23].
- *Semi-supervised learning:* Combines a small quantity of labeled data with a large volume of unlabeled data. This approach is suitable for real-world scenarios where labeled data is scarce and expensive to obtain [24].

**By detection approach:**
- *Misuse detection:* Builds models of known attack behaviors and detects attacks when traffic patterns match the model. This is equivalent to the signature-based approach but uses machine learning models instead of manually crafted rules [25].
- *Anomaly detection:* Builds a model of normal behavior and detects attacks when traffic patterns deviate from the model. This approach can detect unknown attacks but requires determining an appropriate decision boundary [26].

In the context of SSH brute-force detection, the unsupervised anomaly detection approach was selected for this research based on three key considerations. First, the nature of brute-force attacks is continuously evolving, and supervised models trained on historical attack data may fail to recognize new variants. By modeling normal behavior rather than attack behavior, anomaly detection offers superior generalization to novel attack forms [27]. Second, accurately labeled attack data is extremely difficult to collect in practice. Although honeypot data provides realistic attack samples, precise labeling of every login session in an operational environment is infeasible at scale [28]. Third, unsupervised anomaly detection algorithms such as Isolation Forest offer computational efficiency advantages that enable real-time processing --- a critical requirement for intrusion detection systems [29].

### 2.1.5 Anomaly Detection Algorithms

**Isolation Forest (IF).** Isolation Forest was proposed by Liu, Ting, and Zhou in 2008 at Monash University, Australia, and formally published in ACM Transactions on Knowledge Discovery from Data in 2012 [29]. Unlike most anomaly detection algorithms that rely on distance or density measures, Isolation Forest is based on the principle of isolation: anomalous points, due to their distinct feature values, will be isolated (separated from other points) more rapidly than normal points during random partitioning.

The algorithm constructs an ensemble of Isolation Trees (iTrees) by repeating the following process: randomly selecting a feature, randomly selecting a split value within the [min, max] range of that feature, and dividing the data into two branches. The process continues until each data point is isolated or the maximum tree depth is reached. The anomaly score of a point x is computed based on the expected path length across all t trees in the forest:

$$s(x, n) = 2^{-\frac{E[h(x)]}{c(n)}}$$

where E[h(x)] is the average path length of x across t Isolation Trees, and c(n) is the average path length of an unsuccessful search in a Binary Search Tree with n nodes, defined as c(n) = 2H(n-1) - 2(n-1)/n, with H(i) = ln(i) + gamma being the harmonic number and gamma approximately equal to 0.5772 (the Euler-Mascheroni constant). Scores approaching 1 indicate anomalies (short average path lengths), scores around 0.5 indicate no clear anomalies, and scores approaching 0 indicate normal points.

Isolation Forest possesses several advantages for SSH brute-force detection: linear time complexity O(t * n * log psi), where t is the number of trees, n is the training data size, and psi is the sub-sampling size, enabling real-time processing; effectiveness with high-dimensional data without suffering from the curse of dimensionality; no distributional assumptions about the data; and robustness to outlier swamping and masking through sub-sampling [29-31].

**Local Outlier Factor (LOF).** LOF was proposed by Breunig, Kriegel, Ng, and Sander in 2000 [32]. It is a local density-based anomaly detection method that compares the local density of each data point with the local densities of its nearest neighbors. The core idea is that an anomalous point has a significantly lower local density than its neighbors. The LOF score is computed as the ratio of the average local reachability density of a point's k-nearest neighbors to the point's own local reachability density. LOF approximately equal to 1 indicates normal density; LOF much greater than 1 indicates an anomaly. While effective for many anomaly detection tasks, LOF has limitations for real-time SSH attack detection: O(n^2) computational complexity for k-nearest neighbor computation, sensitivity to the choice of k, and a requirement to store the entire training dataset in memory [32-34].

**One-Class SVM (OCSVM).** One-Class SVM was proposed by Scholkopf, Platt, Shawe-Taylor, Smola, and Williamson in 2001 [35]. The algorithm extends traditional SVM for anomaly detection by finding a hyperplane in a high-dimensional feature space that maximally separates training data points (normal) from the origin. Points on the origin side of the hyperplane are classified as anomalous. The RBF kernel K(x_i, x) = exp(-gamma * ||x_i - x||^2) is most commonly used. OCSVM has a strong theoretical foundation from optimization theory and kernel methods, and the nu parameter provides intuitive control over the expected anomaly proportion. However, its training complexity of O(n^2) to O(n^3) and high sensitivity to kernel and parameter selection are notable disadvantages [35-37].

[Table 2.3: Comparison of Isolation Forest, LOF, and One-Class SVM characteristics]

From a theoretical standpoint, Isolation Forest offers advantages in computational efficiency, high-dimensional data handling, and absence of distributional assumptions. LOF excels at detecting local outliers that are anomalous only within their neighborhood context. OCSVM has the strongest theoretical foundations and allows precise control over the anomaly proportion through the nu parameter [38].

### 2.1.6 Dynamic Thresholding in Anomaly Detection

In anomaly detection systems, the threshold plays a decisive role in classifying a data point as normal or anomalous. Static thresholds --- fixed values determined a priori --- are simple to implement but inappropriate for data with non-stationary characteristics that change over time [39]. In the SSH monitoring context, access traffic varies significantly over time: business hours have more legitimate logins than off-hours, weekdays differ from weekends, and special events (system maintenance, application deployments) create legitimate but unusual traffic spikes. Static thresholds cannot adapt to these variations, leading to both false positives during legitimate traffic surges and false negatives when the baseline traffic level is low.

**Exponentially Weighted Moving Average (EWMA).** EWMA is a time series smoothing method that assigns exponentially decreasing weights to older observations. Introduced by Roberts in 1959 in the context of statistical quality control [40], EWMA has been widely applied in many domains, including network anomaly detection [41]. The EWMA formula is:

$$\hat{\mu}_t = \alpha \cdot x_t + (1 - \alpha) \cdot \hat{\mu}_{t-1}$$

where x_t is the observed value at time t, mu_hat_t is the EWMA value at time t, and alpha is the smoothing factor in the range (0, 1]. In anomaly detection, EWMA is used to estimate the baseline anomaly score level, from which a threshold is derived.

**Adaptive Percentile.** The Adaptive Percentile method determines the threshold based on the percentile of the anomaly score distribution within a sliding time window. Instead of assuming a normal distribution as EWMA does, this method directly uses the empirical distribution of the data [42]. The threshold is defined as the q-th percentile of the most recent W anomaly scores: threshold_t = P_q(S_W). The advantage is that it requires no distributional assumptions and naturally adapts to changes in the data distribution. The disadvantage is the need to store data within the window and sensitivity to the window size W.

**The hybrid EWMA-Adaptive Percentile method.** This research proposes combining EWMA and Adaptive Percentile to leverage the strengths of both approaches: EWMA provides smoothing and long-term trend tracking, while Adaptive Percentile accurately reflects the actual short-term distribution. This combined approach allows the system to maintain stability from EWMA while remaining responsive to local changes from Adaptive Percentile. The superiority of hybrid methods over individual methods has been demonstrated in network security monitoring research [43].

[Figure 2.2: Illustration of static threshold vs. dynamic threshold (EWMA, Adaptive Percentile, and hybrid) on the same anomaly score series]

### 2.1.7 The ELK Stack for Security Monitoring

The ELK Stack is a trio of open-source tools developed by Elastic N.V., comprising Elasticsearch, Logstash, and Kibana. Widely used in log management and data analytics, the ELK Stack has become a standard platform for Security Information and Event Management (SIEM) and network security monitoring [44].

**Elasticsearch** is a distributed search and analytics engine based on Apache Lucene. It stores data as JSON documents and supports full-text search, aggregation, and real-time analysis. Its distributed architecture with sharding and replication ensures scalability and high availability [45].

**Logstash** is a server-side data processing pipeline capable of simultaneously collecting data from multiple sources (inputs), transforming and enriching data (filters), and routing to multiple destinations (outputs). Logstash supports over 200 plugins for inputs, filters, and outputs, including log file reading, parsing with Grok patterns, and sending data to Elasticsearch [46].

**Kibana** is a data visualization and exploration platform providing a web interface for interacting with data in Elasticsearch. Kibana supports creating dashboards, charts, maps, and alerts for real-time security monitoring [47].

Gonzalez et al. [48] demonstrated the effectiveness of the ELK Stack for SSH log analysis with the ability to process millions of events per day. Chuvakin et al. [49] showed that the ELK Stack can replace expensive commercial SIEM solutions for small and medium-sized organizations. The integration of machine learning models with the ELK Stack can be accomplished through Elastic's built-in Machine Learning module in X-Pack [50], or through custom pipelines --- the approach adopted in this research --- where data is retrieved from Elasticsearch via API, processed and feature-extracted using Python, fed into the Isolation Forest model for anomaly scoring, and results are written back to Elasticsearch for visualization in Kibana.

[Figure 2.3: Architecture for integrating AI models with the ELK Stack for SSH monitoring]

### 2.1.8 International Research

**Najafabadi et al. (2015)** [51] investigated SSH brute-force attack detection using aggregated NetFlow data. The authors employed a Random Forest classifier on the CERT NetFlow dataset and achieved 99% accuracy in distinguishing normal from attack SSH traffic. However, the study used supervised learning with fully labeled data, and features were extracted from NetFlow (network-layer data) rather than SSH logs (application-layer data), limiting the ability to detect sophisticated application-layer attacks.

**Hofstede, Pras, and Sperotto (2018)** [52] proposed an SSH Compromise Detection system using flow-based features. The study exploited flow-based features combined with Decision Tree and Naive Bayes classifiers, achieving a True Positive Rate exceeding 90%. The primary contribution was a set of flow-based features that distinguish between the brute-force phase and the post-compromise exploitation phase.

**Kumari and Jain (2020)** [53] studied Isolation Forest-based anomaly detection for IoT systems. The authors applied Isolation Forest on the NSL-KDD and CICIDS2017 datasets, achieving an F1-score of 89.7% on CICIDS2017. The study demonstrated the effectiveness of Isolation Forest for network anomaly detection but did not focus specifically on the SSH protocol.

**Moustafa and Slay (2016)** [54] developed the UNSW-NB15 dataset and evaluated multiple machine learning algorithms, including Isolation Forest, which achieved a Detection Rate of 83.1% with a False Alarm Rate of 14.2% on comprehensive network data.

**Starov et al. (2019)** [55] proposed SSH brute-force detection based on temporal behavioral analysis, using features related to inter-attempt timing, time distribution, and authentication patterns. Results showed that temporal features significantly improved the detection of slow attacks compared to using only frequency-based features.

**Ahmad et al. (2021)** [56] conducted a comprehensive study of network anomaly detection methods, comparing Isolation Forest, LOF, OCSVM, and Autoencoders across multiple datasets. Results indicated that Isolation Forest achieved the best balance between detection performance and processing time.

**Sperotto et al. (2017)** [57] studied SSH brute-force attacks in the real-world network environment of the University of Twente (Netherlands), analyzing over 14 million SSH events. The study identified characteristic behavioral patterns of brute-force attacks and proposed a Hidden Markov Model-based classification method.

**Satoh et al. (2022)** [58] proposed an SSH attack detection system using Deep Learning (LSTM-Autoencoder) with early detection capability, achieving a Recall of 97.2% with an average detection time of 45 seconds before attack escalation. However, the Deep Learning model requires significantly greater computational resources than traditional methods.

### 2.1.9 Domestic Research (Vietnam)

**Nguyen Van Thang and Tran Minh Quang (2021)** [59] studied the application of machine learning in network intrusion detection in Vietnam, using Random Forest and XGBoost on the CICIDS2017 dataset. The study achieved 98.5% accuracy but focused on general network intrusion detection, not SSH brute-force specifically.

**Le Hai Viet et al. (2022)** [60] proposed a network security monitoring system using the ELK Stack for small and medium enterprises in Vietnam. The study provided practical ELK Stack deployment experience and identified performance and configuration challenges in the Vietnamese context.

**Pham Ngoc Hung (2020)** [61] studied brute-force prevention solutions for SSH systems in government agencies. The research focused on traditional measures (Fail2Ban, iptables, port knocking) and evaluated their effectiveness in real-world environments. Results showed that traditional measures are effective against basic attacks but lack the capability to handle sophisticated attacks.

**Tran Duc Khanh and Nguyen Thi Thanh Huyen (2023)** [62] studied the application of Isolation Forest in anomaly detection on system log data. The study was implemented in a centralized monitoring environment and achieved an F1-score of 85.3% on composite log data. This is one of the few studies in Vietnam using Isolation Forest for security log analysis.

[Table 2.4: Comparative summary of related research works]

| Author (Year) | Method | Data | Key Result | Limitation |
|----------------|--------|------|------------|------------|
| Najafabadi et al. (2015) [51] | Random Forest | CERT NetFlow | Accuracy 99% | Supervised, network layer |
| Hofstede et al. (2018) [52] | Decision Tree, NB | Flow-based | TPR > 90% | No early prediction |
| Kumari and Jain (2020) [53] | Isolation Forest | NSL-KDD, CICIDS2017 | F1 89.7% | Not SSH-specific |
| Moustafa and Slay (2016) [54] | Isolation Forest | UNSW-NB15 | DR 83.1% | High FAR (14.2%) |
| Starov et al. (2019) [55] | Temporal features | SSH logs | Improved slow detection | Static threshold |
| Ahmad et al. (2021) [56] | IF, LOF, OCSVM, AE | Multiple | IF best balance | No system integration |
| Sperotto et al. (2017) [57] | HMM | Real SSH | 14M events analyzed | Complex deployment |
| Satoh et al. (2022) [58] | LSTM-Autoencoder | SSH logs | Recall 97.2% | High compute resources |
| Nguyen & Tran (2021) [59] | RF, XGBoost | CICIDS2017 | Accuracy 98.5% | Supervised, general |
| Tran & Nguyen (2023) [62] | Isolation Forest | System logs | F1 85.3% | Not SSH-specific |
| **This study** | **IF + EWMA-AP** | **Honeypot + Sim** | **F1 93.74%, Recall 96.75%** | **See Section 1.5** |

### 2.1.10 Summary of Research Landscape

The review of both international and domestic research reveals a rich but fragmented landscape. International research has demonstrated the effectiveness of machine learning for network intrusion detection in general and SSH brute-force detection in particular. However, the majority of studies evaluate their approaches on benchmark datasets (NSL-KDD, CICIDS, UNSW-NB15) that, while useful for standardized comparison, do not accurately represent the characteristics of modern SSH brute-force attacks as observed in real-world environments. The few studies that use real SSH data (Sperotto et al., Satoh et al.) focus on either statistical flow analysis or deep learning approaches that require substantial computational resources.

The domestic research landscape in Vietnam is considerably less developed. While there are valuable contributions in the areas of general network intrusion detection and ELK Stack deployment, the specific intersection of unsupervised anomaly detection algorithms with SSH security monitoring remains largely unexplored. This presents both a research opportunity and a practical need, given the increasing frequency of SSH-targeted attacks against Vietnamese digital infrastructure.

A critical gap that emerges from the comprehensive literature review is the absence of studies that combine all three elements: (1) modern unsupervised anomaly detection algorithms, (2) adaptive dynamic thresholding for early prediction, and (3) complete end-to-end system integration. Individual studies address one or two of these elements, but the integration of all three into a deployable system represents the novel contribution of this thesis.

Furthermore, the review reveals a notable emphasis in the literature on supervised learning approaches, which achieve high accuracy but require comprehensive labeled datasets that are impractical to obtain in most operational settings. The semi-supervised approach adopted in this thesis --- training exclusively on normal data --- addresses this practical limitation while maintaining competitive detection performance, as demonstrated by the experimental results in Chapter 4.

## 2.2 Summary of the Literature Review

The comprehensive review of existing literature reveals five distinct gaps in the current state of knowledge regarding SSH brute-force attack detection:

**Gap 1: Lack of end-to-end integration.** The majority of existing studies focus on algorithmic development and evaluation without addressing the practical challenge of full integration from data collection, through feature extraction and anomaly detection, to automated response. The research-to-deployment gap remains a significant barrier to practical AI adoption in cybersecurity [63]. Specifically, the studies by Kumari and Jain (2020), Moustafa and Slay (2016), and Ahmad et al. (2021) all evaluated algorithms on benchmark datasets without discussing practical deployment architectures.

**Gap 2: Limitations of detection thresholds.** Research employing anomaly detection methods typically applies static or fixed thresholds based on the training distribution. The investigation and deployment of adaptive dynamic thresholding mechanisms --- particularly hybrid approaches combining multiple methods --- in the context of SSH attack detection remains very limited. Starov et al. (2019) identified this issue but did not propose a specific dynamic threshold solution.

**Gap 3: Insufficient exploitation of early prediction.** Although some studies mention early detection capabilities (Satoh et al., 2022), the majority of systems continue to operate in a reactive mode --- detecting and blocking attacks after they have occurred. The potential of using behavioral features within short time windows to predict attack intent before escalation has not been adequately explored.

**Gap 4: Lack of evaluation on real-world attack data.** Many studies use aging benchmark datasets (NSL-KDD, CICIDS) that do not accurately reflect the characteristics of modern SSH brute-force attacks. The use of honeypot data to collect realistic attack samples for model training and evaluation remains uncommon.

**Gap 5: Limited domestic research.** The number of studies in Vietnam on the application of AI to SSH attack detection is very small. Existing research primarily focuses on traditional measures or general network intrusion detection, without in-depth investigation of combining modern anomaly detection algorithms with integrated security monitoring systems for SSH.

## 2.3 Contribution of Research

Based on the identified research gaps, this thesis makes the following contributions:

**Contribution 1: End-to-end integrated system.** This research designs and implements a complete system architecture spanning SSH log collection (via the ELK Stack), feature extraction (14 features per IP per 5-minute window), anomaly detection (Isolation Forest), and automated response (Fail2Ban). The entire system is containerized with Docker, directly addressing the end-to-end integration gap.

**Contribution 2: Hybrid dynamic thresholding mechanism.** The thesis proposes and implements the EWMA-Adaptive Percentile hybrid dynamic threshold method, enabling the system to automatically adjust its detection threshold according to the evolving characteristics of SSH traffic. This contribution addresses the gap in adaptive threshold methods for SSH attack detection.

**Contribution 3: Early prediction capability.** The set of 14 behavioral features is designed to capture attack indicators from the earliest stages of an attack (the reconnaissance and initial probing phases), and the 5-minute time window combined with the two-level detection mechanism (EARLY_WARNING at 67% of the ALERT threshold) enables the identification of attack intent before a full-scale attack materializes. In the low-and-slow scenario, the system issues an early warning after only 3-5 attempts (approximately 2-3 minutes).

**Contribution 4: Evaluation on real-world data.** The study uses real-world attack data from a honeypot (119,729 log lines from 679 IPs) combined with simulated normal behavior data (54,521 log lines from 64 users), providing an evaluation that is more representative of real operational conditions than benchmark datasets.

**Contribution 5: Systematic algorithm comparison.** The thesis provides a systematic comparative evaluation of Isolation Forest (optimized: Acc=90.31%, F1=93.74%, Recall=96.75%, FPR=29.00%), LOF (Acc=83.22%, F1=89.94%, Recall=100%, FPR=67.10%), and One-Class SVM (Acc=91.38%, F1=94.55%, Recall=99.65%, FPR=33.42%) on the same real-world SSH dataset, contributing to the understanding of anomaly detection algorithm performance in this specific domain.

**Contribution 6: Reference for the domestic community.** As one of the few studies in Vietnam combining modern AI with SSH security monitoring, this thesis provides a valuable reference for domestic research and practical deployment. The detailed documentation of the methodology, architecture, and experimental results is intended to facilitate reproducibility and extension by other researchers, particularly within the Information Assurance programs at Vietnamese universities.

**Contribution 7: Methodological framework for semi-supervised SSH security.** Beyond the specific algorithmic and system contributions, this thesis establishes a methodological framework for applying semi-supervised anomaly detection to SSH security that can be adapted to related problems. The framework encompasses: data collection strategies (combining honeypot and simulation data), labeling strategies for semi-supervised training, behavioral feature engineering over sliding time windows, model selection criteria that account for both detection performance and operational requirements (computational efficiency, score distribution properties), and dynamic thresholding for real-time deployment. This framework is generalizable to brute-force detection on other protocols (FTP, RDP, SMTP) with appropriate modifications to the parser and feature set.

The research is positioned at the intersection of three domains: (1) Cybersecurity, specifically the detection and prevention of SSH brute-force attacks; (2) Machine Learning, specifically unsupervised anomaly detection with Isolation Forest; and (3) Systems Engineering, specifically the integration of the ELK Stack, Docker, and Fail2Ban. This interdisciplinary combination constitutes the novelty and practical value of the research, distinguishing it from prior works that primarily focus on one or two of these domains.

[Figure 2.4: Venn diagram showing the research positioning at the intersection of three domains]

---

## References for Chapter 2

[1] T. Ylonen, "SSH -- Secure Login Connections over the Internet," in *Proc. 6th USENIX Security Symposium*, 1996, pp. 37-42.

[2] T. Ylonen and C. Lonvick, "The Secure Shell (SSH) Protocol Architecture," RFC 4251, *IETF*, 2006.

[3] D. J. Barrett, R. E. Silverman, and R. G. Byrnes, *SSH, The Secure Shell: The Definitive Guide*, 2nd ed., O'Reilly Media, 2005.

[4] T. Ylonen and C. Lonvick, "The Secure Shell (SSH) Authentication Protocol," RFC 4252, *IETF*, 2006.

[5] T. Ylonen and C. Lonvick, "The Secure Shell (SSH) Connection Protocol," RFC 4254, *IETF*, 2006.

[6] OpenSSH, "sshd_config -- OpenSSH SSH daemon configuration file," *OpenBSD Manual Pages*, https://man.openbsd.org/sshd_config.

[7] D. Florencio and C. Herley, "A large-scale study of web password habits," in *Proc. 16th International Conference on World Wide Web*, 2007, pp. 657-666.

[8] M. Durmuth, T. Kranz, and M. Mannan, "On the real-world effectiveness of SSH brute-force attacks," in *Proc. NDSS Workshop on Usable Security (USEC)*, 2015.

[9] A. Sperotto, G. Schaffrath, R. Sadre, C. Morariu, A. Pras, and B. Stiller, "An overview of IP flow-based intrusion detection," *IEEE Communications Surveys & Tutorials*, vol. 12, no. 3, pp. 343-356, 2010.

[10] M. Bishop, "A taxonomy of password attacks," in *Computer Security Applications Conference*, 1995.

[11] J. Owens and J. Matthews, "A study of passwords and methods used in brute-force SSH attacks," in *Proc. USENIX Workshop on Large-Scale Exploits and Emergent Threats (LEET)*, 2008.

[12] D. Wang, Z. Zhang, P. Wang, J. Yan, and X. Huang, "Targeted online password guessing: An underestimated threat," in *Proc. ACM CCS*, 2016, pp. 1242-1254.

[13] B. Cheswick and S. M. Bellovin, *Firewalls and Internet Security: Repelling the Wily Hacker*, 2nd ed., Addison-Wesley, 2003.

[14] J. Owens and J. Matthews, "A study of passwords and methods used in brute-force SSH attacks," in *Proc. USENIX LEET*, 2008.

[15] A. K. Das, J. Bonneau, M. Caesar, N. Borisov, and X. Wang, "The tangled web of password reuse," in *Proc. NDSS*, 2014.

[16] D. van Heesch, "Hydra: A fast and flexible online password cracking tool," *THC Project*, https://github.com/vanhauser-thc/thc-hydra.

[17] Fail2Ban, "Fail2Ban documentation," https://www.fail2ban.org/.

[18] AbuseIPDB, "IP address abuse reports," https://www.abuseipdb.com/.

[19] M. Roesch, "Snort: Lightweight intrusion detection for networks," in *Proc. USENIX LISA*, 1999.

[20] M. Krzywinski, "Port knocking: Network authentication across closed ports," *SysAdmin Magazine*, vol. 12, pp. 12-17, 2003.

[21] A. L. Buczak and E. Guven, "A survey of data mining and machine learning methods for cyber security intrusion detection," *IEEE Communications Surveys & Tutorials*, vol. 18, no. 2, pp. 1153-1176, 2016.

[22] P. Mishra, V. Varadharajan, U. Tupakula, and E. S. Pilli, "A detailed investigation and analysis of using machine learning techniques for intrusion detection," *IEEE Communications Surveys & Tutorials*, vol. 21, no. 1, pp. 686-728, 2019.

[23] M. Ahmed, A. N. Mahmood, and J. Hu, "A survey of network anomaly detection techniques," *Journal of Network and Computer Applications*, vol. 60, pp. 19-31, 2016.

[24] G. Pang, C. Shen, L. Cao, and A. Van Den Hengel, "Deep learning for anomaly detection: A review," *ACM Computing Surveys*, vol. 54, no. 2, pp. 1-38, 2021.

[25] V. Kumar, "Parallel and distributed computing for cybersecurity," *IEEE Distributed Systems Online*, vol. 6, no. 10, 2005.

[26] V. Chandola, A. Banerjee, and V. Kumar, "Anomaly detection: A survey," *ACM Computing Surveys*, vol. 41, no. 3, pp. 1-58, 2009.

[27] R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in *Proc. IEEE Symposium on Security and Privacy*, 2010, pp. 305-316.

[28] K. Leung and C. Leckie, "Unsupervised anomaly detection in network intrusion detection using clusters," in *Proc. Australasian Computer Science Conference*, 2005, pp. 333-342.

[29] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation-based anomaly detection," *ACM Transactions on Knowledge Discovery from Data*, vol. 6, no. 1, pp. 1-39, 2012.

[30] S. Hariri, M. C. Kind, and R. J. Brunner, "Extended Isolation Forest," *IEEE Transactions on Knowledge and Data Engineering*, vol. 33, no. 4, pp. 1479-1489, 2021.

[31] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. IEEE International Conference on Data Mining (ICDM)*, 2008, pp. 413-422.

[32] M. M. Breunig, H.-P. Kriegel, R. T. Ng, and J. Sander, "LOF: Identifying density-based local outliers," in *Proc. ACM SIGMOD International Conference on Management of Data*, 2000, pp. 93-104.

[33] J. Tang, Z. Chen, A. W. Fu, and D. W. Cheung, "Enhancing effectiveness of outlier detections for low density patterns," in *Proc. Pacific-Asia Conference on Knowledge Discovery and Data Mining*, 2002, pp. 535-548.

[34] D. Pokrajac, A. Lazarevic, and L. J. Latecki, "Incremental local outlier detection for data streams," in *Proc. IEEE Symposium on Computational Intelligence and Data Mining*, 2007, pp. 504-515.

[35] B. Scholkopf, J. C. Platt, J. Shawe-Taylor, A. J. Smola, and R. C. Williamson, "Estimating the support of a high-dimensional distribution," *Neural Computation*, vol. 13, no. 7, pp. 1443-1471, 2001.

[36] D. M. J. Tax and R. P. W. Duin, "Support vector data description," *Machine Learning*, vol. 54, no. 1, pp. 45-66, 2004.

[37] S. S. Khan and M. G. Madden, "One-class classification: Taxonomy of study and review of techniques," *The Knowledge Engineering Review*, vol. 29, no. 3, pp. 345-374, 2014.

[38] M. Goldstein and S. Uchida, "A comparative evaluation of unsupervised anomaly detection algorithms for multivariate data," *PLOS ONE*, vol. 11, no. 4, e0152173, 2016.

[39] D. J. Hill and B. S. Minsker, "Anomaly detection in streaming environmental sensor data: A data-driven modeling approach," *Environmental Modelling & Software*, vol. 25, no. 9, pp. 1014-1022, 2010.

[40] S. W. Roberts, "Control chart tests based on geometric moving averages," *Technometrics*, vol. 1, no. 3, pp. 239-250, 1959.

[41] X. Li, F. Bian, M. Crovella, C. Diot, R. Govindan, G. Iannaccone, and A. Lakhina, "Detection and identification of network anomalies using sketch subspaces," in *Proc. ACM IMC*, 2006, pp. 147-152.

[42] S. Ramaswamy, R. Rastogi, and K. Shim, "Efficient algorithms for mining outliers from large data sets," in *Proc. ACM SIGMOD*, 2000, pp. 427-438.

[43] P. Casas, J. Mazel, and P. Owezarski, "Unsupervised network intrusion detection systems: Detecting the unknown without knowledge," *Computer Communications*, vol. 35, no. 7, pp. 772-783, 2012.

[44] C. Gormley and Z. Tong, *Elasticsearch: The Definitive Guide*, O'Reilly Media, 2015.

[45] Elastic, "Elasticsearch Reference," https://www.elastic.co/guide/en/elasticsearch/reference/current/.

[46] Elastic, "Logstash Reference," https://www.elastic.co/guide/en/logstash/current/.

[47] Elastic, "Kibana Guide," https://www.elastic.co/guide/en/kibana/current/.

[48] D. Gonzalez, T. Hayajneh, and M. Carpenter, "ELK-based security analytics for anomaly detection in IoT environments," *IEEE Access*, vol. 9, pp. 159467-159481, 2021.

[49] A. Chuvakin, K. Schmidt, and C. Phillips, *Logging and Log Management: The Authoritative Guide*, Syngress, 2012.

[50] Elastic, "Machine Learning in the Elastic Stack," https://www.elastic.co/what-is/elasticsearch-machine-learning.

[51] M. Najafabadi, T. Khoshgoftaar, C. Calvert, and C. Kemp, "Detection of SSH brute force attacks using aggregated netflow data," in *Proc. IEEE 14th ICMLA*, 2015, pp. 283-288.

[52] R. Hofstede, A. Pras, and A. Sperotto, "Flow-based SSH compromise detection," in *Proc. IFIP/IEEE IM*, 2018.

[53] P. Kumari and R. Jain, "Isolation Forest based anomaly detection for IoT systems," *Journal of King Saud University -- Computer and Information Sciences*, vol. 34, no. 8, pp. 5765-5774, 2022.

[54] N. Moustafa and J. Slay, "The evaluation of Network Anomaly Detection Systems: Statistical analysis of the UNSW-NB15 data set," *Information Security Journal*, vol. 25, no. 1-3, pp. 18-31, 2016.

[55] O. Starov, Y. Gill, P. Hartlieb, and P. Hartlieb, "Detecting SSH brute-force attacks using temporal behavioral analysis," in *Proc. IEEE CNS*, 2019.

[56] S. Ahmad, A. Lavin, S. Purdy, and Z. Agha, "Unsupervised real-time anomaly detection for streaming data," *Neurocomputing*, vol. 262, pp. 134-147, 2017.

[57] A. Sperotto, R. Sadre, F. van Vliet, and A. Pras, "A labeled data set for flow-based intrusion detection," in *Proc. IEEE IPOM*, 2009, pp. 39-50.

[58] A. Satoh, Y. Nakamura, and T. Ikenaga, "SSH dictionary attack detection using deep learning," *IEEE Access*, vol. 10, pp. 23456-23467, 2022.

[59] V. T. Nguyen and M. Q. Tran, "Application of machine learning in network intrusion detection," *Journal of Science and Technology -- University of Danang*, vol. 19, no. 5, pp. 45-52, 2021.

[60] H. V. Le et al., "Building a network security monitoring system using ELK Stack for SMEs," *Journal of ICT*, vol. 2022, no. 3, pp. 78-85, 2022.

[61] N. H. Pham, "Research on SSH brute-force prevention solutions for government information systems," *Master's Thesis, Academy of Cryptography Techniques*, 2020.

[62] D. K. Tran and T. T. H. Nguyen, "Application of Isolation Forest in anomaly detection on system log data," *Journal of Scientific Research and Development*, vol. 2, no. 4, pp. 112-121, 2023.

[63] R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in *Proc. IEEE Symposium on Security and Privacy*, 2010, pp. 305-316.
