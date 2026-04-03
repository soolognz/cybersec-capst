# CHAPTER 1: INTRODUCTION

## 1.1 Background

In the context of accelerating digital transformation across the globe, information technology infrastructure plays an increasingly critical role in the operations of organizations, enterprises, and government agencies. According to a report by Cybersecurity Ventures, the global cost of cybercrime is projected to reach 10.5 trillion USD annually by 2025, a dramatic increase from 3 trillion USD in 2015 [1]. This rapid escalation reflects the growing complexity and scale of cyberattacks, underscoring the urgent need for advanced and effective cybersecurity solutions.

The Secure Shell (SSH) protocol is among the most widely used protocols for remote system administration, secure file transfer, and establishing encrypted communication channels. Originally developed in 1995 by Tatu Ylonen at the Helsinki University of Technology, SSH has become the industry standard for managing Linux/Unix servers [2]. However, its very ubiquity has made SSH a primary target for cyberattacks, particularly brute-force attacks, in which an adversary systematically attempts thousands to millions of username-password combinations in order to gain unauthorized access to a system.

Data from the SANS Internet Storm Center indicate that TCP port 22 (SSH) consistently ranks among the top five most scanned and attacked ports on the Internet [3]. A 2023 report by Rapid7 found that, on average, a publicly accessible SSH server receives more than 10,000 unauthorized login attempts per day [4]. In Vietnam, the National Cyber Security Center (NCSC) has reported that SSH brute-force attacks constitute a significant proportion of total cybersecurity incidents recorded annually, with a steadily increasing trend from 2020 onward [5].

Traditional methods of defending against SSH brute-force attacks include rate limiting (restricting the number of failed login attempts), IP blacklisting, public key authentication, and deploying tools such as Fail2Ban or DenyHosts [6]. While these approaches have demonstrated a measure of effectiveness, they suffer from several well-documented limitations. First, methods based on static thresholds are easily circumvented by attackers who reduce the speed of their attempts (slow brute-force) or distribute the attack across multiple IP addresses (distributed brute-force) [7]. Second, the lack of learning and adaptive capabilities prevents traditional systems from recognizing novel attack variants. Third, high false positive rates can disrupt service for legitimate users by erroneously blocking their access.

Against this backdrop, artificial intelligence (AI) and machine learning (ML) have emerged as a highly promising approach to the problem of detecting and preventing cyberattacks. Machine learning models possess the capability to analyze large volumes of log data, identify anomalous behavioral patterns, and issue alerts in real time --- capabilities that rule-based static methods are inherently unable to match [8]. In particular, unsupervised anomaly detection algorithms such as Isolation Forest, Local Outlier Factor (LOF), and One-Class SVM offer a distinct advantage in detecting previously unknown forms of attack, because they do not require labeled data for training [9].

This research was motivated by the practical need to develop an intelligent SSH brute-force attack detection and prevention system with early prediction capabilities, enabling the system to identify attacks before they inflict damage. The proposed system integrates the Isolation Forest algorithm with an EWMA-Adaptive Percentile dynamic thresholding mechanism, deployed on an ELK Stack (Elasticsearch, Logstash, Kibana) and Fail2Ban infrastructure, to create a comprehensive solution encompassing data collection, analysis, detection, and automated response.

The growing reliance on cloud computing and Infrastructure-as-a-Service (IaaS) models has further amplified the importance of SSH security. Major cloud providers including Amazon Web Services (AWS), Google Cloud Platform (GCP), and Microsoft Azure all use SSH as the default protocol for remote access to virtual machine instances. According to Shodan, the specialized search engine for Internet-connected devices, there are over 20 million SSH servers publicly accessible on the Internet at any given time. Each of these servers represents a potential target for brute-force attacks, and the automation of such attacks through botnets and commercial attack tools has made the threat landscape increasingly hostile.

The financial impact of successful SSH compromises extends far beyond the immediate cost of the intrusion itself. Once an attacker gains SSH access to a server, the compromise typically leads to lateral movement within the organization's network, data exfiltration, ransomware deployment, or the installation of cryptocurrency miners. IBM's 2023 Cost of a Data Breach report estimates the average cost of a data breach at 4.45 million USD, with compromised credentials being the most common initial attack vector, responsible for 15% of all breaches. In the Vietnamese context, the Ministry of Information and Communications has emphasized the need for AI-driven cybersecurity solutions as part of the national digital transformation strategy for the period 2021-2025, creating both an institutional imperative and a research opportunity for the development of intelligent security systems.

The convergence of these factors --- the ubiquity of SSH, the increasing sophistication of brute-force attacks, the limitations of traditional detection methods, and the maturation of machine learning techniques --- creates a compelling case for the research presented in this thesis. By combining the Isolation Forest algorithm with a novel dynamic thresholding mechanism and deploying the solution on a modern ELK Stack infrastructure, this research aims to advance the state of the art in SSH security while providing a practical, deployable system for real-world use.

## 1.2 Problem Statement

SSH brute-force attacks represent one of the most persistent and prevalent forms of cyberattack. Despite the existence of numerous deployed countermeasures, the problem of detecting and preventing such attacks remains beset by several unresolved challenges.

**Challenge 1: The evolution of attack techniques.** Modern attackers no longer rely on simple, high-speed brute-force methods. Instead, they employ a range of sophisticated evasion techniques, including: slow brute-force attacks, in which the interval between attempts is deliberately lengthened to evade rate-limiting mechanisms; distributed brute-force attacks, which leverage botnets comprising thousands of IP addresses; intelligent dictionary attacks, employing customized password lists tailored to the target; and credential stuffing attacks, which exploit login credentials leaked from prior data breaches [10].

**Challenge 2: Limitations of static thresholds.** Traditional tools such as Fail2Ban operate on the basis of fixed thresholds --- for example, blocking an IP address after 5 failed login attempts within a 10-minute window. This approach creates two opposing problems: if the threshold is set too low, legitimate users who mistype their password may be erroneously blocked (false positives); if the threshold is set too high, attackers can conduct slow brute-force campaigns without being detected (false negatives) [11]. Moreover, static thresholds are unable to adapt to the natural fluctuation of network traffic over time --- peak hours and off-hours exhibit fundamentally different behavioral patterns.

**Challenge 3: Lack of early prediction capability.** The majority of existing solutions operate in a reactive mode, responding only after an attack has already occurred, rather than proactively predicting an attack before it escalates. The reconnaissance and initial probing phases --- during which an attacker tests a small number of credential combinations to evaluate the target --- are typically not identified, thereby forfeiting the opportunity to intervene before a full-scale attack is launched [12].

**Challenge 4: Integration and automation.** Many studies on the application of AI to attack detection focus exclusively on algorithmic aspects without addressing the practical problem of integration into operational infrastructure. The gap between research prototypes and deployable production systems (the research-to-deployment gap) remains a significant barrier to the practical adoption of AI in cybersecurity [13].

In light of these challenges, the primary research question of this thesis is formulated as follows:

> *How can an AI-based SSH brute-force attack detection and prevention system be constructed that is capable of early attack prediction, dynamically adapts to changes in traffic patterns, and integrates fully into modern security monitoring infrastructure?*

The subsidiary research questions are:

1. How effectively does the Isolation Forest algorithm detect SSH brute-force attacks compared to other unsupervised anomaly detection algorithms (LOF, One-Class SVM)?
2. To what extent does the EWMA-Adaptive Percentile dynamic thresholding mechanism improve detection performance relative to traditional static thresholds?
3. What degree of early prediction does the proposed system achieve across different brute-force attack scenarios?
4. Can the integrated architecture combining ELK Stack, Isolation Forest, and Fail2Ban meet the requirements for real-time monitoring and automated response in a practical environment?

## 1.3 Research Objectives

This research aims to design, implement, and evaluate an AI-based SSH brute-force attack detection and prevention system that integrates early prediction and automated response capabilities, operating on an ELK Stack platform with an adaptive dynamic thresholding mechanism. The research is guided by a clear set of goals that address the identified challenges systematically, spanning the full lifecycle from data collection and feature engineering through model training and evaluation to system deployment and real-time operation.

The specific objectives are as follows:

**Objective 1: Design a comprehensive SSH behavioral feature set.** Design and implement a set of 14 features extracted from SSH log data over 5-minute time windows per source IP address, encompassing features related to frequency, temporal distribution, authentication patterns, and connection behavior. This feature set must comprehensively capture the behavioral aspects necessary to distinguish between normal activity and attacks.

**Objective 2: Train and evaluate anomaly detection models.** Implement and systematically compare the performance of three unsupervised anomaly detection algorithms: Isolation Forest, Local Outlier Factor (LOF), and One-Class SVM. The target performance is a minimum F1-score of 85% and a minimum recall of 95% to ensure a high attack detection rate with minimal missed detections.

**Objective 3: Develop an adaptive dynamic thresholding mechanism.** Design and implement a dynamic threshold method combining EWMA (Exponentially Weighted Moving Average) and Adaptive Percentile, enabling the system to automatically adjust its detection threshold in response to variations in network traffic, thereby minimizing false alarm rates while maintaining high detection sensitivity.

**Objective 4: Build a complete integrated system.** Design a system architecture integrating the ELK Stack (Elasticsearch, Logstash, Kibana) for data collection and visualization, the Isolation Forest model for anomaly detection, and Fail2Ban for automated response. The entire system is containerized using Docker to ensure portability and reproducibility.

**Objective 5: Evaluate the system against realistic attack scenarios.** Design and execute 5 simulated SSH brute-force attack scenarios with varying characteristics --- basic brute-force, slow brute-force, distributed attack, dictionary attack, and credential stuffing --- to comprehensively evaluate the detection and early prediction capabilities of the system. Each scenario is designed to test a specific aspect of the system's capabilities: the basic and dictionary scenarios test detection of straightforward attacks, the distributed and credential stuffing scenarios test detection of attacks that evade per-IP thresholds, and the slow brute-force scenario tests the early prediction capabilities of the dynamic threshold mechanism.

These five objectives collectively address the full spectrum of challenges identified in the problem statement: the evolution of attack techniques (Objectives 1, 5), the limitations of static thresholds (Objective 3), the lack of early prediction (Objectives 3, 5), and the integration and automation gap (Objective 4). The measurable targets (F1>85%, Recall>95%) provide concrete criteria for evaluating the success of the research.

## 1.4 Significance of the Study

### 1.4.1 Scientific Significance

This research contributes to the fields of cybersecurity and artificial intelligence on several fronts. First, the thesis provides a systematic comparative analysis of three unsupervised anomaly detection algorithms --- Isolation Forest, LOF, and One-Class SVM --- in the specific context of SSH brute-force attack detection. Although these algorithms have been extensively studied for general network intrusion detection, their evaluation on real-world SSH attack data from a honeypot remains limited in the existing literature.

Second, the study proposes the EWMA-Adaptive Percentile dynamic thresholding method, a novel approach compared to the fixed thresholds or simple dynamic thresholds commonly used in the literature. This mechanism enables the system to adapt to the natural variability of network traffic while maintaining high sensitivity to attack patterns.

Third, the set of 14 SSH behavioral features designed in this study can serve as a reference foundation for future research on SSH-based anomaly detection, particularly in terms of representing the differences between normal behavior and attacks within short time windows (5 minutes).

Fourth, the research demonstrates that temporal features --- specifically session duration and inter-attempt timing --- are the most discriminative characteristics for distinguishing automated brute-force attacks from legitimate SSH activity, a finding with implications for the design of future detection systems. Feature importance analysis revealed that session_duration_mean (5.50%), min_inter_attempt_time (3.86%), and mean_inter_attempt_time (2.61%) are the top three most important features, outweighing traditional count-based features such as fail_count.

### 1.4.2 Practical Significance

From a practical perspective, the system developed in this research can be deployed directly into the operational environments of organizations and enterprises. The Docker-based architecture ensures portability and rapid deployment. The use of the ELK Stack --- a widely adopted open-source toolset --- reduces deployment costs compared to commercial solutions.

The system provides real-time visual monitoring through the Kibana dashboard and a custom React-based interface, enabling security administrators to track SSH security status in real time. Integration with Fail2Ban ensures automated response upon attack detection, minimizing the mean time to respond (MTTR).

Of particular practical value is the system's early prediction capability, which enables the interception of attacks before they cause damage. Rather than waiting for an attacker to complete thousands of login attempts, the system can identify attack intent from the initial reconnaissance phase, providing the opportunity for timely intervention. In the low-and-slow attack scenario, the system issues an EARLY_WARNING alert after only 3-5 attempts (approximately 2-3 minutes), whereas Fail2Ban with default settings (maxretry=5, findtime=600s) would fail to detect the attack entirely if the attacker spaces attempts sufficiently.

The research outcomes also serve educational and awareness-raising purposes, particularly within the Information Assurance curriculum at FPT University, where students can reference and extend this work. The open-source nature of the underlying technologies (scikit-learn, FastAPI, Elasticsearch, Docker) ensures that the system can be reproduced and experimented with at minimal cost, making it suitable for both academic research and practical training exercises. Students can use the system as a platform for exploring machine learning concepts, cybersecurity principles, and modern software engineering practices in an integrated, hands-on manner.

Furthermore, the research contributes to the growing body of knowledge on AI applications in cybersecurity within the Vietnamese academic community. As the country accelerates its digital transformation and faces increasing cybersecurity challenges, locally developed and validated solutions become increasingly important for building domestic capability and reducing dependence on imported security technologies.

## 1.5 Scope and Limitations

### 1.5.1 Scope

The scope of this research is carefully delineated to ensure depth and rigor within a well-defined boundary, while acknowledging the broader context within which the work is situated.

**Protocol and attack type:** This research focuses on SSH version 2 (SSH-2) and brute-force attacks targeting password-based authentication. The attack forms considered include: classic brute-force (exhaustive enumeration), dictionary attacks, slow brute-force, distributed attacks, and credential stuffing.

**Data:** The research employs two primary data sources: (1) real-world attack data collected from an SSH honeypot system, comprising 119,729 log lines recording brute-force attacks from diverse Internet sources across 679 unique IP addresses; and (2) simulated normal behavior data, comprising 54,521 log lines representing legitimate SSH activities from 64 user accounts. The combined dataset totals 174,250 log lines.

**Algorithms:** The research implements and evaluates three unsupervised anomaly detection algorithms: Isolation Forest (primary algorithm), Local Outlier Factor (LOF), and One-Class SVM (benchmark algorithms). Supervised learning algorithms fall outside the scope of this study, given that the problem demands the ability to detect previously unknown attack forms without requiring labeled attack data.

**Infrastructure:** The system is built on the ELK Stack (Elasticsearch 8.x, Logstash, Kibana) combined with Fail2Ban, containerized using Docker Compose. The test environment utilizes a Linux-based server.

### 1.5.2 Limitations

This research, like all empirical studies, has several limitations that must be transparently acknowledged to enable appropriate interpretation of the results and to guide future research directions. First, the normal behavior data was generated through simulation and may not fully capture the diversity of legitimate SSH behavior across all operational environments. Although the simulation scenarios were designed to cover a wide range of situations, certain environment-specific legitimate behavioral patterns may not be represented in the training data.

Second, the research is focused exclusively on SSH brute-force attacks and does not encompass other types of SSH-based attacks such as man-in-the-middle attacks, session hijacking, or exploitation of SSH software vulnerabilities. Extending the scope to address these attack types would require additional analytical methods.

Third, the system's performance was evaluated in a test environment of moderate scale. The scalability of the system to process traffic from hundreds or thousands of SSH servers simultaneously has not been fully verified, although the ELK Stack architecture theoretically supports horizontal scaling.

Fourth, the Isolation Forest model was trained and evaluated on a specific dataset; its performance may vary when applied to different environments with distinct behavioral patterns and SSH configurations. The study recommends retraining the model when deploying to a new environment.

## 1.6 Thesis Structure

This thesis is organized into six chapters, each serving a specific purpose in presenting the complete research process:

**Chapter 1: Introduction.** This chapter presents the research background, problem statement, research objectives, scientific and practical significance, scope and limitations, and the overall structure of the thesis. It provides an overview of the motivation and approach of the research.

**Chapter 2: Literature Review.** This chapter synthesizes and analyzes the theoretical foundations and related works, including: the SSH protocol, brute-force attack methods, machine learning in intrusion detection, anomaly detection algorithms (Isolation Forest, LOF, One-Class SVM), dynamic thresholding methods, and the ELK Stack. The chapter also identifies the research gaps that this thesis aims to address.

**Chapter 3: Methodology.** This chapter describes the research methodology in detail, including the system architecture, data collection and processing procedures, feature engineering, model configuration and training, the EWMA-Adaptive Percentile dynamic threshold mechanism, and performance evaluation methods.

**Chapter 4: Experimental and Results.** This chapter presents the experimental results, including statistical analysis of the dataset, model training and evaluation results, comparative performance analysis across algorithms, evaluation of the dynamic thresholding mechanism, and results from the five attack simulation scenarios.

**Chapter 5: Discussion.** This chapter analyzes and interprets the results, discusses their implications, compares them with related works, and presents the key findings of the research.

**Chapter 6: Conclusion and Future Work.** The final chapter summarizes the main contributions of the research, evaluates the degree to which the research objectives were achieved, and proposes directions for future research.

---

## References for Chapter 1

[1] S. Morgan, "Cybercrime to cost the world $10.5 trillion annually by 2025," *Cybersecurity Ventures*, 2021.

[2] T. Ylonen and C. Lonvick, "The Secure Shell (SSH) Protocol Architecture," RFC 4251, *Internet Engineering Task Force (IETF)*, 2006.

[3] SANS Internet Storm Center, "DShield: Top 10 Target Ports," https://isc.sans.edu/top10.html, accessed 2025.

[4] Rapid7, "2023 Attack Intelligence Report," *Rapid7 Research*, 2023.

[5] National Cyber Security Center (NCSC), "Annual Report on Cybersecurity in Vietnam," *Ministry of Information and Communications*, 2023.

[6] D. R. Tsai, A. Y. Chang, and S. H. Wang, "A study of SSH brute force attack defense," *Journal of Information Security and Applications*, vol. 49, pp. 102-113, 2019.

[7] M. Najafabadi, T. Khoshgoftaar, C. Calvert, and C. Kemp, "Detection of SSH brute force attacks using aggregated netflow data," in *Proc. IEEE 14th International Conference on Machine Learning and Applications*, 2015, pp. 283-288.

[8] A. L. Buczak and E. Guven, "A survey of data mining and machine learning methods for cyber security intrusion detection," *IEEE Communications Surveys & Tutorials*, vol. 18, no. 2, pp. 1153-1176, 2016.

[9] M. A. Pimentel, D. A. Clifton, L. Clifton, and L. Tarassenko, "A review of novelty detection," *Signal Processing*, vol. 99, pp. 215-249, 2014.

[10] A. Simoiu, C. Gates, J. Bonneau, and S. Goel, "I was told to buy a software or lose my computer. I ignored it: A study of ransomware," in *Proc. Symposium on Usable Privacy and Security (SOUPS)*, 2019, pp. 155-174.

[11] J. Jang-Jaccard and S. Nepal, "A survey of emerging threats in cybersecurity," *Journal of Computer and System Sciences*, vol. 80, no. 5, pp. 973-993, 2014.

[12] F. Syed, M. Bashir, and A. Sharaff, "Machine learning approaches for intrusion detection in IoT: A comprehensive survey," *Journal of King Saud University -- Computer and Information Sciences*, vol. 34, no. 10, pp. 9656-9688, 2022.

[13] R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in *Proc. IEEE Symposium on Security and Privacy*, 2010, pp. 305-316.

[Figure 1.1: Global trends in SSH brute-force attacks (2018-2025)]

[Figure 1.2: Comparison of traditional vs. AI-based attack detection approaches]

[Figure 1.3: Overview of the proposed system architecture (block diagram)]

[Table 1.1: Summary of research challenges and proposed solutions]

[Table 1.2: Research objectives and corresponding approaches]
