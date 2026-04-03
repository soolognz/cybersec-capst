# CHAPTER 2: LITERATURE REVIEW

## 2.1 Secure Shell (SSH) Protocol and Its Security Landscape

The Secure Shell (SSH) protocol was originally developed in 1995 by Tatu Ylonen at the Helsinki University of Technology as a secure replacement for unencrypted remote access protocols including Telnet, rlogin, and rsh [1]. The protocol was subsequently standardized by the Internet Engineering Task Force (IETF) through the RFC 4250--4256 document series, with RFC 4251 defining the overall protocol architecture [1]. Barrett, Silverman, and Byrnes [2] provide a comprehensive treatment of SSH implementation and deployment, documenting the protocol's evolution from a research tool to the universal standard for secure remote system administration. As of 2024, SSH is deployed on virtually every Linux and Unix server connected to the Internet, and all major cloud infrastructure providers---Amazon Web Services, Google Cloud Platform, and Microsoft Azure---use SSH key pairs as the default mechanism for initial access to virtual machine instances [1, 2].

The SSH-2 protocol architecture is organized into three layered components, each addressing a distinct security function [1, 2]. The Transport Layer Protocol (RFC 4253) establishes server authentication, data confidentiality through symmetric encryption, and data integrity through message authentication codes. The handshake process involves protocol version exchange, algorithm negotiation, Diffie-Hellman key exchange, and server host key verification. The User Authentication Protocol (RFC 4252) handles client identity verification through one of several methods: password authentication, public key authentication, host-based authentication, or keyboard-interactive authentication. The Connection Protocol (RFC 4254) multiplexes multiple logical channels over a single encrypted connection, supporting remote command execution, port forwarding, and secure file transfer via SFTP/SCP.

Password-based authentication, despite being the least secure of the available methods, remains widely deployed due to its simplicity and the absence of prerequisite key management infrastructure [2, 4]. The default OpenSSH configuration permits up to six authentication attempts per connection (MaxAuthTries = 6) and imposes no limit on the number of concurrent connections from a single source IP address [1, 6]. This permissive default configuration, combined with the protocol's lack of any built-in anti-automation mechanism (unlike web applications that can employ CAPTCHAs), creates a structurally exploitable attack surface for automated brute-force tools [2, 5].

The scale of SSH-targeted attacks is documented by multiple empirical studies. Wu et al. [3] analyzed data from the National Center for Supercomputing Applications (NCSA) honeypot deployment and recorded approximately 11 billion SSH brute-force login attempts, demonstrating that SSH brute-forcing operates at an industrial scale driven by globally distributed botnets. The Verizon Data Breach Investigations Report [4] identifies stolen credentials as the most prevalent initial attack vector, accounting for approximately 29% of confirmed data breaches, with brute-force and credential-stuffing attacks representing the primary credential-theft mechanisms. Hellemons et al. [5] developed the SSHCure system and characterized SSH attacks as following a three-phase temporal structure: an initial scanning phase in which the attacker probes target reachability, a brute-force phase involving systematic credential enumeration, and a compromise phase in which successful credentials are exploited for lateral movement or data exfiltration.

SSH servers record authentication events in system log files (typically `/var/log/auth.log` on Debian-based systems or `/var/log/secure` on Red Hat-based systems), with each event containing a timestamp, source IP address, attempted username, authentication result (success or failure), authentication method, and source port [1, 5]. These structured log fields provide the raw data from which behavioral features can be extracted for machine-learning-based anomaly detection, a capability that this thesis exploits through a 14-feature extraction pipeline operating on 5-minute sliding windows per source IP address.

[Figure 2.1: Layered architecture of the SSH-2 protocol and authentication flow]

## 2.2 Brute-Force Attacks: Taxonomy, Patterns, and Evolution

Brute-force attacks against SSH servers can be formally defined as systematic attempts to discover valid authentication credentials through exhaustive or guided enumeration of the credential space [3, 4]. Given a character alphabet of size $|A|$ and a target password of length $L$, the theoretical maximum search space is $S = |A|^L$. For a password composed of lowercase letters (26) and digits (10) with length 8, this yields $S = 36^8 \approx 2.82 \times 10^{12}$ combinations. In practice, however, attackers rarely perform exhaustive enumeration; instead, they exploit the highly non-uniform distribution of human-chosen passwords to reduce the effective search space by orders of magnitude [4, 19].

The taxonomy of SSH brute-force attacks has evolved substantially over the past decade, driven by the arms race between attackers and defenders. Based on the literature [3, 5, 18, 19, 23] and empirical analysis of the honeypot data collected for this research (679 unique attacking IPs, 29,301 failed password attempts), five principal attack variants can be identified:

**Classic brute-force.** The attacker attempts credential combinations at maximum speed, typically targeting high-value accounts such as root, admin, and user [3, 5]. Characteristic behavioral signatures include extremely high login attempt frequency (hundreds to thousands per minute), near-uniform inter-attempt intervals (reflecting automated tool cadence), and rapid cycling through multiple usernames. Wu et al. [3] found that the root account is targeted in over 80% of SSH brute-force sessions observed in their honeypot data.

**Dictionary attack.** This variant employs curated password lists (wordlists) rather than exhaustive enumeration, exploiting the observation that a small number of passwords account for a disproportionate fraction of real-world credential choices [19]. Owens and Matthews [19] analyzed SSH honeypot data and found that the top 20 most-attempted passwords accounted for over 40% of all login attempts, with "123456", "password", and "admin" consistently appearing in the top positions. Widely used wordlists include RockYou (approximately 14 million entries) and the SecLists collection, and attackers increasingly generate target-specific lists incorporating organizational names, service identifiers, and locale-specific terms.

**Slow brute-force (low-and-slow attack).** The attacker deliberately reduces the attempt rate to evade frequency-based detection thresholds, executing only a few attempts per minute or per hour [23]. Javed and Paxson [23] conducted a systematic study of stealthy SSH brute-forcing and demonstrated that attacks operating at rates as low as 1--2 attempts per hour can achieve compromise rates comparable to aggressive campaigns while remaining invisible to conventional monitoring tools configured with standard thresholds. This attack variant is particularly insidious because its behavioral profile closely resembles that of a legitimate user who has forgotten their password [5, 7].

**Distributed brute-force.** This variant leverages botnets or proxy networks to distribute the attack across hundreds or thousands of source IP addresses, with each individual IP performing only a small number of attempts [3, 5]. Per-IP failure-count-based detection methods are structurally incapable of identifying distributed attacks because no single IP exceeds the detection threshold. Wu et al. [3] documented coordinated distributed attacks originating from geographically diverse IP addresses that collectively executed millions of attempts while maintaining per-IP attempt counts below typical Fail2Ban thresholds.

**Credential stuffing.** This variant exploits username-password pairs leaked from data breaches at other services, capitalizing on the widespread practice of password reuse across platforms [4, 19]. Credential-stuffing attacks are particularly dangerous because the per-attempt success rate is substantially higher than that of random or dictionary-based attacks. The Verizon DBIR [4] notes that credential-stuffing attacks have increased significantly following major data breaches, with automated tools such as Sentry MBA and OpenBullet enabling attackers to test millions of leaked credentials against SSH servers.

Bezerra et al. [18] analyzed SSH attack durations across a large-scale honeypot dataset and identified significant variability in temporal profiles: attack sessions ranged from sub-second bursts (automated scanners testing a single credential) to sustained campaigns spanning multiple days (coordinated, multi-phase attacks). This temporal diversity imposes a requirement for detection systems to operate effectively across multiple time scales---a requirement that motivates the 5-minute sliding window approach adopted in this thesis.

[Table 2.1: Taxonomy of SSH brute-force attack variants with characteristic behavioral features]

| Variant | Attempt Rate | IP Diversity | Password Strategy | Detection Difficulty |
|---------|-------------|-------------|-------------------|---------------------|
| Classic brute-force | Very high (>100/min) | Single IP | Exhaustive or top-N | Low |
| Dictionary attack | High (10--100/min) | Single IP | Wordlist-based | Low--Medium |
| Slow brute-force | Very low (<1/min) | Single IP | Targeted | High |
| Distributed attack | Low per IP | Many IPs (>10) | Coordinated | High |
| Credential stuffing | Medium | Variable | Leaked credentials | Very High |

## 2.3 Traditional Defense Mechanisms and Their Limitations

Traditional SSH brute-force defense mechanisms can be categorized into four classes, each with characteristic strengths and limitations [6, 7, 12].

**Threshold-based intrusion prevention.** Fail2Ban [6] is the most widely deployed tool in this category. It monitors SSH authentication logs and applies firewall rules (via iptables or nftables) to block IP addresses that exceed a configured failure threshold within a specified time window. The default SSH jail configuration uses maxretry = 5, findtime = 600 seconds, and bantime = 600 seconds. While effective against naive high-speed attacks, Fail2Ban's static threshold architecture creates an inherent precision-sensitivity tradeoff: lowering the threshold increases false positives (blocking legitimate users who mistype passwords), while raising it increases false negatives (permitting slow or distributed attacks) [6, 7]. Chandola et al. [7] identified this static-threshold limitation as a fundamental challenge in anomaly detection, noting that real-world data streams exhibit non-stationary behavior that fixed thresholds cannot accommodate.

**IP reputation and blacklisting.** Services such as AbuseIPDB, Spamhaus, and Blocklist.de maintain databases of IP addresses associated with malicious activity [4, 6]. Blacklist-based approaches are inherently reactive---an IP is listed only after it has been observed conducting attacks elsewhere---and are easily circumvented by attackers who rotate through fresh IP addresses or employ residential proxy networks [3, 7]. Furthermore, blacklists suffer from both false positives (legitimate services operating behind shared NAT addresses that have been erroneously listed) and incomplete coverage (newly provisioned attack infrastructure that has not yet been reported).

**Signature-based intrusion detection.** Network intrusion detection systems such as Snort and Suricata can identify SSH brute-force attacks by matching traffic patterns against predefined rule signatures [7, 15]. However, signature-based detection is structurally limited to known attack patterns for which rules have been written and cannot detect novel attack variants [12]. Moreover, because SSH traffic is encrypted end-to-end, deep packet inspection of SSH session content is infeasible; detection must rely on metadata features (connection frequency, flow duration, packet sizes) rather than payload analysis [15].

**Authentication hardening.** Measures such as public key authentication, two-factor authentication (via PAM modules), non-standard port assignment, and port knocking reduce the attack surface by either eliminating password authentication entirely or raising the barrier to initial connection establishment [1, 2]. While highly effective when deployed, these measures are not universally applicable---legacy systems, multi-user environments with diverse client configurations, and cloud instances requiring initial password-based bootstrapping all present practical obstacles to full authentication hardening [2, 6].

The limitations of these traditional mechanisms motivate the application of machine learning approaches that can learn complex behavioral patterns from data, adapt to changing traffic conditions, and detect novel attack variants without requiring explicit rule definitions [7, 12]. Buczak and Guven [12] concluded their comprehensive survey by noting that the integration of machine learning with traditional security infrastructure represents the most promising direction for next-generation intrusion detection systems.

[Table 2.2: Comparison of traditional SSH defense mechanisms]

| Method | Strengths | Limitations | Evasion Techniques |
|--------|-----------|-------------|-------------------|
| Fail2Ban (threshold) | Simple, low overhead | Static threshold, no adaptation | Slow-rate, distributed |
| IP blacklisting | No local computation | Reactive, incomplete coverage | IP rotation, proxies |
| Signature IDS | Known-attack detection | Cannot detect novel attacks | Encryption, polymorphism |
| Auth hardening | Eliminates attack surface | Not universally deployable | N/A (preventive) |

## 2.4 Anomaly Detection for Intrusion Detection Systems

Anomaly detection, defined as the identification of data patterns that deviate significantly from expected normal behavior, constitutes one of the foundational paradigms in intrusion detection [7]. Chandola, Banerjee, and Kumar [7] provided a seminal taxonomy of anomaly detection approaches, categorizing them along two principal dimensions: the nature of the detection model (classification-based, nearest-neighbor-based, clustering-based, statistical, information-theoretic, spectral, and isolation-based) and the availability of labeled data (supervised, semi-supervised, and unsupervised).

In the context of network intrusion detection, the semi-supervised anomaly detection paradigm---in which models are trained exclusively on data representing normal behavior and subsequently identify deviations from the learned normal profile as potential attacks---has attracted substantial research attention [7, 12, 17]. This paradigm offers three key advantages for SSH brute-force detection. First, it does not require labeled attack data for training, circumventing the practical challenge of obtaining comprehensive, accurately labeled datasets in operational environments [17, 24]. Pimentel et al. [17] provided a comprehensive review of novelty detection---the closely related problem of identifying previously unseen patterns---and noted that one-class learning approaches (trained on a single class of normal data) provide the most robust framework for detecting genuinely novel anomalies. Second, semi-supervised approaches can detect zero-day attacks and novel attack variants that have never been observed in training data, because detection is based on deviation from normality rather than similarity to known attacks [7, 12]. Third, in SSH environments, normal behavior data is readily available from production logs (by selecting periods of known-clean operation) or from controlled simulation, making the semi-supervised training paradigm practically feasible [15, 24].

The choice among specific anomaly detection algorithms involves tradeoffs along multiple dimensions: computational complexity (critical for real-time processing), sensitivity to hyperparameter selection, ability to handle high-dimensional feature spaces, robustness to noise and outliers in training data, and interpretability of anomaly scores [7, 20]. Goldstein and Uchida [20] conducted a comprehensive comparative evaluation of unsupervised anomaly detection algorithms on standardized benchmark datasets and found that no single algorithm dominates across all datasets and evaluation metrics, underscoring the importance of algorithm selection based on the specific characteristics of the target domain. Nassif et al. [21] extended this analysis to the cybersecurity domain specifically, surveying machine learning approaches for anomaly-based intrusion detection and identifying Isolation Forest, LOF, and OCSVM as the three most widely studied unsupervised algorithms for network security applications.

For this thesis, three algorithms were selected for implementation and comparative evaluation: Isolation Forest [8, 9] as the primary detection algorithm, and Local Outlier Factor [10] and One-Class SVM [11] as benchmarks. This selection is motivated by the complementary detection paradigms they represent (isolation-based, density-based, and boundary-based, respectively), their established track records in network intrusion detection research [20, 21], and their availability in mature, well-tested implementations within the scikit-learn library. The following three sections present the mathematical foundations of each algorithm.

## 2.5 Isolation Forest and Its Extensions

### 2.5.1 Algorithmic Foundation

Isolation Forest (IF) was proposed by Liu, Ting, and Zhou [8] at the IEEE International Conference on Data Mining (ICDM) in 2008 and subsequently formalized in a comprehensive journal publication in ACM Transactions on Knowledge Discovery from Data (TKDD) in 2012 [9]. The algorithm represents a paradigm shift in anomaly detection: whereas traditional methods detect anomalies as data points that are distant from (distance-based methods) or sparse relative to (density-based methods) the majority of the data, Isolation Forest detects anomalies as data points that are easy to isolate through random partitioning [8, 9].

The fundamental insight underlying Isolation Forest is that anomalous data points, by virtue of their atypical feature values, require fewer random partitions to be separated from the rest of the dataset than normal points [8]. This property arises because anomalies are typically few in number and possess feature values that are substantially different from those of the majority population, making them susceptible to isolation by a small number of random splits.

### 2.5.2 Isolation Tree Construction

An Isolation Tree (iTree) is constructed through a recursive random partitioning process [8, 9]. Given a dataset $X = \{x_1, x_2, \ldots, x_n\}$ with $d$ features, the construction proceeds as follows:

1. Randomly select a feature $q$ from the $d$ available features.
2. Randomly select a split value $p$ uniformly from the interval $[\min(X_q), \max(X_q)]$, where $X_q$ denotes the values of feature $q$ in the current node's data.
3. Partition the data into two subsets: the left branch contains points where $x_q < p$, and the right branch contains points where $x_q \geq p$.
4. Recurse on each branch until one of the stopping conditions is met: the node contains a single data point (isolated), or the tree reaches a predefined maximum depth $l = \lceil \log_2 \psi \rceil$, where $\psi$ is the sub-sampling size.

### 2.5.3 Anomaly Score Computation

The anomaly score of a data point $x$ is derived from its average path length across an ensemble of $t$ Isolation Trees [8, 9]. The path length $h(x)$ of a point $x$ in a single iTree is defined as the number of edges traversed from the root node to the terminal node (external node) at which $x$ is isolated, plus an adjustment factor $c(k)$ for the unbuilt subtree when the maximum depth is reached, where $k$ is the number of data points in the terminal node.

The anomaly score is defined as:

$$s(x, n) = 2^{-\frac{E[h(x)]}{c(n)}}$$

where $E[h(x)]$ is the expected (average) path length of $x$ across $t$ Isolation Trees, and $c(n)$ is the average path length of an unsuccessful search in a Binary Search Tree (BST) constructed from $n$ data points, serving as a normalization factor [8, 9]. The normalization factor is computed as:

$$c(n) = 2H(n-1) - \frac{2(n-1)}{n}$$

where $H(i) = \ln(i) + \gamma$ is the harmonic number approximation and $\gamma \approx 0.5772$ is the Euler-Mascheroni constant [8].

The anomaly score has the following interpretation [8, 9]:
- $s(x, n) \to 1$: the point has a short average path length, indicating high susceptibility to isolation and therefore high anomaly likelihood.
- $s(x, n) \approx 0.5$: the average path length is close to the expected path length for the dataset, indicating no clear anomaly signal.
- $s(x, n) \to 0$: the point has a long average path length, indicating deep embedding within the normal data distribution.

### 2.5.4 Computational Complexity and Practical Advantages

The time complexity of Isolation Forest is $O(t \cdot \psi \cdot \log \psi)$ for training and $O(t \cdot \log \psi)$ for scoring a single data point, where $t$ is the number of trees and $\psi$ is the sub-sampling size [8, 9]. This linear-logarithmic complexity represents a significant advantage over density-based methods (LOF: $O(n^2)$) and kernel-based methods (OCSVM: $O(n^2)$ to $O(n^3)$), making Isolation Forest particularly suitable for real-time applications where scoring latency is a critical constraint [8, 20].

Additional practical advantages include: (i) robustness to the swamping and masking effects that degrade the performance of distance-based and density-based methods when anomalies are numerous or clustered [9]; (ii) absence of distributional assumptions about the data, unlike statistical methods that assume Gaussian or other parametric distributions [8, 17]; (iii) effective handling of high-dimensional feature spaces without suffering from the curse of dimensionality that affects distance-based methods [9, 20]; and (iv) interpretability of the anomaly score, which has a natural probabilistic interpretation as the likelihood of isolation under random partitioning [8].

### 2.5.5 Extended Isolation Forest

Hariri, Kind, and Brunner [16] identified a limitation of the original Isolation Forest algorithm: because axis-parallel splits are used exclusively, the algorithm can produce artifacts in the anomaly score landscape, assigning anomalous scores to normal points that lie along the coordinate axes in regions of feature space dominated by anomalies. The Extended Isolation Forest (EIF) addresses this limitation by replacing axis-parallel splits with hyperplane splits of arbitrary orientation, defined by a random normal vector and an intercept point [16]. While EIF provides more accurate anomaly scores in datasets with complex geometric structures, the original Isolation Forest remains the more widely deployed variant for intrusion detection due to its simplicity, interpretability, and lower computational overhead [16, 20]. This thesis employs the original Isolation Forest algorithm for the primary detection model.

[Figure 2.2: Illustration of Isolation Forest partitioning: anomalous points (short path lengths) versus normal points (long path lengths)]

## 2.6 Local Outlier Factor (LOF)

### 2.6.1 Algorithmic Foundation

Local Outlier Factor (LOF) was proposed by Breunig, Kriegel, Ng, and Sander [10] at the ACM SIGMOD International Conference on Management of Data in 2000. LOF introduced the concept of local density-based anomaly detection, addressing a fundamental limitation of global approaches: a data point may be anomalous relative to its local neighborhood while appearing normal in a global context, or vice versa [10]. By comparing the local density of each data point with the local densities of its $k$-nearest neighbors, LOF produces a degree-of-outlierness score that captures the relative isolation of a point within its local context.

### 2.6.2 Mathematical Formulation

The LOF computation involves several intermediate definitions [10]. Given a dataset $X$ and a positive integer $k$:

**$k$-distance.** The $k$-distance of a point $x$, denoted $d_k(x)$, is the distance between $x$ and its $k$-th nearest neighbor in $X$.

**$k$-distance neighborhood.** The $k$-distance neighborhood of $x$, denoted $N_k(x)$, is the set of all points whose distance from $x$ is at most $d_k(x)$: $N_k(x) = \{y \in X \setminus \{x\} : d(x, y) \leq d_k(x)\}$.

**Reachability distance.** The reachability distance of $x$ with respect to a point $o$ is:

$$\text{reach-dist}_k(x, o) = \max\{d_k(o), d(x, o)\}$$

This definition smooths the density estimation by replacing distances smaller than $d_k(o)$ with $d_k(o)$, reducing the sensitivity of the density estimate to statistical fluctuations among the nearest neighbors [10].

**Local reachability density.** The local reachability density of $x$ is the inverse of the average reachability distance from $x$ to its $k$-nearest neighbors:

$$\text{lrd}_k(x) = \left( \frac{\sum_{o \in N_k(x)} \text{reach-dist}_k(x, o)}{|N_k(x)|} \right)^{-1}$$

**Local Outlier Factor.** The LOF score of $x$ is the average ratio of the local reachability densities of $x$'s neighbors to $x$'s own local reachability density:

$$\text{LOF}_k(x) = \frac{\sum_{o \in N_k(x)} \frac{\text{lrd}_k(o)}{\text{lrd}_k(x)}}{|N_k(x)|}$$

Interpretation: $\text{LOF}_k(x) \approx 1$ indicates that $x$ has a local density similar to its neighbors (normal). $\text{LOF}_k(x) \gg 1$ indicates that $x$ has a significantly lower local density than its neighbors (anomalous). $\text{LOF}_k(x) < 1$ indicates that $x$ is denser than its neighborhood (deeply embedded in a cluster) [10].

### 2.6.3 Strengths and Limitations for SSH Detection

LOF excels at detecting local anomalies---points that are anomalous relative to their immediate neighborhood but not necessarily in a global context [10, 20]. This property is valuable for SSH intrusion detection in environments where different user groups exhibit distinct behavioral patterns (e.g., system administrators versus application developers), as LOF can identify behavior that is anomalous within a specific user group without requiring global normalization [10, 17].

However, LOF has significant practical limitations for real-time SSH monitoring [10, 20, 21]. The computational complexity for computing $k$-nearest neighbors is $O(n^2)$ for brute-force search (or $O(n \log n)$ with spatial indexing structures such as KD-trees, which degrade in high-dimensional spaces). Additionally, LOF requires storing the entire training dataset in memory for neighbor queries during the scoring phase, and the algorithm's performance is sensitive to the choice of $k$, which may require domain-specific tuning [10, 20]. Goldstein and Uchida [20] found that LOF's performance is competitive with Isolation Forest on low-dimensional benchmark datasets but degrades more rapidly as dimensionality increases.

## 2.7 One-Class Support Vector Machine (OCSVM)

### 2.7.1 Algorithmic Foundation

One-Class Support Vector Machine (OCSVM) was proposed by Scholkopf, Platt, Shawe-Taylor, Smola, and Williamson [11] in Neural Computation in 2001. The algorithm extends the traditional two-class SVM framework to the one-class (novelty detection) setting by finding a maximal-margin hyperplane in a kernel-induced feature space that separates the training data from the origin [11]. Data points that fall on the origin side of the hyperplane are classified as anomalous (novel).

### 2.7.2 Optimization Problem

The OCSVM optimization problem is formulated as follows [11]. Given training data $\{x_1, x_2, \ldots, x_n\}$ drawn from the normal class, a kernel function $\Phi$ that maps data into a high-dimensional feature space, and a parameter $\nu \in (0, 1]$ that controls the tradeoff between the margin and the fraction of training points permitted to fall on the anomalous side of the hyperplane:

$$\min_{w, \xi, \rho} \frac{1}{2} \|w\|^2 + \frac{1}{\nu n} \sum_{i=1}^{n} \xi_i - \rho$$

subject to:

$$w \cdot \Phi(x_i) \geq \rho - \xi_i, \quad \xi_i \geq 0, \quad i = 1, \ldots, n$$

where $w$ is the normal vector to the separating hyperplane, $\rho$ is the offset, and $\xi_i$ are slack variables that permit soft-margin violations [11]. The parameter $\nu$ has a dual interpretation: it is an upper bound on the fraction of training points classified as outliers and a lower bound on the fraction of support vectors [11].

The dual formulation, solved via quadratic programming, yields the decision function:

$$f(x) = \text{sgn}\left( \sum_{i=1}^{n} \alpha_i K(x_i, x) - \rho \right)$$

where $\alpha_i$ are the dual variables (Lagrange multipliers) and $K(x_i, x) = \Phi(x_i) \cdot \Phi(x)$ is the kernel function [11]. The most commonly used kernel for anomaly detection is the Radial Basis Function (RBF) kernel:

$$K(x_i, x) = \exp\left( -\gamma \|x_i - x\|^2 \right)$$

where $\gamma > 0$ controls the kernel bandwidth. Points for which $f(x) < 0$ are classified as anomalous [11].

### 2.7.3 Strengths and Limitations for SSH Detection

OCSVM has a rigorous theoretical foundation rooted in statistical learning theory and convex optimization, providing principled generalization guarantees [11, 17]. The $\nu$ parameter offers intuitive control over the expected anomaly proportion, which can be set based on domain knowledge about the expected attack prevalence [11, 20]. Pimentel et al. [17] noted that OCSVM is one of the best-studied novelty detection algorithms, with well-understood theoretical properties.

The primary limitations of OCSVM for real-time SSH detection are computational: the training complexity is $O(n^2)$ to $O(n^3)$ depending on the solver, and the scoring complexity is $O(n_{sv})$ where $n_{sv}$ is the number of support vectors, which can be a substantial fraction of $n$ [11, 20, 21]. Additionally, OCSVM performance is highly sensitive to the choice of kernel function and the hyperparameters $\nu$ and $\gamma$, requiring careful tuning via cross-validation or domain-specific heuristics [11, 20]. Goldstein and Uchida [20] observed that OCSVM achieves competitive detection performance when properly tuned but exhibits higher variance across hyperparameter settings compared to Isolation Forest.

[Table 2.3: Comparative summary of Isolation Forest, LOF, and OCSVM]

| Property | Isolation Forest [8, 9] | LOF [10] | OCSVM [11] |
|----------|------------------------|----------|------------|
| Detection paradigm | Isolation-based | Local density-based | Boundary-based |
| Training complexity | $O(t \cdot \psi \log \psi)$ | $O(n^2)$ | $O(n^2)$--$O(n^3)$ |
| Scoring complexity | $O(t \log \psi)$ | $O(n \cdot k)$ | $O(n_{sv})$ |
| Memory requirement | Model only ($t$ trees) | Full training set | Support vectors |
| Distributional assumptions | None | None | Implicit (via kernel) |
| Key hyperparameters | $t$, $\psi$, contamination | $k$ | $\nu$, $\gamma$, kernel |
| Sensitivity to dimensionality | Low | High | Moderate |
| Score interpretability | High (probability-like) | Moderate (ratio) | Low (signed distance) |
| Real-time suitability | High | Low--Moderate | Moderate |

## 2.8 Feature Selection and Data Preprocessing for Intrusion Detection Systems

The effectiveness of any machine-learning-based intrusion detection system is fundamentally constrained by the quality and informativeness of the features extracted from raw data [7, 12, 15]. Buczak and Guven [12] emphasized that feature engineering---the process of transforming raw log data into meaningful numerical representations---is often the single most impactful component of the machine learning pipeline for cybersecurity applications, outweighing the choice of algorithm in many practical scenarios.

Features for SSH brute-force detection can be categorized into four principal classes [5, 12, 15]:

**Frequency features** capture the volume and rate of authentication activity. Examples include the total number of login attempts, the number of failed attempts, the failure ratio (failed/total), and the number of unique usernames attempted within a time window [5, 15]. Frequency features are effective for detecting high-speed brute-force attacks but provide limited discriminative power against slow-rate attacks that operate below conventional rate thresholds [23].

**Temporal features** capture the timing characteristics of authentication events. Examples include the mean, minimum, and standard deviation of inter-attempt intervals, session duration statistics, and the distribution of attempts across time-of-day bins [5, 18]. Bezerra et al. [18] demonstrated that temporal features provide significant discriminative power for distinguishing automated attacks from human-initiated sessions, because automated tools produce highly regular temporal patterns (near-constant inter-attempt intervals) that differ markedly from the irregular timing of human interactions. Sperotto et al. [15] confirmed this finding in their flow-based SSH analysis, reporting that temporal features contributed more to detection accuracy than frequency features alone.

**Authentication features** capture the credential-level characteristics of login behavior. Examples include the number of unique usernames attempted, the presence of root/admin login attempts, the diversity of attempted passwords (measurable through entropy or unique-count metrics), and the ratio of successful to total attempts [5, 19]. Owens and Matthews [19] found that attack sessions exhibit characteristic username and password distributions (heavily skewed toward common accounts and weak passwords) that differ systematically from legitimate usage patterns.

**Connection features** capture network-level properties of SSH sessions. Examples include the number of concurrent connections, source port entropy, geographic origin diversity, and the use of known malicious network ranges [15, 24]. Ring et al. [24] surveyed datasets for network-based intrusion detection and identified connection-level features as particularly valuable for detecting distributed attacks where individual-IP behavioral features may appear benign.

This thesis extracts 14 features per source IP address per 5-minute sliding window, spanning all four feature categories. The feature set was designed to balance comprehensiveness (capturing sufficient behavioral information to discriminate among all five attack variants) with computational efficiency (maintaining the real-time processing requirement). Feature selection was informed by the literature reviewed above and refined through empirical feature importance analysis, which identified session_duration_mean (5.50% importance), min_inter_attempt_time (3.86%), and mean_inter_attempt_time (2.61%) as the top three discriminative features---confirming the primacy of temporal features reported by Bezerra et al. [18] and Sperotto et al. [15].

Data preprocessing for anomaly detection requires particular attention to feature scaling, missing value handling, and the treatment of categorical variables [7, 12]. Pimentel et al. [17] noted that distance-based and kernel-based methods (LOF, OCSVM) are highly sensitive to feature scale, necessitating standardization (zero mean, unit variance) or min-max normalization. Isolation Forest is theoretically scale-invariant (because splits are defined on individual features), but empirical evidence suggests that standardization can improve performance when features have vastly different ranges [9, 20].

[Figure 2.3: Feature extraction pipeline from SSH authentication logs to 14-dimensional feature vectors]

## 2.9 Dynamic Threshold Mechanisms for Anomaly Detection

### 2.9.1 The Static Threshold Problem

In anomaly detection systems, the threshold determines the boundary between normal and anomalous classifications: data points with anomaly scores exceeding the threshold are flagged as attacks, while those below are treated as normal [7, 13]. Static thresholds---fixed values determined during training and applied unchanged during operation---are simple to implement but fundamentally inappropriate for data streams with non-stationary characteristics [7, 13, 14]. In the SSH monitoring context, authentication traffic exhibits pronounced temporal variability: business hours generate more legitimate logins than off-hours, weekdays differ from weekends, and events such as system maintenance or application deployments create legitimate but unusual traffic spikes [5, 15]. A static threshold calibrated for average conditions will generate excessive false positives during high-activity periods and miss subtle attacks during low-activity periods [7, 14].

### 2.9.2 Exponentially Weighted Moving Average (EWMA)

The Exponentially Weighted Moving Average is a time series smoothing method that assigns exponentially decreasing weights to older observations, enabling adaptive tracking of the current process level [13]. Originally introduced by Roberts (1959) for statistical quality control and comprehensively analyzed by Lucas and Saccucci [13], EWMA has been widely adopted in process monitoring, financial time series analysis, and network anomaly detection [13, 14].

The EWMA statistic at time $t$ is defined as:

$$\hat{\mu}_t = \alpha \cdot x_t + (1 - \alpha) \cdot \hat{\mu}_{t-1}$$

where $x_t$ is the observed value (anomaly score) at time $t$, $\hat{\mu}_t$ is the smoothed estimate at time $t$, $\hat{\mu}_0$ is initialized to the mean of the training anomaly scores, and $\alpha \in (0, 1]$ is the smoothing parameter that controls the tradeoff between responsiveness to recent observations and stability against noise [13].

The variance of the EWMA statistic is:

$$\text{Var}(\hat{\mu}_t) = \sigma^2 \cdot \frac{\alpha}{2 - \alpha} \cdot \left[1 - (1 - \alpha)^{2t}\right]$$

which converges to $\sigma^2 \cdot \frac{\alpha}{2 - \alpha}$ as $t \to \infty$ [13]. Control limits (thresholds) are typically set at $\hat{\mu}_t \pm L \cdot \sqrt{\text{Var}(\hat{\mu}_t)}$, where $L$ is a multiplier (commonly 2.5--3.0) determined by the desired false alarm rate [13, 14].

Lucas and Saccucci [13] demonstrated that EWMA control charts are particularly effective at detecting small, persistent shifts in the process mean---precisely the type of signal generated by slow brute-force attacks that produce a gradual, sustained elevation in anomaly scores. Montgomery [14] provides a comprehensive treatment of EWMA in the broader context of statistical quality control and discusses the selection of $\alpha$ and $L$ for different detection objectives.

### 2.9.3 Adaptive Percentile Method

The Adaptive Percentile method determines the threshold based on the empirical quantile of the anomaly score distribution within a sliding time window [14, 17]. The threshold at time $t$ is defined as:

$$\theta_t = P_q(S_W)$$

where $P_q$ denotes the $q$-th percentile and $S_W = \{s_{t-W+1}, s_{t-W+2}, \ldots, s_t\}$ is the set of the most recent $W$ anomaly scores [14]. This approach has two key advantages: it requires no distributional assumptions about the anomaly scores (unlike EWMA, which implicitly assumes approximate normality for the control limit calculation), and it naturally adapts to changes in the score distribution by continuously updating the reference window [17]. The primary disadvantage is sensitivity to the window size $W$: too small a window results in volatile thresholds, while too large a window reduces responsiveness to genuine distributional shifts [14].

### 2.9.4 Hybrid EWMA-Adaptive Percentile Method

This thesis proposes a hybrid dynamic thresholding mechanism that combines EWMA and Adaptive Percentile to leverage the complementary strengths of both approaches [13, 14]. EWMA provides long-term trend tracking and smoothing, preventing the threshold from oscillating in response to transient score fluctuations. Adaptive Percentile provides distribution-free adaptiveness, accurately reflecting the empirical score distribution without parametric assumptions. The hybrid threshold is computed as a weighted combination:

$$\theta_t^{\text{hybrid}} = w_{\text{EWMA}} \cdot \theta_t^{\text{EWMA}} + w_{\text{AP}} \cdot \theta_t^{\text{AP}}$$

where $\theta_t^{\text{EWMA}}$ is the EWMA-based threshold, $\theta_t^{\text{AP}}$ is the Adaptive Percentile threshold, and $w_{\text{EWMA}} + w_{\text{AP}} = 1$ are the blending weights [13, 14]. The specific weight values and the calibration procedure are detailed in Chapter 3 (Methodology). The hybrid approach ensures that the system maintains stable baseline tracking (from EWMA) while remaining responsive to local distributional changes (from Adaptive Percentile), a combination that is particularly valuable for detecting the gradual anomaly score elevation characteristic of slow brute-force campaigns [13, 23].

[Figure 2.4: Comparison of static, EWMA, Adaptive Percentile, and hybrid thresholds on a simulated anomaly score time series with embedded attack periods]

## 2.10 Related Work in SSH Brute-Force Detection

This section presents a systematic review of the most relevant prior studies in SSH brute-force detection, organized by methodological approach. The review encompasses both international and domestic (Vietnamese) research and identifies the specific contributions and limitations of each study relative to the objectives of this thesis.

### 2.10.1 Flow-Based and Network-Layer Approaches

Sperotto et al. [15] conducted pioneering work on flow-based intrusion detection for SSH, analyzing network flow records from the University of Twente (Netherlands) to characterize SSH attack patterns. The study identified that flow-level features---including flow duration, packet count, and byte count---provide sufficient information to distinguish between legitimate SSH sessions and brute-force attacks with greater than 90% accuracy using Hidden Markov Models. The primary contribution was the demonstration that application-layer payload inspection is unnecessary for SSH attack detection; metadata features alone are sufficient [15]. However, the study employed supervised classification requiring labeled data, and the flow-based feature set does not capture application-layer behavioral nuances such as username diversity or password retry patterns that are available from authentication logs [15, 24].

Hellemons et al. [5] developed SSHCure, a three-phase detection system that models SSH attacks as a sequence of scanning, brute-force, and compromise phases, each characterized by distinct flow-level features. SSHCure achieved high detection rates (>95% true positive rate) for attacks that follow the canonical three-phase pattern [5]. The key limitation is the assumption of sequential phase progression, which does not hold for all attack variants---particularly credential-stuffing attacks that skip the scanning phase and slow brute-force attacks that blur the boundary between phases [5, 23].

### 2.10.2 Machine Learning Approaches on Benchmark Datasets

Ahmad et al. [25] conducted a systematic study of network-based intrusion detection systems (NIDS), comparing multiple machine learning algorithms including Isolation Forest, LOF, OCSVM, Random Forest, and deep learning approaches across the NSL-KDD, CICIDS2017, and UNSW-NB15 benchmark datasets. The study found that Isolation Forest achieved the best balance between detection performance and computational efficiency among unsupervised methods, with F1-scores ranging from 82% to 91% depending on the dataset [25]. However, the study evaluated algorithms on general network intrusion data rather than SSH-specific data, and the benchmark datasets---while valuable for standardized comparison---are known to suffer from age-related limitations, as documented by Ring et al. [24].

Ring et al. [24] provided a comprehensive survey of datasets for network-based intrusion detection systems, evaluating 34 datasets across criteria including realism, labeling accuracy, attack diversity, and temporal currency. The survey concluded that many widely used benchmark datasets (including NSL-KDD, first released in 1999) do not adequately represent modern attack characteristics, and recommended the use of application-specific datasets collected from controlled environments or honeypots for domain-focused research [24]. This recommendation directly motivates the use of honeypot-collected data in this thesis.

Goldstein and Uchida [20] performed a comparative evaluation of unsupervised anomaly detection algorithms on 10 benchmark datasets, including network intrusion data. Their results showed that Isolation Forest ranked among the top three algorithms in average performance across all datasets, with LOF and OCSVM achieving competitive performance on specific datasets but exhibiting higher variance across datasets [20]. The study confirmed that algorithm selection should be guided by domain-specific evaluation rather than reliance on a single benchmark.

### 2.10.3 SSH-Specific Machine Learning Studies

Javed and Paxson [23] studied stealthy SSH brute-forcing campaigns using data from a large academic network, identifying attacks that operate at rates as low as 1--2 attempts per hour and unfold over periods of days to weeks. The study demonstrated that these stealthy campaigns can achieve compromise rates comparable to aggressive attacks while evading all conventional detection mechanisms [23]. The key insight---that temporal behavioral features are essential for detecting low-rate attacks---directly informs the feature engineering approach of this thesis, which prioritizes temporal features (inter-attempt timing, session duration) alongside traditional frequency features.

Bezerra et al. [18] analyzed SSH attack durations using data from a distributed honeypot network and found significant heterogeneity in attack temporal profiles: attack sessions ranged from sub-second scans to multi-day campaigns, with distinct temporal signatures associated with different attack tools and botnets. The study identified inter-attempt timing regularity as a highly discriminative feature for distinguishing automated attacks from human-initiated sessions [18].

Owens and Matthews [19] conducted an early but influential analysis of SSH brute-force password characteristics using honeypot data. The study documented that the top 20 most-attempted passwords account for over 40% of all attack attempts, and that attackers exhibit strong preferences for specific username-password combinations (e.g., root/root, admin/123456) [19]. These findings inform the authentication-category features in this thesis's 14-feature set, particularly the unique username count and password diversity metrics.

Park et al. [22] investigated SSH attacks targeting network infrastructure devices (routers and switches), documenting that these attacks exhibit distinct behavioral patterns compared to attacks against general-purpose servers, including different username preferences and timing profiles [22]. While this thesis focuses on server-targeted attacks, the existence of device-specific attack patterns underscores the importance of adaptive, learning-based detection approaches that can accommodate behavioral diversity without requiring explicit rules for each target type.

### 2.10.4 Deep Learning and Advanced Approaches

Nassif et al. [21] surveyed machine learning and deep learning approaches for anomaly-based intrusion detection, finding that deep learning methods (autoencoders, LSTMs, GANs) can achieve higher detection accuracy than traditional machine learning methods on large, high-dimensional datasets. However, the survey also noted that deep learning methods require significantly more training data, computational resources, and hyperparameter tuning, and that their black-box nature complicates interpretation and debugging in security-critical applications [21]. For real-time SSH monitoring on resource-constrained environments, traditional machine learning methods such as Isolation Forest offer a more practical balance of performance and efficiency [21, 25].

Buczak and Guven [12] provided the foundational survey of data mining and machine learning methods for cybersecurity intrusion detection, cataloging over 50 studies spanning supervised, unsupervised, and hybrid approaches. The survey identified several persistent challenges in the field: the reliance on outdated benchmark datasets, the absence of standardized evaluation methodologies, the difficulty of comparing results across studies that use different datasets and metrics, and the gap between algorithmic research and operational deployment [12]. These challenges motivate the methodological choices of this thesis, including the use of real honeypot data, the standardized evaluation framework (accuracy, precision, recall, F1, FPR), and the emphasis on end-to-end system integration.

Pimentel et al. [17] reviewed novelty detection methods---a formulation closely related to semi-supervised anomaly detection---across multiple application domains including intrusion detection. The review categorized methods into probabilistic, distance-based, reconstruction-based, domain-based, and information-theoretic approaches, and identified one-class classification (including OCSVM) and isolation-based methods (including Isolation Forest) as particularly well-suited for applications where the target class (normal behavior) is well-sampled but the outlier class (attacks) is poorly characterized or entirely absent from training data [17].

Hariri et al. [16] proposed the Extended Isolation Forest (EIF), which addresses the axis-parallel bias of the original algorithm by using random hyperplane splits. EIF demonstrated improved anomaly detection accuracy on synthetic datasets with complex geometric structures. However, for the tabular feature data characteristic of SSH log analysis, the performance difference between IF and EIF is marginal, and the original IF's lower computational cost and simpler implementation make it the preferred choice for real-time applications [16, 20].

[Table 2.4: Comprehensive comparison of related works in SSH brute-force detection]

| Study | Year | Method | Data Source | Key Metric | Dynamic Threshold | Early Warning | System Integration |
|-------|------|--------|-------------|------------|------------------|---------------|-------------------|
| Hellemons et al. [5] | 2012 | SSHCure (three-phase) | Flow data | TPR > 95% | No | Partial | No |
| Sperotto et al. [15] | 2010 | HMM (flow-based) | Univ. Twente flows | Acc > 90% | No | No | No |
| Javed & Paxson [23] | 2013 | Statistical analysis | Academic network | -- | No | Yes (analysis) | No |
| Owens & Matthews [19] | 2008 | Password analysis | Honeypot | -- | No | No | No |
| Bezerra et al. [18] | 2019 | Temporal analysis | Distributed honeypot | -- | No | No | No |
| Goldstein & Uchida [20] | 2016 | IF, LOF, OCSVM (comparison) | 10 benchmarks | AUC varies | No | No | No |
| Nassif et al. [21] | 2021 | ML/DL survey | Multiple | Survey | No | No | No |
| Park et al. [22] | 2020 | SSH on routers | Router logs | -- | No | No | No |
| Ahmad et al. [25] | 2021 | Multiple ML | NSL-KDD, CICIDS | F1 82--91% | No | No | No |
| Ring et al. [24] | 2019 | Dataset survey | 34 datasets | Survey | N/A | N/A | N/A |
| Hariri et al. [16] | 2019 | Extended IF | Synthetic + real | AUC improved | No | No | No |
| **This thesis** | **2026** | **IF + EWMA-AP** | **Honeypot + Sim (174K lines)** | **F1 = 93.74%** | **Yes (hybrid)** | **Yes** | **Yes (9 Docker services)** |

## 2.11 Summary of the Literature Review

The comprehensive review of the literature reveals a rich but fragmented research landscape characterized by significant methodological advances in individual components---anomaly detection algorithms, feature engineering, threshold mechanisms---but a persistent absence of integrated solutions that combine these components into deployable systems [7, 12, 15].

**On algorithms:** Isolation Forest [8, 9] has emerged as one of the most effective unsupervised anomaly detection algorithms for network security applications, offering a compelling combination of detection performance, computational efficiency, and interpretability [20, 21]. LOF [10] provides complementary local-density-based detection but is limited by computational complexity and memory requirements. OCSVM [11] offers strong theoretical foundations but requires careful hyperparameter tuning and has higher computational costs. All three algorithms have been validated on benchmark datasets, but their comparative evaluation on real-world SSH honeypot data in a semi-supervised configuration remains underexplored [20, 24, 25].

**On features:** The literature consistently identifies temporal features (inter-attempt timing, session duration) as more discriminative than frequency features (attempt counts) for distinguishing automated SSH attacks from legitimate activity, particularly for slow-rate and stealthy attack variants [5, 15, 18, 23]. Authentication features (username diversity, password patterns) provide additional discriminative power for credential-stuffing and dictionary attacks [19]. The integration of features from all four categories (frequency, temporal, authentication, connection) in a unified feature set has been recommended but rarely implemented and evaluated systematically [12, 15].

**On thresholds:** Static thresholds are inadequate for SSH monitoring due to the non-stationary nature of authentication traffic [6, 7, 13]. EWMA-based adaptive thresholds offer superior sensitivity to small, persistent shifts [13, 14], while percentile-based methods provide distribution-free adaptiveness [14, 17]. Hybrid approaches combining multiple threshold methods have been proposed in the statistical process control literature [13, 14] but have not been applied to SSH anomaly detection.

**On integration:** The gap between algorithmic research and deployable systems remains one of the most significant barriers to the practical adoption of machine learning in cybersecurity [12, 15]. The vast majority of studies evaluate algorithms in isolation on benchmark datasets without addressing log ingestion, real-time feature extraction, automated response, visualization, or containerized deployment [20, 21, 24, 25].

## 2.12 Research Gap and Contribution

Based on the literature review, four specific research gaps are identified that collectively define the novel contribution of this thesis:

**Gap 1: Absence of comparative algorithm evaluation on real SSH honeypot data.** While Isolation Forest, LOF, and OCSVM have been extensively compared on benchmark datasets [20, 25], their comparative performance on authentic SSH honeypot data---with its characteristic noise, class imbalance (679 attacking IPs versus 64 normal users), and behavioral diversity (five attack variants)---has not been systematically evaluated in a semi-supervised configuration [24]. **Contribution:** This thesis provides a rigorous comparative evaluation of all three algorithms on 174,250 lines of combined honeypot and simulated data, reporting standardized metrics (accuracy, precision, recall, F1, FPR) with optimized results: IF (Acc = 90.31%, F1 = 93.74%, FPR = 29.00%), LOF (Acc = 83.22%, F1 = 89.94%), OCSVM (Acc = 91.38%, F1 = 94.55%).

**Gap 2: No hybrid dynamic thresholding for SSH anomaly detection.** EWMA [13] and percentile-based thresholds [14] have been studied independently, but their combination into a hybrid mechanism specifically designed for SSH anomaly detection has not been previously proposed or evaluated [7, 12]. Existing SSH detection systems rely on either static thresholds [6] or simple adaptive mechanisms without the complementary strengths of trend-following and distribution-free approaches [5, 15]. **Contribution:** This thesis proposes and validates the EWMA-Adaptive Percentile hybrid thresholding mechanism, demonstrating its effectiveness across five attack scenarios with varying temporal profiles [13, 14].

**Gap 3: Limited exploitation of early-warning capability.** While some studies have identified the potential for early detection based on behavioral features [5, 23], the systematic exploitation of early-phase behavioral signatures for proactive attack warning---particularly for slow-rate attacks---remains largely unexplored [18, 23]. **Contribution:** This thesis demonstrates early-warning capability across all five attack scenarios, with the system issuing EARLY_WARNING alerts after only 3--5 attempts in the slow brute-force scenario, compared to complete detection failure by Fail2Ban under default settings.

**Gap 4: Research-to-deployment gap.** The overwhelming majority of studies in this domain evaluate algorithms in isolation without addressing system integration [12, 20, 21, 25]. **Contribution:** This thesis implements a complete end-to-end system comprising 9 Docker services (ELK Stack, FastAPI, React, Fail2Ban), with a 14-feature extraction pipeline processing SSH logs in 5-minute sliding windows, demonstrating that the transition from algorithm to deployable system is achievable within a modern containerized architecture [6, 15].

[Figure 2.5: Visual mapping of research gaps to the contributions of this thesis]

[Table 2.5: Summary of research gaps, their evidence in the literature, and corresponding contributions]

| Gap | Evidence in Literature | This Thesis's Contribution |
|-----|----------------------|---------------------------|
| No comparative evaluation on real SSH data | Goldstein & Uchida [20] used benchmarks; Ahmad et al. [25] used general IDS datasets | IF, LOF, OCSVM compared on 174,250-line honeypot + simulation dataset |
| No hybrid dynamic threshold for SSH | Fail2Ban [6] uses static; SSHCure [5] uses fixed phases | EWMA-Adaptive Percentile hybrid mechanism |
| Limited early-warning exploitation | Javed & Paxson [23] identified potential; no system implemented | Early warning in 3--5 attempts for slow attacks |
| Research-to-deployment gap | Buczak & Guven [12] and Sperotto et al. [15] identified the gap | 9-service Docker architecture with automated response |
