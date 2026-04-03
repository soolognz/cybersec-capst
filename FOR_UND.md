# FOR_UND: Understanding This Project Inside Out

*A deep breakdown of building an AI-powered SSH brute-force detection system — explained like a sharp friend over coffee, not a textbook.*

---

## Step 1: What approach did we take, and why?

### The Starting Point

Imagine you're a security guard at a building. Right now, your rule is: "If someone fails to badge in 5 times in 10 minutes, lock them out." That's Fail2Ban. Simple, but dumb — a smart thief just tries once every 11 minutes and never gets caught.

Our project asks: **Can we make the guard smarter?** Instead of counting failures, can we teach the guard to *recognize suspicious behavior patterns* and raise the alarm *before* the thief even gets close to succeeding?

### The Core Reasoning Chain

**Decision 1: Anomaly detection, not classification.**  
We chose *unsupervised anomaly detection* (learn what "normal" looks like, flag anything weird) over *supervised classification* (learn from labeled attack examples). Why? Because attackers constantly invent new techniques. A supervised model only catches attacks it's seen before. An anomaly model catches anything that *doesn't look normal* — including attacks that haven't been invented yet. This is a fundamental architectural decision that shaped everything.

**Decision 2: Isolation Forest as the main model.**  
Among anomaly detection algorithms, we picked Isolation Forest (IF) over LOF and One-Class SVM. The key reason isn't accuracy (OCSVM actually scored slightly higher) — it's that IF produces *continuous anomaly scores* with a smooth distribution. This matters enormously for the dynamic threshold, which needs a stream of scores to compute EWMA. LOF scores are "spiky" and OCSVM scores cluster around the decision boundary. IF scores flow like a river, which is exactly what EWMA needs.

Think of it like choosing a thermometer: you want one that gives you a smooth temperature reading (IF), not one that just says "hot or cold" (binary classifier) or one that jumps around erratically (LOF).

**Decision 3: Time-window features, not session-based.**  
Instead of analyzing individual SSH sessions ("this one login attempt was suspicious"), we analyze *windows of behavior per IP* ("what has this IP been doing in the last 5 minutes?"). Why? Because a single failed login is normal — everyone fat-fingers their password sometimes. But 50 failed logins from the same IP in 5 minutes? That's a pattern. Brute-force is about *patterns over time*, not individual events.

**Decision 4: EWMA + Adaptive Percentile for the dynamic threshold.**  
This is the innovation claim of the thesis. Standard thresholds are static lines. Our threshold is alive — it moves. EWMA smooths out noise while staying responsive to trends. Adaptive Percentile adjusts the alarm level based on what "recent normal" looks like. Together, they catch slow attacks that fly under static radar.

Analogy: Imagine your car's speedometer. Static threshold = a sign saying "speed limit 60." EWMA threshold = a sign that says "you're driving 15% faster than the average speed of the last 100 cars." The second one catches the guy doing 80 in a 60 zone, even if he slowed down for a moment.

---

## Step 2: What approaches did we consider but reject?

### Rejected: Deep Learning (LSTM/Transformer)

Why considered: LSTMs are great at sequential pattern recognition. SSH logs are sequential. Seems perfect.

Why rejected: Three reasons. (1) We have limited training data (~7,000 normal samples). Deep learning needs 10x-100x that to avoid overfitting. (2) Interpretability — when the thesis committee asks "why did it flag this IP?", we can point to specific feature values with IF. With an LSTM, it's a black box. (3) Training time and complexity don't fit a 4-month capstone timeline.

**Lesson:** The best algorithm isn't always the fanciest. Match the method to the data size and the use case.

### Rejected: Supervised Random Forest / XGBoost

Why considered: These often top leaderboards. Many papers use them for intrusion detection.

Why rejected: They need *labeled attack data for training*. Our training approach is semi-supervised — train on normal only. This is deliberate: we want to catch attacks we've never seen, not just replay known patterns. Supervised models are glorified pattern-matchers; we needed an anomaly *discoverer*.

### Rejected: Per-Session Features Instead of Per-Window

Why considered: Each SSH connection has a clear lifecycle (connect → auth → success/fail → disconnect). Feature per session seems natural.

Why rejected: Sessions from attackers are interleaved with sessions from normal users. The attack pattern emerges from the *aggregate* behavior of one IP across many sessions, not from any single session. Also, "message repeated N times" entries in syslog compress multiple events, making session reconstruction unreliable.

### Rejected: StandardScaler for Preprocessing

Why considered: It's the default. Everyone uses it.

Why rejected: StandardScaler uses mean and standard deviation, which are sensitive to outliers. Our training data (normal behavior) might have occasional weird spikes (a user typing their password wrong 5 times on a bad day). RobustScaler uses median and IQR — it shrugs off outliers. Small choice, big impact on model stability.

---

## Step 3: How do the parts connect?

Here's the architecture as a story:

```
[Chapter 1: The Mailroom]
SSH logs arrive → Log Parser reads them line by line
                  Extracts: who, when, from where, what happened

[Chapter 2: The Sorting Office]  
Labeler tags each entry: "this is normal" or "this is attack"
Feature Extractor groups entries by IP + 5-min window
Computes 14 numbers describing behavior in that window

[Chapter 3: The Training Academy]
Data Splitter separates training (normal only) from testing
Preprocessor scales all features to comparable ranges
Three models (IF, LOF, OCSVM) learn what "normal" looks like

[Chapter 4: The Watchtower]
Real-time pipeline tails the log file continuously
For each active IP, extracts features from its current window
IF scores how "abnormal" this behavior is (0 to 1)
Dynamic threshold decides: NORMAL, EARLY_WARNING, or ALERT

[Chapter 5: The Response Team]
EARLY_WARNING → log it, add to watchlist, push to dashboard
ALERT → send email, push WebSocket notification, Fail2Ban bans IP
Dashboard shows everything in real-time via React + Kibana
```

**The critical flow**: Raw log line → parsed event → feature vector → anomaly score → threshold decision → action. Every component exists to serve this chain. Remove any link and the chain breaks.

---

## Step 4: What tools, and why those specifically?

| Tool | Why This | Why Not the Alternative |
|------|----------|----------------------|
| **Python + scikit-learn** | Mature ML library, IF/LOF/OCSVM all built-in, huge ecosystem | PyTorch/TensorFlow overkill for classical ML |
| **FastAPI** (not Flask) | Native async + WebSocket support, critical for real-time push | Flask needs extensions for async, no native WebSocket |
| **React + TypeScript** | Type safety, component reuse, strong ecosystem | Vue/Svelte smaller ecosystem, less hiring pool |
| **ELK Stack** | Industry standard SIEM, Kibana's geo-maps are impressive for demo | Grafana lacks log aggregation, Splunk is expensive |
| **Redis** (not Kafka) | Lightweight message passing, project scale doesn't need Kafka | Kafka adds operational complexity for minimal benefit |
| **Docker Compose** | Single-command deployment, reproducibility | Kubernetes overkill for demo; bare metal unreproducible |
| **RobustScaler** (not StandardScaler) | Resistant to outliers in training data | StandardScaler distorted by occasional normal-user spikes |
| **pandoc + XeLaTeX** | Unicode Vietnamese support, PDF quality | pdfLaTeX can't handle Vietnamese; Word loses formatting |

---

## Step 5: What tradeoffs did we make?

### Tradeoff 1: Recall vs. False Positive Rate
We optimized for **high Recall** (catch nearly all attacks, even at cost of some false alarms). Why? In security, missing an attack (false negative) is catastrophic — data breach, ransomware, total compromise. A false alarm (false positive) just means investigating a non-issue. The cost asymmetry is 1000:1.

Result: Recall 96.75%, but FPR 29%. Acceptable for security; would be unacceptable for, say, spam filtering.

### Tradeoff 2: Model Simplicity vs. Peak Accuracy
OCSVM scored F1=94.55% vs IF's 93.74%. We chose IF anyway because:
- IF trains in O(n log n), OCSVM in O(n²). For real-time retraining, this matters.
- IF scores are smoother for EWMA. Better integration > marginally better accuracy.
- We can explain IF to the thesis committee in 2 minutes. OCSVM kernel trick takes 10.

### Tradeoff 3: 14 Features (Original) vs 23 Features (Optimized)
The optimized pipeline adds 9 derived features (log transforms, ratios). More features = better accuracy, but also = more complexity, more chance of overfitting, harder to explain. We kept both pipelines: the 14-feature one for the thesis (clean, explainable), the 23-feature one for actual production use.

### Tradeoff 4: Non-Overlapping vs Overlapping Windows
Original: 5-min window, 1-min stride = overlapping. Catches transitions better but creates correlated training samples.
Optimized: 5-min window, 5-min stride = non-overlapping. Less correlated samples = better model generalization.

We went with non-overlapping for training (better model), overlapping for real-time detection (smoother monitoring). Different stride for different purposes.

---

## Step 6: Mistakes, dead ends, and wrong turns

### Mistake 1: Initial FPR of 77%
The first run gave IF a false positive rate of 77%. That means 3 out of 4 normal samples were flagged as attacks. Useless.

**Root cause**: Overlapping windows created highly correlated training samples. The model learned a very narrow definition of "normal" that didn't generalize.

**Fix**: Switch to non-overlapping windows for training. FPR dropped from 77% to 29%.

**Lesson**: Data engineering matters more than model selection. The same algorithm went from useless to great just by changing how we window the data.

### Mistake 2: Dynamic Threshold Flagging Everything
The first dynamic threshold implementation flagged 15,175 out of 15,184 test samples as EARLY_WARNING. Basically, everything was suspicious.

**Root cause**: When all scores in the buffer are identical (common with identical normal behavior), the 95th percentile equals the EWMA, which equals every score. So the early warning threshold (95th percentile / 1.5) is lower than every score.

**Fix**: Added variance to scores via proper feature engineering. With diverse features, scores naturally vary, and the percentile becomes meaningful.

### Mistake 3: LaTeX Table Compilation Errors
The markdown-to-LaTeX converter produced lonely `\item` commands and malformed tables.

**Root cause**: Naive regex-based conversion doesn't handle context (items need `\begin{itemize}`, tables need proper row termination).

**Fix**: Used pandoc instead of custom converter. Pandoc has 15+ years of edge-case handling built in.

**Lesson**: Don't reinvent wheels. If a mature tool exists (pandoc), use it.

### Mistake 4: LOF Formula Typo in Thesis
Chapter 2 had an extra `}` in the LOF formula that broke LaTeX compilation.

**Lesson**: Always compile-test your thesis incrementally, not all at once at the end.

---

## Step 7: Pitfalls to watch out for

1. **"Works on my dataset" syndrome.** Our model performs well on this specific honeypot + simulation data. It may not generalize to other environments without retraining. Always retrain on local data before deploying.

2. **Concept drift is real.** Attack patterns evolve. A model trained today may be obsolete in 6 months. Build retraining into your operational plan.

3. **Docker ≠ Production-ready.** Our Docker setup works for demo. For actual production: add health checks, resource limits, log rotation, backup strategy, monitoring for the monitoring system itself.

4. **Feature engineering is 80% of the work.** We spent more time on the 14 features than on all three models combined. The features determine the ceiling; the model just tries to reach it.

5. **Your thesis committee cares about WHY, not WHAT.** They can read your code. What they want to know is: Why Isolation Forest and not Random Forest? Why 5-minute windows and not 10? Why EWMA alpha=0.3? Have answers ready.

6. **Test with the slow attack scenario first.** That's your differentiator. If your system catches the slow attack but Fail2Ban doesn't, you've proven your thesis. If it doesn't catch it, nothing else matters.

7. **False positives in security are okay; false negatives are not.** When someone asks "why is FPR 29%?", respond: "Because we chose to never miss an attack. Would you prefer 5% FPR with 80% Recall, missing 1 in 5 attacks?"

---

## Step 8: What would an expert notice?

### What experts see that beginners miss:

1. **The train/test data distribution mismatch.** Training data (simulation) and test data normal samples (simulation + honeypot admin logins) come from different environments (different hostnames, different user patterns). An expert would ask: "How much of your FPR comes from domain shift vs. actual model weakness?" This is a valid concern.

2. **The anomaly score inversion.** scikit-learn's IF returns *lower* scores for anomalies. We invert them (-score) for EWMA. An expert would verify this inversion is consistent everywhere — one missed negation sign and your entire threshold logic flips.

3. **The contamination parameter.** Setting contamination=0.01 in the optimized model tells IF "expect 1% of training data to be anomalous." But our training data is supposed to be 100% normal. An expert would question whether this creates a subtle bias. (Answer: it does, but it's a useful bias — it makes the model slightly more conservative, reducing FPR.)

4. **Window boundary effects.** If an attack starts at minute 4 of one window and ends at minute 2 of the next, both windows see only partial attack signal. An expert would suggest overlapping windows for detection (which we do) while using non-overlapping for training (which we also do).

5. **The feature importance result.** Timing features dominate (session_duration_mean, min_inter_attempt_time). An expert would note: this means our model primarily detects automation speed, not authentication patterns. A human-speed attacker using compromised credentials might evade it. This is a real limitation.

---

## Step 9: Transferable lessons

### Lesson 1: "Start with the data, not the model"
We spent the first 3 phases on data processing before touching any ML. This pattern applies everywhere — in web development (understand the requirements before coding), in writing (outline before drafting), in cooking (mise en place before turning on the stove).

### Lesson 2: "The best model is the one that fits the system, not the benchmark"
OCSVM had better F1, but IF was the right choice for the dynamic threshold integration. In real engineering, the best component is the one that plays well with others. A Formula 1 engine doesn't make a good family car.

### Lesson 3: "Two-level alerts reduce decision fatigue"
EARLY_WARNING (watch this) vs ALERT (act now) is a pattern used in weather forecasting, medical monitoring, and DevOps. It gives humans time to prepare without forcing immediate action on uncertain signals.

### Lesson 4: "Containerize from day one"
Our Docker setup took much less time because we designed with containers in mind from the start. Retrofitting Docker onto an existing system is always painful. This applies to any infrastructure: think about deployment before you write the first line.

### Lesson 5: "Make it work, make it right, make it fast"
Our pipeline: v1 (overlapping windows, basic params) → v2 (non-overlapping, derived features, tuned contamination). We didn't try to optimize everything on the first pass. Get a working baseline, measure it, then improve systematically. This is the scientific method applied to engineering.

### Lesson 6: "Documentation is a product, not an afterthought"
We generated 5 types of documentation (setup guide, demo runbook, API reference, architecture diagram, feature dictionary) not because they were required, but because they make the system *usable*. Code without documentation is a puzzle; code with documentation is a tool.

---

*Written for understanding, not for show. May you build something even better next time.*
