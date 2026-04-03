# System Architecture / Kiến trúc hệ thống

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SSH Target Server                         │
│              /var/log/auth.log (syslog)                      │
└──────────────┬──────────────────────────┬───────────────────┘
               │                          │
          [Filebeat]                 [Log Tailer]
               │                     (Python asyncio)
               ▼                          │
┌──────────────────────┐    ┌─────────────┴──────────────┐
│      Logstash        │    │    Detection Worker         │
│  ┌────────────────┐  │    │  ┌───────────────────────┐  │
│  │ Grok Parser    │  │    │  │ SSHLogParser          │  │
│  │ GeoIP Enrich   │  │    │  │ IPWindowManager       │  │
│  │ Timestamp      │  │    │  │ FeatureExtractor(14)  │  │
│  └────────────────┘  │    │  │ Preprocessor(Scaler)  │  │
└──────────┬───────────┘    │  │ IsolationForest       │  │
           │                │  │ DynamicThreshold      │  │
           ▼                │  │ (EWMA+Percentile)     │  │
┌──────────────────────┐    │  └───────────┬───────────┘  │
│   Elasticsearch      │    └──────────────┼──────────────┘
│  ┌────────────────┐  │                   │
│  │ ssh-auth-logs  │  │                   ▼
│  │ index          │  │    ┌──────────────────────────┐
│  └────────────────┘  │    │      Redis Stream         │
└──────────┬───────────┘    │  (anomaly scores, alerts) │
           │                └──────────────┬───────────┘
           ▼                               │
┌──────────────────────┐                   ▼
│      Kibana          │    ┌──────────────────────────┐
│  ┌────────────────┐  │    │    FastAPI Backend        │
│  │ SSH Dashboard  │  │    │  ┌───────────────────┐   │
│  │ - Attack Map   │  │    │  │ REST API          │   │
│  │ - Timeseries   │  │    │  │ WebSocket Server  │───┼──┐
│  │ - Top IPs      │  │    │  │ Alert Manager ────┼───┼──┼─► Email (SMTP)
│  └────────────────┘  │    │  │ Prevention Ctrl ──┼───┼──┼─► Fail2Ban
└──────────────────────┘    │  └───────────────────┘   │  │
                            └──────────────┬───────────┘  │
                                           │              │
                                           ▼              │
                            ┌──────────────────────────┐  │
                            │   React Dashboard        │◄─┘
                            │  ┌───────────────────┐   │ (WebSocket)
                            │  │ Dashboard Page    │   │
                            │  │ Alerts Page       │   │
                            │  │ Model Comparison  │   │
                            │  │ Kibana Embed      │   │
                            │  │ Settings Page     │   │
                            │  └───────────────────┘   │
                            └──────────────────────────┘
```

## Data Flow / Luồng dữ liệu

### Training Pipeline (Offline)
```
honeypot_auth.log ──┐
                    ├──→ LogParser ──→ Labeler ──→ FeatureExtractor
simulation_auth.log ┘                                    │
                                                    14 features
                                                    per IP-window
                                                         │
                                                    DataSplitter
                                                   (70/30 + 1:3)
                                                         │
                                              ┌──────────┴──────────┐
                                              │                     │
                                         Train Set              Test Set
                                       (7,212 normal)     (15,184 mixed)
                                              │                     │
                                         RobustScaler              │
                                              │                     │
                                    ┌─────────┼─────────┐          │
                                    ▼         ▼         ▼          │
                                   IF       LOF      OCSVM        │
                                    │         │         │          │
                                    └─────────┼─────────┘          │
                                              │                    │
                                         Evaluation ◄─────────────┘
                                              │
                                    ModelComparator
                                    (metrics, ROC, CM)
```

### Detection Pipeline (Real-time)
```
auth.log (new line) ──→ LogParser ──→ IPWindowManager
                                         │
                                    [5-min window per IP]
                                         │
                                    FeatureExtractor ──→ 14 features
                                                            │
                                                    RobustScaler.transform()
                                                            │
                                                    IF.score_samples()
                                                            │
                                                    anomaly_score (float)
                                                            │
                                                    DynamicThreshold.evaluate()
                                                            │
                                              ┌─────────────┼─────────────┐
                                              │             │             │
                                           NORMAL    EARLY_WARNING     ALERT
                                              │             │             │
                                            (log)      WebSocket      Email
                                                       Dashboard     Fail2Ban
                                                                     ban IP
```

## Dynamic Threshold Algorithm

```
Score Stream:  s₁, s₂, s₃, ..., sₜ

Step 1: EWMA Smoothing
    ewma₀ = s₁
    ewmaₜ = α·sₜ + (1-α)·ewmaₜ₋₁     (α = 0.3)

Step 2: Adaptive Threshold
    buffer = [sₜ₋ₙ, ..., sₜ]          (n = lookback_window = 100)
    threshold = percentile(buffer, 95)

Step 3: Early Warning Threshold
    early_threshold = threshold / sensitivity_factor    (factor = 1.5)

Step 4: Decision
    if ewmaₜ ≥ threshold:           → ALERT
    elif ewmaₜ ≥ early_threshold:   → EARLY_WARNING
    else:                            → NORMAL

Step 5: Self-Calibration (periodic)
    if FPR > target:  increase percentile
    if FPR < target/2: decrease percentile
```

## Feature Engineering (14 Features)

```
Per Source IP, Per 5-minute Window:

Attempt-based Features:
  1. fail_count              - Number of failed password attempts
  2. success_count           - Number of successful logins
  3. fail_rate               - Failure ratio
  4. unique_usernames        - Distinct usernames tried
  5. invalid_user_count      - "Invalid user" events
  6. invalid_user_ratio      - Invalid user proportion

Timing Features:
  7. connection_count        - Total connections initiated
  8. mean_inter_attempt_time - Average gap between attempts
  9. std_inter_attempt_time  - Variability of timing
  10. min_inter_attempt_time - Minimum gap (catches automation)

Connection Features:
  11. unique_ports           - Distinct source ports used

Escalation Features:
  12. pam_failure_escalation - PAM escalation events
  13. max_retries_exceeded   - PAM max retries exceeded

Session Features:
  14. session_duration_mean  - Average session length
```

## Docker Services

```
┌──────────────────────────────────────────────────────┐
│                 docker-compose.yml                     │
│                                                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │ elastic  │  │ logstash │  │  kibana  │ ELK Stack   │
│  │  :9200   │  │          │  │  :5601   │            │
│  └──────────┘  └──────────┘  └──────────┘            │
│                                                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │  redis   │  │   api    │  │   web    │ App Layer   │
│  │  :6379   │  │  :8000   │  │  :3000   │            │
│  └──────────┘  └──────────┘  └──────────┘            │
│                                                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │ detector │  │ fail2ban │  │ssh_target│ Services    │
│  │          │  │          │  │  :2222   │            │
│  └──────────┘  └──────────┘  └──────────┘            │
│                                                        │
│  ┌──────────┐                                         │
│  │ attacker │  (on-demand, --profile demo)            │
│  └──────────┘                                         │
└──────────────────────────────────────────────────────┘
```
