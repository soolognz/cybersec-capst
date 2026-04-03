# SSH Brute-Force Detection - Project Status

## Project Overview
- **Title**: Application of AI in Detecting and Preventing Brute-Force Attacks on SSH Systems with Early Prediction
- **University**: FPT University - Information Assurance
- **Duration**: 4 months (Semester Spring 2026)

## Implementation Status

### Phase 1: Data Processing Pipeline - COMPLETE
- [x] Log parser with 14+ event types
- [x] Data labeler (simulation=normal, honeypot=attack/normal)
- [x] Feature extractor (14 features per IP-window)
- [x] Data splitter (70/30 + 1:3 ratio)
- [x] Preprocessor (RobustScaler)

### Phase 2: Model Training - COMPLETE
- [x] Isolation Forest (main): F1=0.886, Recall=99.99%
- [x] LOF (benchmark): F1=0.905, Recall=100%
- [x] One-Class SVM (benchmark): F1=0.913, Recall=100%
- [x] Hyperparameter tuning
- [x] Model comparison metrics

### Phase 3: Dynamic Threshold - COMPLETE
- [x] EWMA-Adaptive Percentile hybrid algorithm
- [x] Two-level detection (EARLY_WARNING + ALERT)
- [x] Self-calibration mechanism

### Phase 4: Real-time Pipeline - COMPLETE
- [x] AsyncIO log tailer
- [x] Per-IP sliding window manager
- [x] Alert manager (email + WebSocket)
- [x] Fail2Ban integration

### Phase 5-6: ELK + Web Dashboard - COMPLETE
- [x] Logstash pipeline config
- [x] Elasticsearch index template
- [x] FastAPI backend with REST + WebSocket
- [x] React dashboard (5 pages)

### Phase 7-8: Attack Simulation + Docker - COMPLETE
- [x] 5 attack scenarios
- [x] Docker Compose (9 services)
- [x] Dockerfiles for all components

### Phase 9-10: Documentation - IN PROGRESS
- [ ] Thesis report (Vietnamese + English)
- [ ] Setup guide
- [ ] Demo runbook

## Dataset Statistics
- Training: 7,212 samples (100% normal from simulation)
- Testing: 15,184 samples (3,796 normal + 11,388 attack = 1:3)
- Honeypot: 119,729 log lines (5 days, 679 unique IPs)
- Simulation: 54,521 log lines (64 users, normal behavior)

## Model Results Summary
| Model | Accuracy | F1-Score | Recall | ROC-AUC |
|-------|----------|----------|--------|---------|
| Isolation Forest | 80.76% | 88.63% | 99.99% | 83.16% |
| LOF | 84.15% | 90.45% | 100% | 97.59% |
| One-Class SVM | 85.73% | 91.31% | 100% | 90.03% |

## Top Features (by importance)
1. session_duration_mean (5.50%)
2. min_inter_attempt_time (3.86%)
3. mean_inter_attempt_time (2.61%)
4. std_inter_attempt_time (1.64%)
5. unique_ports (1.42%)
