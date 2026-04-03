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

### Phase 9-10: Documentation - MOSTLY COMPLETE
- [x] Thesis outline (thesis_outline_vi.md)
- [x] Chapter 1: Introduction (3,777 words)
- [x] Chapter 2: Literature Review (9,627 words)
- [x] Chapter 3: Methodology (6,723 words)
- [ ] Chapter 4: Experimental Results (in progress)
- [x] Chapter 5: Discussion (1,606 words)
- [x] Chapter 6: Conclusion (1,088 words)
- [x] Setup guide manual (1,123 lines, bilingual)
- [x] Demo runbook
- [x] Architecture diagram
- [x] Feature dictionary
- [x] API reference

### Tests - COMPLETE
- [x] 51/51 tests passing
- [x] Log parser tests (12)
- [x] Feature extractor tests (11)
- [x] Data splitter tests (6)
- [x] Model tests (8)
- [x] Preprocessor tests (5)
- [x] API tests (9)

### Model Optimization - COMPLETE
- [x] Non-overlapping windows
- [x] 9 derived features (23 total)
- [x] Extended hyperparameter grid search
- [x] Contamination tuning

### GitHub - PUSHED
- [x] Repository: https://github.com/soolognz/cybersec-capst
- [x] 3 commits on main branch

## Dataset Statistics
- Training: 7,212 samples (100% normal from simulation)
- Testing: 15,184 samples (3,796 normal + 11,388 attack = 1:3)
- Honeypot: 119,729 log lines (5 days, 679 unique IPs)
- Simulation: 54,521 log lines (64 users, normal behavior)

## Model Results Summary (After Optimization)
| Model | Accuracy | F1-Score | FPR | ROC-AUC |
|-------|----------|----------|-----|---------|
| **Isolation Forest** | **90.31%** | **93.74%** | **29.00%** | **86.61%** |
| LOF | 83.22% | 89.94% | 67.10% | 65.24% |
| One-Class SVM | 91.38% | 94.55% | 33.42% | 83.42% |

### Improvement vs Baseline
| Model | Accuracy Change | F1 Change | FPR Reduction |
|-------|----------------|-----------|---------------|
| IF | +9.55% | +5.11% | -47.92% |

## Top Features (by importance)
1. session_duration_mean (5.50%)
2. min_inter_attempt_time (3.86%)
3. mean_inter_attempt_time (2.61%)
4. std_inter_attempt_time (1.64%)
5. unique_ports (1.42%)
