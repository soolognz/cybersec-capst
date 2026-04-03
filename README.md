# SSH Brute-Force Detection System with AI-Powered Early Prediction

Application of AI in Detecting and Preventing Brute-Force Attacks on SSH Systems with Early Prediction

*FPT University - Capstone Project - Information Assurance*

## Overview

An AI-powered system that detects and predicts SSH brute-force attacks in real-time using machine learning anomaly detection. Unlike traditional tools like Fail2Ban that react after a fixed threshold, this system uses **Isolation Forest** with a **dynamic threshold** to provide **early warnings** before attacks fully escalate.

## Key Features

- **AI Detection**: Isolation Forest anomaly detection trained on normal SSH behavior
- **Early Prediction**: EWMA-Adaptive Percentile dynamic threshold for proactive warnings
- **Real-time Monitoring**: AsyncIO pipeline with sub-second detection latency
- **Model Comparison**: Benchmarked against LOF and One-Class SVM
- **Visualization**: React dashboard + ELK Stack (Kibana) integration
- **Prevention**: Automatic IP blocking via Fail2Ban
- **Alerts**: Email notifications + WebSocket real-time push
- **Containerized**: Full Docker Compose deployment (9 services)

## Architecture

```
SSH Server ──→ Log Parser ──→ Feature Extractor ──→ Isolation Forest
                                                         │
                                                   Dynamic Threshold
                                                    ┌─────┴─────┐
                                              EARLY_WARNING   ALERT
                                                    │           │
                                              Dashboard    Fail2Ban
                                              Email        IP Ban
```

## Quick Start

### Docker (Recommended)

```bash
cd docker
cp .env.example .env  # Configure email alerts
docker compose up -d
```

- Dashboard: http://localhost:3000
- API: http://localhost:8000
- Kibana: http://localhost:5601

### Manual Setup

```bash
pip install -r requirements.txt
python -m src.pipeline --mode full     # Train models
uvicorn src.api.main:app --port 8000   # Start API
cd src/web && npm install && npm run dev  # Start dashboard
```

## Attack Simulation (Demo)

```bash
# Basic brute-force
docker compose --profile demo run attacker python brute_force_basic.py --target ssh_target

# Low-and-slow (tests early prediction)
docker compose --profile demo run attacker python slow_brute_force.py --target ssh_target
```

## Model Results

| Model | Accuracy | F1-Score | Recall | ROC-AUC |
|-------|----------|----------|--------|---------|
| **Isolation Forest** | 80.76% | 88.63% | 99.99% | 83.16% |
| LOF | 84.15% | 90.45% | 100% | 97.59% |
| One-Class SVM | 85.73% | 91.31% | 100% | 90.03% |

## Project Structure

```
├── src/
│   ├── data_processing/    # Log parser, feature extractor, labeler
│   ├── models/             # IF, LOF, OCSVM, dynamic threshold
│   ├── detection/          # Real-time pipeline, alerts, Fail2Ban
│   ├── api/                # FastAPI backend
│   └── web/                # React dashboard
├── attack_simulation/      # 5 attack scenarios
├── docker/                 # Docker Compose + Dockerfiles
├── elk/                    # ELK Stack configs
├── fail2ban/               # Fail2Ban configs
├── configs/                # Model + system configs
└── thesis/                 # Thesis report
```

## Technologies

- **ML**: Python, scikit-learn, pandas, numpy
- **Backend**: FastAPI, Redis, asyncio
- **Frontend**: React, TypeScript, Tailwind CSS, Recharts
- **Infrastructure**: ELK Stack 8.12, Fail2Ban, Docker
- **Monitoring**: Kibana, WebSocket real-time

## License

This project is part of FPT University Capstone requirements.
