# Demo Runbook - SSH Brute-Force Detection System
# Quy trình Demo trước Hội đồng

## Prerequisites / Yêu cầu trước khi demo
- Docker Desktop installed and running
- At least 8GB RAM available
- Ports available: 3000, 5601, 8000, 9200, 2222

## Step 1: Start the System / Khởi động hệ thống

```bash
cd D:\cybersec-capst\docker
docker compose up -d

# Wait for all services to be healthy (~2 minutes)
docker compose ps
```

Verify services:
- Web Dashboard: http://localhost:3000
- API: http://localhost:8000/api/health
- Kibana: http://localhost:5601
- Elasticsearch: http://localhost:9200
- SSH Target: localhost:2222

## Step 2: Show Dashboard Baseline / Hiển thị baseline

1. Open http://localhost:3000 in browser
2. Show Dashboard page - all stats at 0, no alerts
3. Show Model Performance page - IF vs LOF vs OCSVM comparison
4. Show Kibana page - ELK Stack integration
5. Show Settings page - dynamic threshold parameters

## Step 3: Demo Attack Scenario 1 - Basic Brute-Force

```bash
# Open a new terminal
docker compose --profile demo run attacker python brute_force_basic.py \
    --target ssh_target --port 22 --rate 10 --max-attempts 50
```

**What to show:**
- Real-time anomaly score spike on Dashboard
- ALERT notification appearing
- Email notification (if configured)
- Fail2Ban auto-blocking the attacker IP
- Kibana visualization of the attack pattern

**Expected result:** ALERT within 30 seconds

## Step 4: Demo Attack Scenario 3 - Low-and-Slow (KEY demo)

```bash
# This demonstrates the EARLY PREDICTION capability
docker compose --profile demo run attacker python slow_brute_force.py \
    --target ssh_target --port 22 --min-delay 30 --max-delay 60 --max-attempts 10
```

**What to show:**
- EARLY_WARNING appears after 3-5 attempts (~2-3 minutes)
- Traditional systems (Fail2Ban alone) would NOT detect this
- Dynamic threshold's EWMA accumulates suspicious scores over time
- Show threshold graph: EWMA score gradually rising toward threshold

**Expected result:** EARLY_WARNING after ~3 attempts, before full attack

## Step 5: Demo Attack Scenario 5 - Dictionary Attack

```bash
docker compose --profile demo run attacker python dictionary_attack.py \
    --target ssh_target --port 22 --rate 8 --max-users 10
```

**What to show:**
- Multiple invalid usernames being flagged
- High invalid_user_ratio in features
- Quick ALERT detection

## Step 6: Show Model Comparison Results

1. Navigate to Model Performance page
2. Highlight IF vs LOF vs OCSVM metrics
3. Show bar chart and radar chart comparison
4. Explain why IF is suitable for dynamic threshold approach
5. Show feature importance ranking

## Step 7: Show Architecture Diagram

Present the system architecture:
```
SSH Server → Log Parser → Feature Extractor → IF Model → Dynamic Threshold
                                                              ↓
                                          EARLY_WARNING / ALERT
                                              ↓           ↓
                                         Dashboard    Fail2Ban
                                         Email Alert   IP Ban
```

## Step 8: Cleanup / Dọn dẹp

```bash
docker compose --profile demo down
docker compose down -v  # Remove volumes if needed
```

## Troubleshooting / Xử lý sự cố

| Issue | Solution |
|-------|----------|
| Services not starting | Check Docker Desktop is running, increase RAM |
| No alerts showing | Check detector logs: `docker compose logs detector` |
| Kibana not loading | Wait 2-3 minutes after start, refresh page |
| SSH connection refused | Check ssh_target is running: `docker compose ps` |
| Email not sending | Configure SMTP in .env file |

## Key Talking Points / Điểm nhấn khi trình bày

1. **Early Prediction**: Unlike Fail2Ban (reactive), our system predicts attacks BEFORE they escalate using EWMA-based dynamic threshold
2. **AI-Powered**: Isolation Forest learns normal SSH behavior and detects anomalies without predefined rules
3. **Real-time**: Sub-second detection latency with asyncio pipeline
4. **Comprehensive**: 14 features capture multi-dimensional attack behavior
5. **Production-ready**: Docker containerization, ELK Stack, email alerts
