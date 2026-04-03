# Hướng dẫn kiểm tra Real-time từng bước
# Step-by-Step Real-time Testing Guide

## Mục tiêu
Hướng dẫn chi tiết cách kiểm tra hệ thống phát hiện brute-force SSH hoạt động real-time, từ A đến Z.

---

## Phương pháp 1: Docker (Khuyến nghị)

### Bước 1: Khởi động toàn bộ hệ thống

```bash
cd D:\cybersec-capst\docker

# Copy và cấu hình email (tùy chọn)
cp .env.example .env
# Sửa .env nếu muốn nhận email alert

# Khởi động tất cả services
docker compose up -d

# Đợi ~2 phút cho services khởi động
docker compose ps
```

Kiểm tra tất cả services đều "healthy":
- elasticsearch (port 9200)
- kibana (port 5601)
- redis (port 6379)
- api (port 8000)
- web (port 3000)
- ssh_target (port 2222)

### Bước 2: Verify các services

```bash
# Check API health
curl http://localhost:8000/api/health

# Check Elasticsearch
curl http://localhost:9200

# Mở dashboard
# Trình duyệt: http://localhost:3000

# Mở Kibana
# Trình duyệt: http://localhost:5601
```

### Bước 3: Kiểm tra SSH target hoạt động

```bash
# Thử SSH vào target server (password: DemoPass123)
ssh root@localhost -p 2222
# Nhập password: DemoPass123 → phải đăng nhập thành công
# exit để thoát
```

### Bước 4: Chạy kịch bản tấn công

```bash
# Scenario 1: Basic Brute-force (nhanh, dễ phát hiện)
docker compose --profile demo run attacker python brute_force_basic.py \
    --target ssh_target --port 22 --rate 10 --max-attempts 50
```

### Bước 5: Quan sát kết quả trên Dashboard

1. Mở http://localhost:3000
2. Xem tab **Dashboard**: số Critical Alerts tăng
3. Xem tab **Alerts**: danh sách alert với IP, score, action
4. Xem tab **Model Performance**: biểu đồ so sánh IF vs LOF vs OCSVM
5. Xem Kibana: http://localhost:5601 → các biểu đồ log

### Bước 6: Test kịch bản Low-and-Slow (KEY TEST)

```bash
# Scenario 3: Tấn công chậm - thử thách cho hệ thống
docker compose --profile demo run attacker python slow_brute_force.py \
    --target ssh_target --port 22 --min-delay 30 --max-delay 60 --max-attempts 10
```

**Kỳ vọng**: EARLY_WARNING xuất hiện sau 3-5 lần thử (~2-3 phút).
Fail2Ban thông thường KHÔNG phát hiện được kịch bản này.

### Bước 7: Kiểm tra Fail2Ban đã chặn IP

```bash
docker compose exec fail2ban fail2ban-client status sshd-ai
```

### Bước 8: Cleanup

```bash
docker compose --profile demo down
docker compose down -v  # Xóa volumes nếu muốn reset
```

---

## Phương pháp 2: Manual (không Docker)

### Bước 1: Cài đặt dependencies

```bash
pip install -r requirements.txt
```

### Bước 2: Train models

```bash
python -m src.pipeline --mode full
# Output: trained_models/*.joblib, output/*.csv
```

### Bước 3: Start API server

```bash
# Terminal 1
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

### Bước 4: Test offline detection (không cần real SSH server)

```python
# Terminal 2 - Python interactive
from src.detection.realtime_pipeline import RealtimePipeline

pipeline = RealtimePipeline(model_dir='trained_models')
detections = pipeline.process_log_file('Dataset/honeypot_auth.log.log')

# Xem kết quả
for d in detections[:10]:
    print(f"IP: {d['ip']}, Score: {d['score']:.4f}, Level: {d['threat_level']}")
```

### Bước 5: Test real-time trên máy local (Linux)

```bash
# Terminal 1: Start detection
python -c "
import asyncio
from src.detection.realtime_pipeline import RealtimePipeline

async def on_alert(ip, score, decision):
    print(f'ALERT! IP={ip} Score={score:.4f}')

pipeline = RealtimePipeline(
    log_path='/var/log/auth.log',
    model_dir='trained_models',
    scoring_interval=10,
    on_alert=on_alert,
)
asyncio.run(pipeline.start())
"

# Terminal 2: Simulate attack
python attack_simulation/brute_force_basic.py --target localhost --port 22 --rate 5
```

---

## Phương pháp 3: Test nhanh bằng script verify

```bash
# Chạy test script tổng hợp
python -m pytest tests/ -v

# Kết quả mong đợi: 51/51 PASSED
```

---

## Checklist xác nhận hệ thống hoạt động

- [ ] Pipeline train chạy thành công (models saved)
- [ ] API health endpoint trả về "healthy"
- [ ] Dashboard load được tại port 3000
- [ ] Basic brute-force bị phát hiện (< 30 giây)
- [ ] Low-and-slow trigger EARLY_WARNING (< 5 phút)
- [ ] Alert xuất hiện trên Dashboard
- [ ] Kibana hiển thị log events
- [ ] Fail2Ban chặn IP khi ALERT

---

## Troubleshooting thường gặp

| Vấn đề | Nguyên nhân | Giải pháp |
|---------|-------------|-----------|
| Docker services không start | Thiếu RAM | Cần ≥ 8GB RAM, đóng ứng dụng khác |
| API trả về 500 | Model chưa train | Chạy `python -m src.pipeline --mode full` trước |
| Không connect SSH target | Port 2222 bị chiếm | Đổi port trong docker-compose.yml |
| Dashboard trống | API chưa start | Kiểm tra `docker compose logs api` |
| Kibana loading mãi | ES chưa ready | Đợi 2-3 phút, refresh |
| Email không gửi | SMTP chưa config | Cấu hình .env với Gmail App Password |
