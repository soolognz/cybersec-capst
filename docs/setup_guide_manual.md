# Huong dan Cai dat va Trien khai He thong Phat hien Tan cong Brute-Force SSH

# Setup and Deployment Guide for SSH Brute-Force Detection System

---

**Phien ban / Version:** 1.0
**Cap nhat lan cuoi / Last Updated:** 03/04/2026
**He dieu hanh muc tieu / Target OS:** Ubuntu 22.04 LTS Server

---

## Muc luc / Table of Contents

1. [Yeu cau he thong / System Requirements](#1-yeu-cau-he-thong--system-requirements)
2. [Cai dat thu cong tren Linux / Manual Installation on Linux](#2-cai-dat-thu-cong-tren-linux--manual-installation-on-linux)
3. [Thiet lap moi truong Python / Python Environment Setup](#3-thiet-lap-moi-truong-python--python-environment-setup)
4. [Chuan bi du lieu / Dataset Preparation](#4-chuan-bi-du-lieu--dataset-preparation)
5. [Chay Pipeline huan luyen mo hinh / Model Training Pipeline](#5-chay-pipeline-huan-luyen-mo-hinh--model-training-pipeline)
6. [Cai dat ELK Stack / ELK Stack Setup](#6-cai-dat-elk-stack--elk-stack-setup)
7. [Cau hinh Fail2Ban / Fail2Ban Configuration](#7-cau-hinh-fail2ban--fail2ban-configuration)
8. [Khoi dong API Server / API Server Startup](#8-khoi-dong-api-server--api-server-startup)
9. [Xay dung va khoi dong Web Dashboard / Web Dashboard Build and Startup](#9-xay-dung-va-khoi-dong-web-dashboard--web-dashboard-build-and-startup)
10. [Trien khai bang Docker / Docker Deployment](#10-trien-khai-bang-docker--docker-deployment)
11. [Chay mo phong tan cong / Running Attack Simulations](#11-chay-mo-phong-tan-cong--running-attack-simulations)
12. [Xu ly su co thuong gap / Troubleshooting Common Issues](#12-xu-ly-su-co-thuong-gap--troubleshooting-common-issues)
13. [Danh sach kiem tra xac nhan / Verification Checklist](#13-danh-sach-kiem-tra-xac-nhan--verification-checklist)

---

## 1. Yeu cau he thong / System Requirements

### 1.1. Yeu cau phan cung / Hardware Requirements

| Thanh phan / Component | Toi thieu / Minimum       | Khuyen nghi / Recommended |
| ---------------------- | ------------------------- | ------------------------- |
| CPU                    | 2 cores                   | 4 cores                   |
| RAM                    | 4 GB                      | 8 GB                      |
| Disk                   | 20 GB                     | 50 GB SSD                 |
| Network                | 1 Gbps                    | 1 Gbps                    |

> **Ghi chu / Note:** ELK Stack yeu cau toi thieu 4 GB RAM. Khi chay dong thoi tat ca cac dich vu, khuyen nghi su dung may co 8 GB RAM tro len.
>
> ELK Stack requires a minimum of 4 GB RAM. When running all services concurrently, a machine with at least 8 GB RAM is recommended.

### 1.2. Yeu cau phan mem / Software Requirements

| Phan mem / Software   | Phien ban / Version | Muc dich / Purpose                    |
| --------------------- | ------------------- | ------------------------------------- |
| Ubuntu Server         | 22.04 LTS           | He dieu hanh / Operating system       |
| Python                | 3.11+               | Backend va ML pipeline                |
| Node.js               | 18 LTS+             | Xay dung web dashboard                |
| Docker                | 24.0+               | Trien khai container                  |
| Docker Compose        | 2.20+               | Dieu phoi da container                |
| Elasticsearch         | 8.12.0              | Luu tru va truy van log               |
| Logstash              | 8.12.0              | Thu thap va xu ly log                 |
| Kibana                | 8.12.0              | Truc quan hoa du lieu                 |
| Redis                 | 7.x                 | Message queue thoi gian thuc          |
| Fail2Ban              | 0.11+               | Chan IP tu dong                       |
| OpenSSH Server        | 8.9+                | SSH server muc tieu                   |

### 1.3. Cong mang can mo / Required Network Ports

| Cong / Port | Dich vu / Service    | Mo ta / Description                   |
| ----------- | -------------------- | ------------------------------------- |
| 22          | SSH                  | SSH server (muc tieu)                 |
| 2222        | SSH (demo)           | SSH server demo trong Docker          |
| 3000        | Web Dashboard        | Giao dien React                       |
| 5601        | Kibana               | Giao dien truc quan hoa               |
| 6379        | Redis                | Message queue                         |
| 8000        | FastAPI              | API backend                           |
| 9200        | Elasticsearch        | REST API Elasticsearch                |

---

## 2. Cai dat thu cong tren Linux / Manual Installation on Linux

### 2.1. Cap nhat he thong / System Update

```bash
sudo apt update && sudo apt upgrade -y
```

### 2.2. Cai dat cac goi can thiet / Install Required Packages

```bash
sudo apt install -y \
    build-essential \
    curl \
    wget \
    git \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    openssh-server \
    iptables \
    net-tools
```

### 2.3. Cai dat Python 3.11 / Install Python 3.11

```bash
# Them PPA deadsnakes neu Python 3.11 chua co san
# Add deadsnakes PPA if Python 3.11 is not available
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev python3-pip
```

Xac nhan phien ban / Verify version:

```bash
python3.11 --version
# Expected output: Python 3.11.x
```

### 2.4. Cai dat Node.js 18 LTS / Install Node.js 18 LTS

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

Xac nhan / Verify:

```bash
node --version   # Expected: v18.x.x
npm --version    # Expected: 9.x.x or 10.x.x
```

### 2.5. Cai dat Redis 7 / Install Redis 7

```bash
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
sudo apt update
sudo apt install -y redis-server
```

Kich hoat va khoi dong Redis / Enable and start Redis:

```bash
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

Kiem tra / Test:

```bash
redis-cli ping
# Expected output: PONG
```

### 2.6. Clone du an / Clone the Project

```bash
cd /opt
sudo git clone <repository-url> ssh-bruteforce-detection
sudo chown -R $USER:$USER /opt/ssh-bruteforce-detection
cd /opt/ssh-bruteforce-detection
```

> **Ghi chu / Note:** Thay `<repository-url>` bang URL thuc te cua repository.
>
> Replace `<repository-url>` with the actual repository URL.

---

## 3. Thiet lap moi truong Python / Python Environment Setup

### 3.1. Tao moi truong ao / Create Virtual Environment

```bash
cd /opt/ssh-bruteforce-detection
python3.11 -m venv venv
source venv/bin/activate
```

### 3.2. Cai dat cac thu vien / Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Cac thu vien chinh duoc cai dat bao gom / The main libraries installed include:

- **pandas >= 2.0.0** -- Xu ly du lieu / Data processing
- **numpy >= 1.24.0** -- Tinh toan so hoc / Numerical computation
- **scikit-learn >= 1.3.0** -- Mo hinh hoc may / Machine learning models
- **fastapi >= 0.104.0** -- API framework
- **uvicorn >= 0.24.0** -- ASGI server
- **redis >= 5.0.0** -- Client ket noi Redis
- **elasticsearch >= 8.0.0** -- Client ket noi Elasticsearch
- **paramiko >= 3.0.0** -- Mo phong tan cong SSH / SSH attack simulation
- **websockets >= 12.0** -- Giao tiep thoi gian thuc / Real-time communication
- **pyyaml >= 6.0.0** -- Doc file cau hinh / Configuration file parsing

### 3.3. Xac nhan cai dat / Verify Installation

```bash
python -c "import sklearn; import fastapi; import redis; import elasticsearch; print('All dependencies OK')"
```

---

## 4. Chuan bi du lieu / Dataset Preparation

### 4.1. Cau truc thu muc du lieu / Dataset Directory Structure

Du an su dung hai file log SSH lam du lieu dau vao, dat trong thu muc `Dataset/`:

The project uses two SSH log files as input data, located in the `Dataset/` directory:

```
Dataset/
  ├── honeypot_auth.log.log      # Log tu may chu honeypot (chua nhieu tan cong)
  └── simulation_auth.log.log    # Log tu mo phong (co nhan binh thuong va tan cong)
```

- **honeypot_auth.log.log** -- Chua nhat ky xac thuc SSH tu may chu honeypot. Phan lon cac ban ghi trong file nay la tan cong brute-force thuc te.
  
  Contains SSH authentication logs from a honeypot server. Most records in this file are actual brute-force attacks.

- **simulation_auth.log.log** -- Chua nhat ky tu moi truong mo phong voi ca luong truy cap binh thuong lan tan cong duoc kiem soat.
  
  Contains logs from a simulated environment with both normal traffic and controlled attacks.

### 4.2. Kiem tra du lieu / Verify Dataset

```bash
cd /opt/ssh-bruteforce-detection

# Kiem tra file ton tai / Check files exist
ls -la Dataset/

# Dem so dong / Count lines
wc -l Dataset/*.log
```

### 4.3. Dinh dang du lieu / Data Format

Cac file log theo dinh dang syslog chuan voi timestamp ISO 8601:

The log files follow standard syslog format with ISO 8601 timestamps:

```
2024-01-15T10:30:45+07:00 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
2024-01-15T10:30:46+07:00 server sshd[12345]: Accepted password for user1 from 10.0.0.5 port 22345 ssh2
```

---

## 5. Chay Pipeline huan luyen mo hinh / Model Training Pipeline

### 5.1. Tong quan Pipeline / Pipeline Overview

Pipeline xu ly du lieu va huan luyen mo hinh gom 8 buoc:

The data processing and model training pipeline consists of 8 steps:

| Buoc / Step | Mo ta / Description                                           |
| ----------- | ------------------------------------------------------------- |
| 1           | Phan tich va gan nhan du lieu / Parse and label data          |
| 2           | Trich xuat dac trung (14 features/IP-window) / Feature extraction |
| 3           | Chia du lieu train/test (70/30, ti le 1:3) / Data splitting  |
| 4           | Tien xu ly (RobustScaler) / Preprocessing                    |
| 5           | Huan luyen 3 mo hinh + toi uu sieu tham so / Train 3 models + hyperparameter tuning |
| 6           | So sanh va danh gia mo hinh / Model comparison and evaluation |
| 7           | Danh gia nguong dong (Dynamic Threshold) / Dynamic threshold evaluation |
| 8           | Xep hang do quan trong dac trung / Feature importance ranking |

### 5.2. Chay toan bo Pipeline / Run Full Pipeline

```bash
cd /opt/ssh-bruteforce-detection
source venv/bin/activate

# Chay pipeline day du / Run full pipeline
python -m src.pipeline --mode full
```

> **Thoi gian du kien / Expected time:** 2--5 phut tuy theo kich thuoc du lieu va cau hinh may.
>
> 2--5 minutes depending on dataset size and machine configuration.

### 5.3. Ket qua dau ra / Output Results

Sau khi pipeline hoan thanh, cac file ket qua duoc luu tai:

After the pipeline completes, output files are saved at:

```
trained_models/
  ├── isolation_forest.joblib       # Mo hinh Isolation Forest (chinh)
  ├── lof.joblib                    # Mo hinh LOF (doi chieu)
  ├── ocsvm.joblib                  # Mo hinh One-Class SVM (doi chieu)
  └── scaler.joblib                 # RobustScaler da fit

output/
  ├── model_comparison.csv          # Bang so sanh hieu nang 3 mo hinh
  ├── dynamic_threshold_results.json # Ket qua nguong dong
  ├── feature_importance.csv        # Xep hang dac trung
  ├── X_train.npy                   # Du lieu huan luyen da xu ly
  ├── X_test.npy                    # Du lieu kiem tra da xu ly
  ├── y_test.npy                    # Nhan kiem tra
  ├── train_features.csv            # Dac trung chua scale
  ├── test_features.csv             # Dac trung kiem tra chua scale
  └── test_labels.csv               # Nhan kiem tra
```

### 5.4. Kiem tra mo hinh da duoc luu / Verify Saved Models

```bash
ls -la trained_models/
# Kiem tra xem cac file .joblib da duoc tao thanh cong
# Verify that .joblib files were created successfully

python -c "
import joblib
model = joblib.load('trained_models/isolation_forest.joblib')
print(f'Model loaded: {type(model).__name__}')
print(f'Number of estimators: {model.n_estimators}')
"
```

---

## 6. Cai dat ELK Stack / ELK Stack Setup

### 6.1. Cai dat Elasticsearch 8.12 / Install Elasticsearch 8.12

```bash
# Them khoa GPG va repository cua Elastic
# Add Elastic GPG key and repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update
sudo apt install -y elasticsearch=8.12.0
```

### 6.2. Cau hinh Elasticsearch / Configure Elasticsearch

```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Them hoac sua cac dong sau / Add or modify the following lines:

```yaml
cluster.name: ssh-bruteforce-cluster
node.name: node-1
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false

# Gioi han bo nho / Memory limits
# Chinh trong /etc/elasticsearch/jvm.options:
# Adjust in /etc/elasticsearch/jvm.options:
# -Xms512m
# -Xmx512m
```

Khoi dong Elasticsearch / Start Elasticsearch:

```bash
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

Kiem tra / Verify:

```bash
curl -s http://localhost:9200 | python3 -m json.tool
# Phai tra ve thong tin cluster voi version 8.12.0
# Should return cluster info with version 8.12.0
```

### 6.3. Tao Index Template / Create Index Template

```bash
curl -X PUT "http://localhost:9200/_index_template/ssh-auth-logs" \
  -H "Content-Type: application/json" \
  -d @elk/elasticsearch/ssh_index_template.json
```

### 6.4. Cai dat Logstash 8.12 / Install Logstash 8.12

```bash
sudo apt install -y logstash=1:8.12.0-1
```

### 6.5. Cau hinh Logstash Pipeline / Configure Logstash Pipeline

Sao chep file cau hinh pipeline cua du an:

Copy the project's pipeline configuration file:

```bash
sudo cp elk/logstash/pipeline/ssh_logs.conf /etc/logstash/conf.d/ssh_logs.conf
```

> **Ghi chu / Note:** File `ssh_logs.conf` da duoc cau hinh san de:
>
> The `ssh_logs.conf` file is pre-configured to:
> - Doc file `/var/log/auth.log` / Read file `/var/log/auth.log`
> - Phan tich cac su kien SSH (failed_password, accepted_password, invalid_user, v.v.) / Parse SSH events
> - Lam giau du lieu voi GeoIP / Enrich data with GeoIP
> - Xuat ra Elasticsearch voi index `ssh-auth-logs-YYYY.MM.dd` / Output to Elasticsearch

Khoi dong Logstash / Start Logstash:

```bash
sudo systemctl enable logstash
sudo systemctl start logstash
```

### 6.6. Cai dat Kibana 8.12 / Install Kibana 8.12

```bash
sudo apt install -y kibana=8.12.0
```

Cau hinh Kibana / Configure Kibana:

```bash
sudo nano /etc/kibana/kibana.yml
```

```yaml
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
```

Khoi dong Kibana / Start Kibana:

```bash
sudo systemctl enable kibana
sudo systemctl start kibana
```

Kiem tra / Verify:

```bash
# Doi khoang 30 giay de Kibana khoi dong
# Wait about 30 seconds for Kibana to start
curl -s http://localhost:5601/api/status | python3 -m json.tool
```

Truy cap giao dien Kibana tai / Access Kibana interface at: `http://<server-ip>:5601`

---

## 7. Cau hinh Fail2Ban / Fail2Ban Configuration

### 7.1. Cai dat Fail2Ban / Install Fail2Ban

```bash
sudo apt install -y fail2ban
```

### 7.2. Sao chep cau hinh du an / Copy Project Configuration

```bash
# Sao chep file jail / Copy jail file
sudo cp fail2ban/jail.local /etc/fail2ban/jail.local

# Sao chep filter cho AI detection / Copy AI detection filter
sudo cp fail2ban/filter.d/sshd-ai.conf /etc/fail2ban/filter.d/sshd-ai.conf
```

### 7.3. Mo ta cau hinh / Configuration Description

**Jail `[sshd]`** (bao ve co ban / basic protection):
- `maxretry = 5` -- Chan IP sau 5 lan dang nhap that bai / Ban IP after 5 failed logins
- `bantime = 600` -- Chan trong 10 phut / Ban for 10 minutes

**Jail `[sshd-ai]`** (bao ve bang AI / AI-powered protection):
- `filter = sshd-ai` -- Su dung filter nhan dien tu AI / Uses AI detection filter
- `bantime = 3600` -- Chan trong 1 gio / Ban for 1 hour
- `maxretry = 100` -- Dat cao vi AI xu ly logic phat hien / Set high since AI handles detection logic
- Filter nhan dang cac dong log co dang / Filter matches log lines like:
  - `AI-ALERT ... source_ip=<HOST> ... threat_level=critical`
  - `CRITICAL ... Brute-force attack detected from <HOST>`

### 7.4. Khoi dong Fail2Ban / Start Fail2Ban

```bash
sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
```

### 7.5. Kiem tra trang thai / Check Status

```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo fail2ban-client status sshd-ai
```

Ket qua mong doi / Expected output:

```
Status for the jail: sshd-ai
|- Filter
|  |- Currently failed: 0
|  |- Total failed:     0
|  `- File list:        /var/log/auth.log
`- Actions
   |- Currently banned: 0
   |- Total banned:     0
   `- Banned IP list:
```

---

## 8. Khoi dong API Server / API Server Startup

### 8.1. Cau hinh / Configuration

Kiem tra file cau hinh he thong tai `configs/system_config.yaml`:

Review the system configuration file at `configs/system_config.yaml`:

```yaml
api:
  host: 0.0.0.0
  port: 8000
  cors_origins:
    - "http://localhost:3000"    # Web dashboard
    - "http://localhost:5601"    # Kibana

elasticsearch:
  hosts:
    - "http://localhost:9200"

redis:
  host: localhost
  port: 6379
```

### 8.2. Thiet lap bien moi truong (tuy chon) / Set Environment Variables (Optional)

Neu su dung chuc nang canh bao email / If using email alert functionality:

```bash
export SMTP_USER="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"
export ALERT_EMAIL_TO="admin@example.com"
```

### 8.3. Khoi dong API / Start API Server

```bash
cd /opt/ssh-bruteforce-detection
source venv/bin/activate

# Khoi dong API server / Start API server
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

Hoac chay nen / Or run in background:

```bash
nohup uvicorn src.api.main:app --host 0.0.0.0 --port 8000 > logs/api.log 2>&1 &
```

### 8.4. Kiem tra API / Verify API

```bash
# Kiem tra health endpoint / Check health endpoint
curl http://localhost:8000/

# Xem tai lieu API tu dong / View auto-generated API documentation
# Truy cap / Visit: http://localhost:8000/docs  (Swagger UI)
# Hoac / Or:       http://localhost:8000/redoc  (ReDoc)
```

### 8.5. Khoi dong Real-time Detection Worker (tuy chon) / Start Real-time Detection Worker (Optional)

```bash
# Chay worker phat hien thoi gian thuc / Run real-time detection worker
python -m src.detection.realtime_pipeline
```

Worker nay se / This worker will:
- Theo doi file `/var/log/auth.log` theo thoi gian thuc / Monitor `/var/log/auth.log` in real-time
- Trich xuat dac trung va tinh diem bat thuong / Extract features and compute anomaly scores
- Day ket qua vao Redis stream / Push results to Redis stream
- Gui canh bao khi phat hien tan cong / Send alerts when attacks are detected

---

## 9. Xay dung va khoi dong Web Dashboard / Web Dashboard Build and Startup

### 9.1. Cai dat thu vien / Install Dependencies

```bash
cd /opt/ssh-bruteforce-detection/src/web
npm install
```

### 9.2. Chay o che do phat trien / Run in Development Mode

```bash
npm run dev
# Dashboard se khoi dong tai http://localhost:5173 (Vite default)
# Dashboard will start at http://localhost:5173 (Vite default)
```

### 9.3. Build cho moi truong san xuat / Build for Production

```bash
npm run build
```

Ket qua build se duoc luu tai `src/web/dist/`. Cac file nay co the duoc phuc vu boi bat ky web server nao (Nginx, Apache, v.v.).

Build output will be saved to `src/web/dist/`. These files can be served by any web server (Nginx, Apache, etc.).

### 9.4. Phuc vu bang Nginx (tuy chon) / Serve with Nginx (Optional)

```bash
sudo apt install -y nginx

# Tao cau hinh Nginx / Create Nginx configuration
sudo tee /etc/nginx/sites-available/ssh-dashboard << 'NGINX_CONF'
server {
    listen 3000;
    server_name _;

    root /opt/ssh-bruteforce-detection/src/web/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://localhost:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws {
        proxy_pass http://localhost:8000/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
NGINX_CONF

sudo ln -sf /etc/nginx/sites-available/ssh-dashboard /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

Truy cap dashboard tai / Access dashboard at: `http://<server-ip>:3000`

---

## 10. Trien khai bang Docker / Docker Deployment

### 10.1. Cai dat Docker va Docker Compose / Install Docker and Docker Compose

```bash
# Cai dat Docker / Install Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

# Kiem tra / Verify
docker --version        # Expected: Docker version 24.x+
docker compose version  # Expected: Docker Compose version v2.20+
```

### 10.2. Cau truc Docker cua du an / Project Docker Structure

```
docker/
  ├── docker-compose.yml       # Dieu phoi toan bo dich vu / Full service orchestration
  ├── Dockerfile.api           # API backend (Python 3.11 + FastAPI)
  ├── Dockerfile.detector      # Real-time detection worker
  ├── Dockerfile.web           # Web dashboard (React + Nginx)
  ├── Dockerfile.ssh_target    # SSH server muc tieu cho demo
  ├── Dockerfile.attacker      # Container tan cong cho demo
  └── nginx.conf               # Cau hinh Nginx cho web dashboard
```

### 10.3. Cac dich vu trong Docker Compose / Services in Docker Compose

| Dich vu / Service | Image / Build               | Cong / Port  | Mo ta / Description                   |
| ----------------- | --------------------------- | ------------ | ------------------------------------- |
| elasticsearch     | elasticsearch:8.12.0        | 9200         | Luu tru log                           |
| logstash          | logstash:8.12.0             | (internal)   | Xu ly log                             |
| kibana            | kibana:8.12.0               | 5601         | Truc quan hoa                         |
| redis             | redis:7-alpine              | 6379         | Message queue                         |
| api               | Dockerfile.api              | 8000         | FastAPI backend                       |
| detector          | Dockerfile.detector         | (internal)   | Worker phat hien thoi gian thuc       |
| web               | Dockerfile.web              | 3000         | React dashboard                       |
| fail2ban          | crazymax/fail2ban           | (host)       | Chan IP tu dong                       |
| ssh_target        | Dockerfile.ssh_target       | 2222         | SSH server demo                       |
| attacker          | Dockerfile.attacker         | (none)       | Container tan cong (profile: demo)    |

### 10.4. Huan luyen mo hinh truoc khi trien khai / Train Models Before Deployment

**Quan trong / Important:** Mo hinh phai duoc huan luyen truoc khi xay dung Docker image API.

Models must be trained before building the API Docker image.

```bash
cd /opt/ssh-bruteforce-detection

# Dam bao da huan luyen mo hinh (xem Muc 5)
# Ensure models are trained (see Section 5)
ls trained_models/
# Phai thay: isolation_forest.joblib, lof.joblib, ocsvm.joblib, scaler.joblib
# Must see: isolation_forest.joblib, lof.joblib, ocsvm.joblib, scaler.joblib
```

### 10.5. Khoi dong tat ca dich vu / Start All Services

```bash
cd /opt/ssh-bruteforce-detection/docker

# Khoi dong tat ca dich vu / Start all services
docker compose up -d

# Theo doi log / Follow logs
docker compose logs -f
```

### 10.6. Kiem tra trang thai dich vu / Check Service Status

```bash
# Xem trang thai tat ca container / View all container status
docker compose ps

# Kiem tra tung dich vu / Check individual services
docker compose logs elasticsearch | tail -20
docker compose logs api | tail -20
docker compose logs web | tail -10
```

Ket qua mong doi / Expected output:

```
NAME                 STATUS          PORTS
ssh-ai-elasticsearch healthy         0.0.0.0:9200->9200/tcp
ssh-ai-logstash      running         ...
ssh-ai-kibana        running         0.0.0.0:5601->5601/tcp
ssh-ai-redis         healthy         0.0.0.0:6379->6379/tcp
ssh-ai-api           running         0.0.0.0:8000->8000/tcp
ssh-ai-detector      running         ...
ssh-ai-web           running         0.0.0.0:3000->80/tcp
ssh-ai-fail2ban      running         ...
ssh-ai-target        running         0.0.0.0:2222->22/tcp
```

### 10.7. Dung tat ca dich vu / Stop All Services

```bash
cd /opt/ssh-bruteforce-detection/docker

# Dung va xoa container / Stop and remove containers
docker compose down

# Dung va xoa ca du lieu (volumes) / Stop and remove including data
docker compose down -v
```

---

## 11. Chay mo phong tan cong / Running Attack Simulations

### 11.1. Danh sach kich ban tan cong / Available Attack Scenarios

Du an cung cap 5 kich ban mo phong tan cong trong thu muc `attack_simulation/`:

The project provides 5 attack simulation scenarios in the `attack_simulation/` directory:

| Script                         | Mo ta / Description                                            |
| ------------------------------ | -------------------------------------------------------------- |
| `brute_force_basic.py`         | Tan cong brute-force co ban, thu nhieu mat khau lien tuc       |
|                                | Basic brute-force, rapid sequential password attempts          |
| `brute_force_distributed.py`   | Tan cong phan tan tu nhieu IP                                  |
|                                | Distributed attack from multiple IPs                           |
| `dictionary_attack.py`         | Tan cong tu dien voi danh sach mat khau pho bien               |
|                                | Dictionary attack with common password lists                   |
| `credential_stuffing.py`       | Tan cong nhoi thong tin dang nhap                              |
|                                | Credential stuffing attack                                     |
| `slow_brute_force.py`          | Tan cong brute-force cham de tranh bi phat hien                |
|                                | Slow brute-force designed to evade detection                   |

### 11.2. Chay mo phong thu cong / Run Simulations Manually

```bash
cd /opt/ssh-bruteforce-detection
source venv/bin/activate

# Tan cong brute-force co ban nhám vao localhost
# Basic brute-force targeting localhost
python attack_simulation/brute_force_basic.py --target localhost --port 22

# Tan cong tu dien / Dictionary attack
python attack_simulation/dictionary_attack.py --target localhost --port 22
```

### 11.3. Chay mo phong qua Docker / Run Simulations via Docker

```bash
cd /opt/ssh-bruteforce-detection/docker

# Chay container tan cong voi profile demo
# Run attacker container with demo profile
docker compose --profile demo run attacker python brute_force_basic.py --target ssh_target --port 22

# Hoac chay tu dien tan cong / Or run dictionary attack
docker compose --profile demo run attacker python dictionary_attack.py --target ssh_target --port 22
```

### 11.4. Quan sat ket qua / Observe Results

Trong khi mo phong dang chay, quan sat cac dich vu:

While simulations are running, observe the services:

```bash
# 1. Xem log API de thay canh bao / View API logs for alerts
docker compose logs -f api

# 2. Xem log detector / View detector logs
docker compose logs -f detector

# 3. Kiem tra Fail2Ban / Check Fail2Ban
sudo fail2ban-client status sshd-ai

# 4. Truy cap dashboard tai / Access dashboard at
# http://localhost:3000

# 5. Truy cap Kibana tai / Access Kibana at
# http://localhost:5601
```

---

## 12. Xu ly su co thuong gap / Troubleshooting Common Issues

### 12.1. Elasticsearch khong khoi dong / Elasticsearch Fails to Start

**Trieu chung / Symptom:** Elasticsearch thoat ngay sau khi khoi dong.

Elasticsearch exits immediately after starting.

**Nguyen nhan va giai phap / Cause and Solution:**

```bash
# Kiem tra log / Check logs
sudo journalctl -u elasticsearch --no-pager -n 50

# Nguyen nhan pho bien: thieu bo nho hoac vm.max_map_count qua thap
# Common cause: insufficient memory or vm.max_map_count too low
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Dam bao du bo nho / Ensure sufficient memory
# Chinh JVM heap trong /etc/elasticsearch/jvm.options
# Adjust JVM heap in /etc/elasticsearch/jvm.options
# -Xms512m
# -Xmx512m (khong vuot qua 50% RAM / do not exceed 50% of RAM)
```

### 12.2. Redis khong ket noi duoc / Redis Connection Refused

**Trieu chung / Symptom:** `ConnectionError: Error connecting to Redis on localhost:6379`

```bash
# Kiem tra Redis dang chay / Check Redis is running
sudo systemctl status redis-server

# Khoi dong lai / Restart
sudo systemctl restart redis-server

# Kiem tra binding / Check binding
grep "bind" /etc/redis/redis.conf
# Dam bao co: bind 127.0.0.1 ::1
# Ensure: bind 127.0.0.1 ::1
```

### 12.3. API Server khong khoi dong / API Server Fails to Start

**Trieu chung / Symptom:** `ModuleNotFoundError` hoac port bi chiem / or port occupied.

```bash
# Kiem tra moi truong ao dang duoc kich hoat / Verify venv is activated
which python  # Phai tro toi venv / Should point to venv

# Kiem tra port 8000 / Check port 8000
lsof -i :8000
# Neu bi chiem, tat tien trinh / If occupied, kill the process
kill -9 <PID>

# Khoi dong lai / Restart
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

### 12.4. Mo hinh chua duoc huan luyen / Models Not Trained

**Trieu chung / Symptom:** `FileNotFoundError: trained_models/isolation_forest.joblib`

```bash
# Chay pipeline huan luyen / Run training pipeline
python -m src.pipeline --mode full

# Kiem tra ket qua / Verify output
ls -la trained_models/
```

### 12.5. Web Dashboard khong ket noi duoc API / Web Dashboard Cannot Connect to API

**Trieu chung / Symptom:** Dashboard hien thi loi mang / Dashboard shows network error.

```bash
# Kiem tra API dang chay / Verify API is running
curl http://localhost:8000/

# Kiem tra CORS da duoc cau hinh / Check CORS is configured
# Trong configs/system_config.yaml, dam bao:
# In configs/system_config.yaml, ensure:
# cors_origins:
#   - "http://localhost:3000"
```

### 12.6. Docker: Container khong khoi dong / Docker: Container Fails to Start

```bash
# Xem log chi tiet / View detailed logs
docker compose logs <service-name>

# Xay dung lai image / Rebuild image
docker compose build --no-cache <service-name>

# Khoi dong lai tung dich vu / Restart individual service
docker compose restart <service-name>

# Xoa tat ca va bat dau lai / Remove all and start fresh
docker compose down -v
docker compose up -d
```

### 12.7. Fail2Ban khong chan IP / Fail2Ban Not Banning IPs

```bash
# Kiem tra trang thai jail / Check jail status
sudo fail2ban-client status sshd-ai

# Kiem tra filter hoat dong / Test filter
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd-ai.conf

# Kiem tra quyen truy cap file log / Check log file permissions
ls -la /var/log/auth.log

# Khoi dong lai Fail2Ban / Restart Fail2Ban
sudo systemctl restart fail2ban
```

### 12.8. Logstash khong gui du lieu den Elasticsearch / Logstash Not Sending Data to Elasticsearch

```bash
# Kiem tra Logstash log / Check Logstash logs
sudo journalctl -u logstash --no-pager -n 50

# Kiem tra Elasticsearch co nhan du lieu / Check Elasticsearch receives data
curl -s "http://localhost:9200/ssh-auth-logs-*/_count" | python3 -m json.tool

# Kiem tra quyen doc file log / Check log file read permissions
ls -la /var/log/auth.log
sudo chmod 644 /var/log/auth.log
```

---

## 13. Danh sach kiem tra xac nhan / Verification Checklist

Su dung danh sach sau de xac nhan he thong da duoc cai dat va hoat dong dung:

Use the following checklist to confirm the system is installed and operating correctly:

### 13.1. Ha tang / Infrastructure

| # | Hang muc / Item                                    | Lenh kiem tra / Verification Command                         | Ket qua mong doi / Expected Result |
|---|----------------------------------------------------|--------------------------------------------------------------|-------------------------------------|
| 1 | Python 3.11+ da cai dat                            | `python3.11 --version`                                       | `Python 3.11.x`                     |
| 2 | Node.js 18+ da cai dat                             | `node --version`                                             | `v18.x.x`                          |
| 3 | Redis dang chay                                    | `redis-cli ping`                                             | `PONG`                              |
| 4 | Elasticsearch dang chay                            | `curl -s http://localhost:9200`                               | JSON voi version 8.12.0            |
| 5 | Kibana dang chay                                   | `curl -s http://localhost:5601/api/status`                    | JSON voi status available           |
| 6 | Logstash dang chay                                 | `sudo systemctl status logstash`                              | `active (running)`                  |
| 7 | Fail2Ban dang chay                                 | `sudo fail2ban-client status`                                 | Danh sach jail bao gom sshd-ai     |

### 13.2. Ung dung / Application

| # | Hang muc / Item                                    | Lenh kiem tra / Verification Command                         | Ket qua mong doi / Expected Result |
|---|----------------------------------------------------|--------------------------------------------------------------|-------------------------------------|
| 8 | Thu vien Python da cai dat                         | `pip list \| grep scikit-learn`                               | `scikit-learn 1.3.x`               |
| 9 | Du lieu dataset ton tai                            | `ls Dataset/*.log`                                            | 2 file .log                         |
| 10| Mo hinh da duoc huan luyen                         | `ls trained_models/*.joblib`                                  | 4 file .joblib                      |
| 11| Ket qua pipeline da luu                            | `ls output/model_comparison.csv`                              | File ton tai                        |
| 12| API server phan hoi                                | `curl http://localhost:8000/`                                  | JSON response                       |
| 13| API docs co the truy cap                           | Truy cap `http://localhost:8000/docs`                         | Swagger UI hien thi                 |
| 14| Web dashboard hoat dong                            | Truy cap `http://localhost:3000`                               | Giao dien dashboard hien thi        |

### 13.3. Tich hop / Integration

| # | Hang muc / Item                                    | Lenh kiem tra / Verification Command                         | Ket qua mong doi / Expected Result |
|---|----------------------------------------------------|--------------------------------------------------------------|-------------------------------------|
| 15| Elasticsearch nhan du lieu tu Logstash             | `curl http://localhost:9200/ssh-auth-logs-*/_count`           | `count > 0`                         |
| 16| Fail2Ban jail sshd-ai hoat dong                   | `sudo fail2ban-client status sshd-ai`                        | Jail active, file list co auth.log  |
| 17| Redis co the nhan va gui tin nhan                  | `redis-cli publish ssh_alerts "test"`                         | `(integer) 1` neu co subscriber     |
| 18| Mo phong tan cong tao log                          | Chay script tan cong, kiem tra `/var/log/auth.log`           | Dong log Failed password moi        |

### 13.4. Docker (neu su dung) / Docker (if applicable)

| # | Hang muc / Item                                    | Lenh kiem tra / Verification Command                         | Ket qua mong doi / Expected Result |
|---|----------------------------------------------------|--------------------------------------------------------------|-------------------------------------|
| 19| Docker da cai dat                                  | `docker --version`                                            | `Docker version 24.x+`             |
| 20| Docker Compose da cai dat                          | `docker compose version`                                      | `v2.20+`                            |
| 21| Tat ca container dang chay                         | `docker compose ps` (trong thu muc docker/)                  | Tat ca dich vu: running/healthy     |
| 22| API container phan hoi                             | `curl http://localhost:8000/`                                  | JSON response                       |
| 23| Web container phan hoi                             | `curl http://localhost:3000`                                   | HTML response                       |
| 24| Elasticsearch container healthy                    | `docker compose exec elasticsearch curl localhost:9200`       | JSON voi version 8.12.0            |

---

## Phu luc A: Tham khao nhanh cac lenh / Appendix A: Quick Command Reference

### Khoi dong thu cong (khong Docker) / Manual Startup (without Docker)

```bash
# 1. Kich hoat moi truong / Activate environment
cd /opt/ssh-bruteforce-detection
source venv/bin/activate

# 2. Khoi dong cac dich vu nen / Start background services
sudo systemctl start elasticsearch redis-server logstash kibana fail2ban

# 3. Khoi dong API / Start API
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 &

# 4. Khoi dong detection worker / Start detection worker
python -m src.detection.realtime_pipeline &

# 5. Khoi dong web dashboard / Start web dashboard
cd src/web && npm run dev &
```

### Khoi dong Docker / Docker Startup

```bash
cd /opt/ssh-bruteforce-detection/docker

# Khoi dong tat ca / Start all
docker compose up -d

# Dung tat ca / Stop all
docker compose down

# Xem log / View logs
docker compose logs -f

# Chay tan cong demo / Run attack demo
docker compose --profile demo run attacker python brute_force_basic.py --target ssh_target --port 22
```

---

## Phu luc B: So do kien truc tong quan / Appendix B: Architecture Overview

```
                    +-------------------+
                    |   Web Dashboard   |
                    |  (React + Vite)   |
                    |   Port: 3000      |
                    +--------+----------+
                             |
                             | HTTP / WebSocket
                             v
                    +-------------------+
                    |   FastAPI Server  |
                    |   Port: 8000      |
                    +--+-----+------+---+
                       |     |      |
            +----------+  +--+--+  +----------+
            |             |     |             |
            v             v     v             v
    +-------+---+  +------+-+ +--+--------+  +--------+
    | Trained   |  | Redis  | | Elastic-  |  |Fail2Ban|
    | Models    |  | 6379   | | search    |  |        |
    | (.joblib) |  +------+-+ | 9200      |  +----+---+
    +-----------+         |   +-----+-----+       |
                          |         ^             |
              +-----------+    +----+----+        |
              |                |Logstash |        |
              v                +----+----+        |
    +---------+------+              ^             |
    | Real-time      |              |             |
    | Detection      +--> /var/log/auth.log <-----+
    | Worker         |
    +----------------+
```

---

*Tai lieu nay la mot phan cua bao cao khoa luan tot nghiep ve "He thong Phat hien Tan cong Brute-Force SSH su dung Hoc May".*

*This document is part of the thesis report on "SSH Brute-Force Attack Detection System using Machine Learning".*
