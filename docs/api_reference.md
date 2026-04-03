# API Reference / Tài liệu API

**Base URL**: `http://localhost:8000`

## Health Check

### GET /api/health
```json
Response: { "status": "healthy", "version": "1.0.0", "models_loaded": true }
```

## Dashboard

### GET /api/dashboard/stats
Returns summary statistics including model performance, alerts, prevention stats.

### GET /api/dashboard/model-comparison
Returns detailed model comparison data.
```json
Response: {
  "comparison": {
    "Isolation Forest": { "Accuracy": 0.8076, "Precision": 0.7959, ... },
    "LOF": { ... },
    "One-Class SVM": { ... }
  },
  "best_model": "One-Class SVM"
}
```

## Alerts

### GET /api/alerts
Query params: `page` (int), `page_size` (int), `threat_level` (string: critical|warning)
```json
Response: {
  "alerts": [...],
  "total": 100,
  "page": 1,
  "page_size": 50,
  "total_pages": 2
}
```

### GET /api/alerts/stats
```json
Response: { "total_alerts": 100, "critical": 20, "warning": 80 }
```

## Prevention

### GET /api/prevention/banned
Returns list of currently banned IPs.

### GET /api/prevention/watchlist
Returns current watchlist (early warning IPs).

### POST /api/prevention/ban
```json
Request: { "ip": "192.168.1.100", "reason": "Manual ban" }
Response: { "result": "IP 192.168.1.100 banned via Fail2Ban" }
```

### POST /api/prevention/unban
```json
Request: { "ip": "192.168.1.100" }
Response: { "result": "IP 192.168.1.100 unbanned" }
```

## Threshold Configuration

### GET /api/threshold/config
```json
Response: {
  "alpha": 0.3,
  "base_percentile": 95.0,
  "sensitivity_factor": 1.5,
  "lookback_window": 100
}
```

### PUT /api/threshold/config
Update dynamic threshold parameters.

## WebSocket

### WS /api/ws/realtime
Real-time anomaly score and alert streaming.
```json
Messages from server:
{
  "id": "ALT-000001",
  "timestamp": "2026-03-27T12:00:00",
  "source_ip": "192.168.1.100",
  "threat_level": "critical",
  "anomaly_score": 0.8543,
  "ewma_score": 0.7234,
  "message": "CRITICAL: Brute-force attack detected from 192.168.1.100"
}
```
