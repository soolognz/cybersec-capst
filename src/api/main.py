"""
FastAPI Application - SSH Brute-Force Detection System API.

Provides REST endpoints and WebSocket for the monitoring dashboard.
"""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.api.config import get_settings
from src.detection.alert_manager import AlertManager
from src.detection.prevention import Fail2BanIntegration
from src.models.dynamic_threshold import DynamicThreshold

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

settings = get_settings()

# Global components
alert_manager = AlertManager(
    smtp_host=settings.smtp_host,
    smtp_port=settings.smtp_port,
    smtp_user=settings.smtp_user,
    smtp_password=settings.smtp_password,
    alert_email_to=settings.alert_email_to,
)

fail2ban = Fail2BanIntegration(
    jail_name=settings.fail2ban_jail,
    ban_time=settings.fail2ban_ban_time,
    enabled=settings.fail2ban_enabled,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    logger.info("SSH Brute-Force Detection API starting...")
    # Load model comparison results if available
    output_dir = Path(settings.output_dir)
    if (output_dir / 'model_comparison.csv').exists():
        logger.info("Model comparison results available")
    yield
    logger.info("API shutting down...")


app = FastAPI(
    title="SSH Brute-Force Detection API",
    description="AI-powered SSH brute-force detection with early prediction",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Dashboard Endpoints
# ============================================================

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """Get summary statistics for the dashboard."""
    import pandas as pd
    output_dir = Path(settings.output_dir)

    stats = {
        "alert_stats": alert_manager.get_stats(),
        "prevention_stats": fail2ban.get_stats(),
    }

    # Load model comparison if available
    comparison_path = output_dir / 'model_comparison.csv'
    if comparison_path.exists():
        df = pd.read_csv(comparison_path, index_col=0)
        stats["model_performance"] = df.to_dict(orient='index')

    # Load feature importance
    importance_path = output_dir / 'feature_importance.csv'
    if importance_path.exists():
        df = pd.read_csv(importance_path)
        stats["feature_importance"] = df.to_dict(orient='records')

    # Load dynamic threshold results
    threshold_path = output_dir / 'dynamic_threshold_results.json'
    if threshold_path.exists():
        with open(threshold_path) as f:
            stats["threshold_results"] = json.load(f)

    return stats


@app.get("/api/dashboard/model-comparison")
async def get_model_comparison():
    """Get detailed model comparison data."""
    import pandas as pd
    comparison_path = Path(settings.output_dir) / 'model_comparison.csv'

    if not comparison_path.exists():
        raise HTTPException(status_code=404, detail="Model comparison not available. Run pipeline first.")

    df = pd.read_csv(comparison_path, index_col=0)
    return {
        "comparison": df.to_dict(orient='index'),
        "best_model": df['F1-Score'].idxmax(),
    }


# ============================================================
# Alert Endpoints
# ============================================================

@app.get("/api/alerts")
async def get_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    threat_level: Optional[str] = None,
):
    """Get paginated alert history."""
    return alert_manager.get_alerts(page=page, page_size=page_size, threat_level=threat_level)


@app.get("/api/alerts/stats")
async def get_alert_stats():
    """Get alert statistics."""
    return alert_manager.get_stats()


# ============================================================
# Prevention Endpoints
# ============================================================

@app.get("/api/prevention/banned")
async def get_banned_ips():
    """Get list of currently banned IPs."""
    return {"banned_ips": fail2ban.get_banned_ips()}


@app.get("/api/prevention/watchlist")
async def get_watchlist():
    """Get current watchlist."""
    return {"watchlist": fail2ban.get_watchlist()}


class BanRequest(BaseModel):
    ip: str
    reason: str = "Manual ban"


@app.post("/api/prevention/ban")
async def ban_ip(request: BanRequest):
    """Manually ban an IP."""
    result = await fail2ban.ban_ip(request.ip, reason=request.reason)
    return {"result": result}


@app.post("/api/prevention/unban")
async def unban_ip(request: BanRequest):
    """Unban an IP."""
    result = await fail2ban.unban_ip(request.ip)
    return {"result": result}


@app.get("/api/prevention/stats")
async def get_prevention_stats():
    """Get prevention statistics."""
    return fail2ban.get_stats()


# ============================================================
# Threshold Configuration
# ============================================================

class ThresholdConfig(BaseModel):
    alpha: float = 0.3
    base_percentile: float = 95.0
    sensitivity_factor: float = 1.5
    lookback_window: int = 100


@app.get("/api/threshold/config")
async def get_threshold_config():
    """Get current threshold configuration."""
    return {
        "alpha": 0.3,
        "base_percentile": 95.0,
        "sensitivity_factor": 1.5,
        "lookback_window": 100,
    }


# ============================================================
# WebSocket for Real-Time Updates
# ============================================================

@app.websocket("/api/ws/realtime")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time anomaly score and alert streaming."""
    await websocket.accept()
    alert_manager.register_websocket(websocket)

    try:
        while True:
            # Keep connection alive, receive any client messages
            data = await websocket.receive_text()
            # Handle client commands if needed
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        alert_manager.unregister_websocket(websocket)


# ============================================================
# Health Check
# ============================================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "models_loaded": Path(settings.model_dir).exists(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)
