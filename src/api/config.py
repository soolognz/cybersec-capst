"""
Application configuration loaded from environment variables and config files.
"""

import os
from pathlib import Path
from pydantic import BaseModel
from typing import List, Optional


class Settings(BaseModel):
    """Application settings."""

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5601"]

    # Elasticsearch
    es_hosts: List[str] = ["http://localhost:9200"]
    es_index_prefix: str = "ssh-auth-logs"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0

    # Detection
    log_path: str = "/var/log/auth.log"
    scoring_interval: int = 10
    window_minutes: int = 5

    # Email alerts
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_email_to: str = ""

    # Fail2Ban
    fail2ban_enabled: bool = True
    fail2ban_jail: str = "sshd-ai"
    fail2ban_ban_time: int = 3600

    # Paths
    model_dir: str = "trained_models"
    dataset_dir: str = "Dataset"
    output_dir: str = "output"

    # Kibana
    kibana_url: str = "http://localhost:5601"

    class Config:
        env_prefix = "SSH_AI_"


def get_settings() -> Settings:
    """Load settings from environment variables."""
    return Settings(
        smtp_user=os.getenv("SMTP_USER", ""),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        alert_email_to=os.getenv("ALERT_EMAIL_TO", ""),
        redis_host=os.getenv("REDIS_HOST", "localhost"),
        es_hosts=os.getenv("ES_HOSTS", "http://localhost:9200").split(","),
    )
