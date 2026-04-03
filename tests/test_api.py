"""Tests for FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient
from src.api.main import app


@pytest.fixture
def client():
    return TestClient(app)


class TestHealthCheck:
    def test_health_endpoint(self, client):
        response = client.get('/api/health')
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'
        assert 'version' in data

class TestDashboard:
    def test_stats_endpoint(self, client):
        response = client.get('/api/dashboard/stats')
        assert response.status_code == 200
        data = response.json()
        assert 'alert_stats' in data
        assert 'prevention_stats' in data

class TestAlerts:
    def test_get_alerts(self, client):
        response = client.get('/api/alerts')
        assert response.status_code == 200
        data = response.json()
        assert 'alerts' in data
        assert 'total' in data

    def test_alert_stats(self, client):
        response = client.get('/api/alerts/stats')
        assert response.status_code == 200

    def test_alerts_pagination(self, client):
        response = client.get('/api/alerts?page=1&page_size=10')
        assert response.status_code == 200

class TestPrevention:
    def test_get_banned(self, client):
        response = client.get('/api/prevention/banned')
        assert response.status_code == 200
        assert 'banned_ips' in response.json()

    def test_get_watchlist(self, client):
        response = client.get('/api/prevention/watchlist')
        assert response.status_code == 200

    def test_prevention_stats(self, client):
        response = client.get('/api/prevention/stats')
        assert response.status_code == 200

class TestThreshold:
    def test_get_config(self, client):
        response = client.get('/api/threshold/config')
        assert response.status_code == 200
        data = response.json()
        assert 'alpha' in data
        assert 'base_percentile' in data
