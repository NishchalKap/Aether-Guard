"""Tests for API endpoints."""

import pytest
from fastapi.testclient import TestClient

from aether_guard.main import app

client = TestClient(app)


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_endpoint(self):
        """Test that health endpoint returns OK."""
        response = client.get("/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "service" in data
        assert "timestamp_utc" in data


class TestEmailAnalysisEndpoint:
    """Tests for email analysis endpoint."""

    def test_analyze_email_basic(self):
        """Test basic email analysis."""
        payload = {
            "email_text": "Hello, this is a test email.",
            "sender": "test@example.com",
            "links": [],
        }

        response = client.post("/v1/analyze/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert "risk_score" in data
        assert "severity" in data
        assert "alert" in data
        assert "signals" in data
        assert data["risk_score"] >= 0
        assert data["risk_score"] <= 100
        assert data["severity"] in ("low", "medium", "high")

    def test_analyze_email_phishing(self):
        """Test phishing email detection."""
        payload = {
            "email_text": "URGENT: Your account will be locked. Verify your password here: https://example.com/login",
            "sender": "it-support@gmail.com",
            "links": ["https://example.com/login"],
        }

        response = client.post("/v1/analyze/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        # Should detect higher risk
        assert data["risk_score"] > 30  # At least medium risk
        assert len(data["signals"]) > 0

    def test_analyze_email_validation(self):
        """Test that invalid input is rejected."""
        # Missing required field
        payload = {}

        response = client.post("/v1/analyze/email", json=payload)
        assert response.status_code == 422  # Validation error


class TestDashboardEndpoints:
    """Tests for dashboard endpoints."""

    def test_list_alerts(self):
        """Test alerts listing endpoint."""
        response = client.get("/v1/alerts")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_risk_stats(self):
        """Test risk statistics endpoint."""
        response = client.get("/v1/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_alerts" in data
        assert "by_severity" in data
        assert isinstance(data["by_severity"], dict)

    def test_detector_telemetry(self):
        """Test detector telemetry endpoint."""
        response = client.get("/v1/detectors")
        assert response.status_code == 200
        data = response.json()
        assert "total_detectors" in data
        assert "total_executions" in data
        assert "detectors" in data

