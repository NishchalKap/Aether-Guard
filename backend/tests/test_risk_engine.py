"""Tests for risk engine."""

import pytest

from aether_guard.detection.signals import Signal
from aether_guard.services.risk_engine import RiskEngine


class TestRiskEngine:
    """Tests for RiskEngine."""

    def test_basic_scoring(self):
        """Test basic risk scoring."""
        engine = RiskEngine()

        signals = [
            Signal(
                name="credential_request",
                confidence=0.8,
                source="test",
            ),
            Signal(
                name="urgent_language",
                confidence=0.6,
                source="test",
            ),
        ]

        assessment = engine.score(signals=signals)

        assert assessment.risk_score >= 0
        assert assessment.risk_score <= 100
        assert assessment.severity in ("LOW", "MEDIUM", "HIGH")
        assert "credential_request" in assessment.signals
        assert "urgent_language" in assessment.signals

    def test_high_risk_detection(self):
        """Test that high confidence signals produce high risk scores."""
        engine = RiskEngine()

        signals = [
            Signal(
                name="credential_request",
                confidence=0.95,
                source="test",
            ),
            Signal(
                name="ml_phishing_probability",
                confidence=0.90,
                source="test",
            ),
        ]

        assessment = engine.score(signals=signals, low_max=29, medium_max=69)

        # Should be HIGH risk with strong signals
        assert assessment.risk_score > 50  # At least medium-high
        assert "credential_request" in assessment.contributions
        assert "ml_phishing_probability" in assessment.contributions

    def test_low_risk_detection(self):
        """Test that low confidence signals produce low risk scores."""
        engine = RiskEngine()

        signals = [
            Signal(
                name="url_density",
                confidence=0.1,
                source="test",
            ),
        ]

        assessment = engine.score(signals=signals)

        assert assessment.risk_score < 50  # Should be low
        assert assessment.severity in ("LOW", "MEDIUM")

    def test_hybrid_scoring(self):
        """Test hybrid heuristic + ML scoring."""
        engine = RiskEngine()

        # Mix of heuristic and ML signals
        signals = [
            Signal(
                name="credential_request",  # Heuristic
                confidence=0.7,
                source="heuristic",
            ),
            Signal(
                name="ml_phishing_probability",  # ML
                confidence=0.8,
                source="ml",
            ),
        ]

        assessment = engine.score(signals=signals)

        assert assessment.risk_score >= 0
        assert assessment.risk_score <= 100
        # Should have both heuristic and ML scores
        assert assessment.heuristic_score is not None or assessment.ml_score is not None

