"""Tests for detector modules."""

import pytest

from aether_guard.detection.signals import Signal
from aether_guard.detection.urgent_language_detector import UrgentLanguageDetector
from aether_guard.detection.credential_request_detector import CredentialRequestDetector
from aether_guard.detection.url_shortener_detector import UrlShortenerDetector


class TestUrgentLanguageDetector:
    """Tests for UrgentLanguageDetector."""

    def test_detects_urgent_language(self):
        """Test that urgent language is detected."""
        detector = UrgentLanguageDetector()
        signals = detector.analyze(
            text="URGENT: Your account will be locked immediately!",
            sender=None,
            links=[],
        )

        assert len(signals) > 0
        assert any(s.name == "urgent_language" for s in signals)
        urgent_signal = next(s for s in signals if s.name == "urgent_language")
        assert urgent_signal.confidence > 0.0

    def test_no_urgent_language(self):
        """Test that normal text doesn't trigger urgent detection."""
        detector = UrgentLanguageDetector()
        signals = detector.analyze(
            text="Hello, how are you today?",
            sender=None,
            links=[],
        )

        urgent_signals = [s for s in signals if s.name == "urgent_language"]
        if urgent_signals:
            assert urgent_signals[0].confidence < 0.5


class TestCredentialRequestDetector:
    """Tests for CredentialRequestDetector."""

    def test_detects_credential_request(self):
        """Test that credential requests are detected."""
        detector = CredentialRequestDetector()
        signals = detector.analyze(
            text="Please verify your account by clicking here and entering your password.",
            sender=None,
            links=[],
        )

        assert len(signals) > 0
        assert any(s.name == "credential_request" for s in signals)
        cred_signal = next(s for s in signals if s.name == "credential_request")
        assert cred_signal.confidence > 0.0

    def test_no_credential_request(self):
        """Test that normal text doesn't trigger credential detection."""
        detector = CredentialRequestDetector()
        signals = detector.analyze(
            text="Thanks for your email. I'll get back to you soon.",
            sender=None,
            links=[],
        )

        cred_signals = [s for s in signals if s.name == "credential_request"]
        if cred_signals:
            assert cred_signals[0].confidence < 0.5


class TestUrlShortenerDetector:
    """Tests for UrlShortenerDetector."""

    def test_detects_url_shortener(self):
        """Test that URL shorteners are detected."""
        detector = UrlShortenerDetector()
        signals = detector.analyze(
            text="Check this out: https://bit.ly/abc123",
            sender=None,
            links=["https://bit.ly/abc123"],
        )

        assert len(signals) > 0
        assert any(s.name == "url_shortener" for s in signals)
        shortener_signal = next(s for s in signals if s.name == "url_shortener")
        assert shortener_signal.confidence > 0.0

    def test_no_url_shortener(self):
        """Test that regular URLs don't trigger shortener detection."""
        detector = UrlShortenerDetector()
        signals = detector.analyze(
            text="Visit https://example.com/page",
            sender=None,
            links=["https://example.com/page"],
        )

        shortener_signals = [s for s in signals if s.name == "url_shortener"]
        assert len(shortener_signals) == 0


class TestSignalNormalization:
    """Tests for Signal normalization."""

    def test_signal_clamping(self):
        """Test that signal confidence is clamped to [0, 1]."""
        signal = Signal(
            name="test",
            confidence=1.5,  # Over 1.0
            source="test",
        )

        normalized = signal.normalized()
        assert normalized.confidence == 1.0

        signal_negative = Signal(
            name="test",
            confidence=-0.5,  # Under 0.0
            source="test",
        )

        normalized_neg = signal_negative.normalized()
        assert normalized_neg.confidence == 0.0

