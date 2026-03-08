from __future__ import annotations

import re

from aether_guard.detection.base import Detector
from aether_guard.detection.registry import register_detector
from aether_guard.detection.signals import Signal


_CREDENTIAL_PATTERNS = [
    r"\bverify\b.*\baccount\b",
    r"\breset\b.*\bpassword\b",
    r"\bchange\b.*\bpassword\b",
    r"\blog(?:\s?in|in)\b.*\b(?:now|here|immediately)\b",
    r"\bupdate\b.*\b(?:payment|billing|information)\b",
    r"\b(?:ssn|social security)\b",
    r"\bconfirm\b.*\b(?:identity|account|email)\b",
    r"\bvalidate\b.*\b(?:account|credentials)\b",
    r"\benter\b.*\b(?:password|credentials|login)\b",
    r"\bprovide\b.*\b(?:password|pin|security)\b",
]


def _clamp01(x: float) -> float:
    return 0.0 if x <= 0 else (1.0 if x >= 1 else x)


def _count_credential_matches(text: str) -> int:
    """Count how many credential request patterns match in the text."""
    matches = 0
    text_lower = text.lower()
    for pattern in _CREDENTIAL_PATTERNS:
        if re.search(pattern, text_lower):
            matches += 1
    return matches


@register_detector
class CredentialRequestDetector(Detector):
    """
    Specialized detector for credential/password/account verification requests.

    This detector identifies patterns that suggest the message is asking
    the recipient to provide login credentials, reset passwords, or verify accounts.
    """

    name = "credential_request_detector_v1"

    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        text_norm = (text or "").strip()
        if not text_norm:
            return []

        match_count = _count_credential_matches(text_norm)
        # Normalize: 0 matches = 0.0, 1 match = 0.4, 2+ matches = 0.7-1.0
        confidence = _clamp01(0.35 * match_count + 0.1 * min(match_count, 3))

        evidence = None
        if confidence >= 0.5:
            evidence = f"Detected {match_count} pattern(s) suggesting a request for credentials or account verification."

        return [
            Signal(
                name="credential_request",
                confidence=confidence,
                source=self.name,
                evidence=evidence,
            )
        ]

