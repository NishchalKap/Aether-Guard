from __future__ import annotations

import re

from aether_guard.detection.base import Detector
from aether_guard.detection.registry import register_detector
from aether_guard.detection.signals import Signal


_URGENT_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bact\s+now\b",
    r"\basap\b",
    r"\brush\b",
    r"\bwithin\s+\d+\s+(minutes?|hours?)\b",
    r"\byour\s+account\s+will\s+be\s+(?:closed|disabled|locked|suspended)\b",
    r"\bexpir(?:es?|ing)\s+(?:soon|today|tomorrow)\b",
    r"\bfinal\s+notice\b",
    r"\baction\s+required\b",
    r"\bverify\s+now\b",
    r"\bclick\s+here\s+immediately\b",
]


def _clamp01(x: float) -> float:
    return 0.0 if x <= 0 else (1.0 if x >= 1 else x)


def _count_urgent_matches(text: str) -> int:
    """Count how many urgent patterns match in the text."""
    matches = 0
    text_lower = text.lower()
    for pattern in _URGENT_PATTERNS:
        if re.search(pattern, text_lower):
            matches += 1
    return matches


@register_detector
class UrgentLanguageDetector(Detector):
    """
    Specialized detector for urgent/time-pressure language patterns.

    This detector focuses specifically on identifying language that creates
    artificial urgency, which is a common phishing tactic.
    """

    name = "urgent_language_detector_v1"

    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        text_norm = (text or "").strip()
        if not text_norm:
            return []

        match_count = _count_urgent_matches(text_norm)
        # Normalize: 0 matches = 0.0, 1-2 matches = 0.4-0.6, 3+ matches = 0.8-1.0
        confidence = _clamp01(0.2 * match_count + 0.2 * min(match_count, 3))

        evidence = None
        if confidence >= 0.5:
            evidence = f"Detected {match_count} urgent language pattern(s) that create time pressure."

        return [
            Signal(
                name="urgent_language",
                confidence=confidence,
                source=self.name,
                evidence=evidence,
            )
        ]

