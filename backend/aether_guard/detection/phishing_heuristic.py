from __future__ import annotations

import re
from urllib.parse import urlparse

from aether_guard.detection.base import Detector
from aether_guard.detection.registry import register_detector
from aether_guard.detection.signals import Signal


_URGENT_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bact\s+now\b",
    r"\bwithin\s+\d+\s+(minutes?|hours?)\b",
    r"\byour\s+account\s+will\s+be\s+(?:closed|disabled|locked)\b",
]

_CREDENTIAL_PATTERNS = [
    r"\bverify\b.*\baccount\b",
    r"\breset\b.*\bpassword\b",
    r"\blog(?:\s?in|in)\b",
    r"\bupdate\b.*\bpayment\b",
    r"\b(ssn|social security)\b",
]

_IMP_PERSONATION_PATTERNS = [
    r"\b(it\s+support|help\s+desk|service\s+desk)\b",
    r"\buniversity\b.*\bsecurity\b",
    r"\b(microsoft|google|apple)\b.*\bsecurity\b",
]


def _clamp01(x: float) -> float:
    return 0.0 if x <= 0 else (1.0 if x >= 1 else x)


def _contains_any(patterns: list[str], text: str) -> float:
    matches = 0
    for p in patterns:
        if re.search(p, text, flags=re.IGNORECASE):
            matches += 1
    # Normalize: 0, 0.5, 1.0 for 0/1/2+ hits
    return _clamp01(matches / 2.0)


def _count_urls(text: str, links: list[str]) -> int:
    # Lightweight URL extraction (no heavy parsing): include explicit links list too
    urls = re.findall(r"https?://[^\s)>\"]+", text, flags=re.IGNORECASE)
    return len(set(urls + (links or [])))


def _suspicious_url_score(url: str) -> float:
    """
    Heuristic URL suspicion score in [0,1] based on shape/entropy-like indicators.
    This is NOT reputation-based (no external calls) to preserve privacy/offline mode.
    """

    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        path = p.path or ""
    except Exception:
        return 0.3

    if not host:
        return 0.0

    score = 0.0

    # IP-based host is often used in phishing
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 0.6

    # Lots of subdomains / long hostnames
    if host.count(".") >= 3:
        score += 0.25
    if len(host) >= 28:
        score += 0.2

    # Punycode / IDN trick indicator
    if "xn--" in host:
        score += 0.35

    # URL shorteners are ambiguous; treat as mildly suspicious
    if host in {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}:
        score += 0.25

    # Phishy keyword in path/query
    if re.search(r"(login|verify|password|auth|update|secure)", path, flags=re.IGNORECASE):
        score += 0.2

    return _clamp01(score)


@register_detector
class PhishingHeuristicDetector(Detector):
    """
    First-pass phishing detector.

    Design intent:
    - Fast, local, explainable
    - Produces stable signals the risk engine can consume
    - Later we can swap/augment with ML (e.g., fine-tuned transformer on ROCm)
    """

    name = "phishing_heuristic_v1"

    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        text_norm = (text or "").strip()
        sender_norm = (sender or "").strip().lower()
        links = links or []

        urgent = _contains_any(_URGENT_PATTERNS, text_norm)
        credential = _contains_any(_CREDENTIAL_PATTERNS, text_norm)
        impersonation = _contains_any(_IMP_PERSONATION_PATTERNS, text_norm)

        url_count = _count_urls(text_norm, links)
        url_density = _clamp01(url_count / 5.0)  # 0..1 for 0..5+ links

        url_susp = 0.0
        all_urls = set(re.findall(r"https?://[^\s)>\"]+", text_norm, flags=re.IGNORECASE) + links)
        if all_urls:
            url_susp = max(_suspicious_url_score(u) for u in all_urls)

        # Sender mismatch is tricky; keep lightweight (institution can customize later)
        external_sender = 0.0
        if sender_norm and any(x in sender_norm for x in ["@gmail.", "@outlook.", "@yahoo."]):
            # common personal domains; not inherently bad, but for "IT Support" style text it matters
            external_sender = 1.0 if impersonation > 0 else 0.25

        return [
            Signal(
                name="urgent_language",
                confidence=urgent,
                source=self.name,
                evidence="Urgent/time-pressure phrasing patterns were detected." if urgent >= 0.5 else None,
            ),
            Signal(
                name="credential_request",
                confidence=credential,
                source=self.name,
                evidence="Patterns suggesting a request to log in/reset a password/verify an account were detected."
                if credential >= 0.5
                else None,
            ),
            Signal(
                name="impersonation_language",
                confidence=impersonation,
                source=self.name,
                evidence="Language resembling trusted IT/security support impersonation was detected."
                if impersonation >= 0.5
                else None,
            ),
            Signal(
                name="url_density",
                confidence=url_density,
                source=self.name,
                evidence="The message contains multiple links." if url_density >= 0.6 else None,
            ),
            Signal(
                name="suspicious_url_shape",
                confidence=url_susp,
                source=self.name,
                evidence="At least one link has a suspicious structure (e.g., many subdomains, IP host, or login-like path)."
                if url_susp >= 0.4
                else None,
            ),
            Signal(
                name="external_sender_indicator",
                confidence=external_sender,
                source=self.name,
                evidence="Sender appears to be from a personal email domain while claiming an organization."
                if external_sender >= 0.8
                else None,
            ),
        ]


