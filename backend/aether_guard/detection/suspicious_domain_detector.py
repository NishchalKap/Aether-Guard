from __future__ import annotations

import re
from urllib.parse import urlparse

from aether_guard.detection.base import Detector
from aether_guard.detection.registry import register_detector
from aether_guard.detection.signals import Signal


# Common legitimate domains that phishers often try to spoof
_LEGITIMATE_DOMAINS = {
    "microsoft.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "bankofamerica.com",
    "chase.com",
    "wellsfargo.com",
    "university.edu",  # placeholder for institution domains
}

# Suspicious TLDs often used in phishing
_SUSPICIOUS_TLDS = {
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".click",
    ".download",
}


def _clamp01(x: float) -> float:
    return 0.0 if x <= 0 else (1.0 if x >= 1 else x)


def _extract_domain_from_url(url: str) -> str | None:
    """Extract domain from a URL."""
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return None


def _is_suspicious_domain(domain: str) -> tuple[float, str | None]:
    """
    Analyze domain for suspicious characteristics.

    Returns:
        (confidence_score, evidence_string)
    """
    if not domain:
        return 0.0, None

    score = 0.0
    reasons: list[str] = []

    # Check for suspicious TLD
    if any(tld in domain for tld in _SUSPICIOUS_TLDS):
        score += 0.4
        reasons.append("Uses a suspicious top-level domain")

    # Check for typosquatting-like patterns (e.g., microsoftt.com, gooogle.com)
    domain_lower = domain.lower()
    for legit in _LEGITIMATE_DOMAINS:
        legit_base = legit.split(".")[0]
        if legit_base in domain_lower and domain_lower != legit:
            # Check for character insertion/deletion
            if len(domain_lower) - len(legit_base) <= 2:
                score += 0.5
                reasons.append(f"Domain resembles '{legit}' but may be a typo/spoof")

    # IP address instead of domain
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        score += 0.6
        reasons.append("Uses IP address instead of domain name")

    # Very long domain (often used to hide malicious content)
    if len(domain) > 40:
        score += 0.3
        reasons.append("Unusually long domain name")

    # Many subdomains (potential obfuscation)
    if domain.count(".") >= 4:
        score += 0.3
        reasons.append("Contains many subdomains")

    confidence = _clamp01(score)
    evidence = "; ".join(reasons) if reasons and confidence >= 0.4 else None

    return confidence, evidence


@register_detector
class SuspiciousDomainDetector(Detector):
    """
    Detector for suspicious domain characteristics.

    Analyzes domains from links and sender addresses to identify:
    - Typosquatting attempts
    - Suspicious TLDs
    - IP-based domains
    - Obfuscation techniques
    """

    name = "suspicious_domain_detector_v1"

    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        all_domains: set[str] = set()

        # Extract domain from sender
        if sender:
            sender_domain = sender.split("@")[-1].lower() if "@" in sender else None
            if sender_domain:
                all_domains.add(sender_domain)

        # Extract domains from links
        for link in links or []:
            domain = _extract_domain_from_url(link)
            if domain:
                all_domains.add(domain)

        # Also extract from text URLs
        url_pattern = r"https?://([^\s/\)>\"]+)"
        text_urls = re.findall(url_pattern, text, flags=re.IGNORECASE)
        for url_part in text_urls:
            domain = _extract_domain_from_url(f"http://{url_part}")
            if domain:
                all_domains.add(domain)

        if not all_domains:
            return []

        # Score each domain and take the maximum
        max_confidence = 0.0
        max_evidence: str | None = None

        for domain in all_domains:
            conf, ev = _is_suspicious_domain(domain)
            if conf > max_confidence:
                max_confidence = conf
                max_evidence = ev

        return [
            Signal(
                name="suspicious_domain",
                confidence=max_confidence,
                source=self.name,
                evidence=max_evidence,
            )
        ]

