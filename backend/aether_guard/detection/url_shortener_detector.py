from __future__ import annotations

import re
from urllib.parse import urlparse

from aether_guard.detection.base import Detector
from aether_guard.detection.registry import register_detector
from aether_guard.detection.signals import Signal


# Known URL shortener domains
_URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "short.link",
    "ow.ly",
    "buff.ly",
    "goo.gl",
    "rebrand.ly",
    "tiny.cc",
    "shorturl.at",
    "v.gd",
    "shorte.st",
    "adf.ly",
    "bc.vc",
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


@register_detector
class UrlShortenerDetector(Detector):
    """
    Detector for URL shortener services.

    URL shorteners are not inherently malicious, but they:
    - Hide the true destination
    - Are commonly used in phishing campaigns
    - Make it harder for users to verify link safety

    This detector flags messages containing shortened URLs as potentially risky.
    """

    name = "url_shortener_detector_v1"

    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        all_urls: set[str] = set()

        # Collect URLs from links parameter
        for link in links or []:
            all_urls.add(link)

        # Extract URLs from text
        url_pattern = r"https?://[^\s\)>\"]+"
        text_urls = re.findall(url_pattern, text, flags=re.IGNORECASE)
        all_urls.update(text_urls)

        if not all_urls:
            return []

        # Check how many URLs are shorteners
        shortener_count = 0
        total_urls = len(all_urls)

        for url in all_urls:
            domain = _extract_domain_from_url(url)
            if domain and domain in _URL_SHORTENERS:
                shortener_count += 1

        if shortener_count == 0:
            return []

        # Confidence increases with the ratio of shorteners to total URLs
        # Also increases if ALL URLs are shorteners (more suspicious)
        ratio = shortener_count / total_urls if total_urls > 0 else 0.0
        confidence = _clamp01(ratio * 0.7 + (0.3 if shortener_count == total_urls else 0.0))

        evidence = None
        if confidence >= 0.3:
            if shortener_count == total_urls:
                evidence = f"All {shortener_count} link(s) use URL shortener services, hiding true destinations."
            else:
                evidence = f"{shortener_count} of {total_urls} link(s) use URL shortener services."

        return [
            Signal(
                name="url_shortener",
                confidence=confidence,
                source=self.name,
                evidence=evidence,
            )
        ]

