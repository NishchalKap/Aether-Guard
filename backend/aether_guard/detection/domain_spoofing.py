from __future__ import annotations

import re
from urllib.parse import urlparse

from aether_guard.detection.base import Detector
from aether_guard.detection.registry import register_detector
from aether_guard.detection.signals import Signal


def _extract_sender_domain(sender: str | None) -> str | None:
    if not sender:
        return None
    s = sender.strip().lower()
    # Very lightweight: find last @... token
    m = re.search(r"@([a-z0-9.\-]+\.[a-z]{2,})", s)
    if not m:
        return None
    return m.group(1)


def _extract_link_domains(text: str, links: list[str]) -> set[str]:
    urls = set(links or [])
    urls.update(re.findall(r"https?://[^\s)>\"]+", text or "", flags=re.IGNORECASE))
    out: set[str] = set()
    for u in urls:
        try:
            host = (urlparse(u).hostname or "").lower()
        except Exception:
            host = ""
        if host:
            out.add(host)
    return out


@register_detector
class DomainSpoofingDetector(Detector):
    """
    Detects simple sender/link domain inconsistencies that often show spoofing.

    Privacy-first:
    - Emits only derived indicators; does not store sender/link strings.
    """

    name = "domain_spoofing_v1"

    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        sender_domain = _extract_sender_domain(sender)
        link_domains = _extract_link_domains(text, links)

        if not sender_domain or not link_domains:
            return [Signal(name="sender_link_domain_mismatch", confidence=0.0, source=self.name)]

        # If sender is "university.edu" but links go to unrelated domains, raise mismatch.
        mismatch = 0.0
        if any(d.endswith(sender_domain) for d in link_domains):
            mismatch = 0.0
        else:
            mismatch = 0.7

        evidence = None
        if mismatch >= 0.7:
            evidence = "Sender domain and link domain(s) do not appear to match."

        return [Signal(name="sender_link_domain_mismatch", confidence=mismatch, source=self.name, evidence=evidence)]


