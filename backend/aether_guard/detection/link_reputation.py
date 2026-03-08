from __future__ import annotations

import re
from urllib.parse import urlparse

from aether_guard.detection.base import Detector
from aether_guard.detection.registry import register_detector
from aether_guard.detection.signals import Signal


@register_detector
class LinkReputationDetector(Detector):
    """
    Privacy-first link risk detector (offline heuristic).

    Later upgrades:
    - Optional institutional on-prem lookup (safe list / known-bad list)
    - Sandboxed detonation / redirect tracing in controlled environment
    """

    name = "link_reputation_v1"

    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        # Only use URLs; avoid persisting raw content.
        extracted = re.findall(r"https?://[^\s)>\"]+", text or "", flags=re.IGNORECASE)
        urls = list({*(links or []), *extracted})

        if not urls:
            return [Signal(name="has_links", confidence=0.0, source=self.name)]

        scores: list[float] = []
        evidences: list[str] = []
        for u in urls:
            try:
                p = urlparse(u)
                host = (p.hostname or "").lower()
            except Exception:
                host = ""

            s = 0.0
            if not host:
                s = 0.3
                evidences.append("A link could not be parsed cleanly.")
            else:
                if host.endswith((".zip", ".mov", ".top", ".click")):
                    s += 0.25
                    evidences.append("The link domain uses a TLD commonly abused in scams.")
                if "xn--" in host:
                    s += 0.35
                    evidences.append("The link uses punycode (IDN), which is sometimes used for lookalike domains.")
                if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
                    s += 0.6
                    evidences.append("The link uses a raw IP address instead of a domain name.")
                if host.count(".") >= 3:
                    s += 0.2
                    evidences.append("The link has many subdomains, which can be used to mimic trusted brands.")

            scores.append(min(1.0, s))

        risk = max(scores) if scores else 0.0
        evidence = None
        if evidences and risk >= 0.35:
            # Keep evidence high-level, no raw URLs embedded.
            evidence = "; ".join(sorted(set(evidences))[:3])

        return [
            Signal(name="has_links", confidence=1.0, source=self.name, evidence="The message contains at least one link."),
            Signal(name="link_reputation_risk", confidence=risk, source=self.name, evidence=evidence),
        ]


