from __future__ import annotations

from dataclasses import dataclass


def _clamp01(x: float) -> float:
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    return float(x)


@dataclass(frozen=True)
class Signal:
    """
    A privacy-safe derived indicator emitted by a detector.

    - `name`: stable key used by the risk engine + explainability.
    - `confidence`: normalized in [0,1].
    - `evidence`: optional plain-language evidence derived from signals (not raw input text).
    - `source`: detector name/version.
    """

    name: str
    confidence: float
    source: str
    evidence: str | None = None

    def normalized(self) -> "Signal":
        return Signal(
            name=self.name,
            confidence=_clamp01(self.confidence),
            source=self.source,
            evidence=self.evidence,
        )


