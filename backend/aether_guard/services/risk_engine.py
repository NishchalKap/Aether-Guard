from __future__ import annotations

from dataclasses import dataclass

from aether_guard.config import settings
from aether_guard.detection.signals import Signal


def _clamp_int(x: float, *, lo: int = 0, hi: int = 100) -> int:
    if x <= lo:
        return lo
    if x >= hi:
        return hi
    return int(round(x))


@dataclass(frozen=True)
class RiskAssessment:
    risk_score: int
    severity: str  # "LOW" | "MEDIUM" | "HIGH"
    signals: dict[str, float]
    contributions: dict[str, float]
    heuristic_score: float | None = None
    ml_score: float | None = None


class RiskEngine:
    """
    Central risk scoring pipeline.

    Inputs:
    - `signals`: normalized detector outputs (preferably in [0,1])

    Output:
    - integer risk score [0,100] + severity
    """

    def __init__(self) -> None:
        # Load weights from config (can be overridden via environment variables)
        self._weights: dict[str, float] = settings.risk_weights.copy()
        # Add ML signal weights
        self._weights.update(settings.ml_signal_weights)
        self._base: float = settings.risk_base
        self._heuristic_weight: float = settings.hybrid_heuristic_weight
        self._ml_weight: float = settings.hybrid_ml_weight

    def score(self, *, signals: list[Signal], low_max: int = 29, medium_max: int = 69) -> RiskAssessment:
        """
        Score a set of signals into a risk assessment using hybrid heuristic + ML scoring.

        - `signals`: list of Signal objects from the pipeline.
        - thresholds are configurable (defaults align with current behavior).

        Hybrid scoring:
        1. Separates heuristic and ML signals
        2. Scores each category independently
        3. Combines using configurable weights
        """

        merged: dict[str, float] = {}
        for s in signals:
            # Merge policy: take max confidence for each signal key.
            merged[s.name] = max(float(s.confidence), float(merged.get(s.name, 0.0)))

        # Separate heuristic and ML signals
        heuristic_signals: dict[str, float] = {}
        ml_signals: dict[str, float] = {}

        ml_prefixes = ("ml_", "transformer_", "classifier_")
        for key, conf in merged.items():
            if any(key.startswith(prefix) for prefix in ml_prefixes):
                ml_signals[key] = conf
            else:
                heuristic_signals[key] = conf

        # Score heuristic signals
        heuristic_score01 = self._base
        heuristic_contributions: dict[str, float] = {}
        for key, w in self._weights.items():
            if key in heuristic_signals:
                c = w * float(heuristic_signals[key])
                heuristic_contributions[key] = c
                heuristic_score01 += c

        # Score ML signals
        ml_score01 = 0.0
        ml_contributions: dict[str, float] = {}
        for key, w in self._weights.items():
            if key in ml_signals:
                c = w * float(ml_signals[key])
                ml_contributions[key] = c
                ml_score01 += c

        # Combine heuristic and ML scores with weights
        combined_score01 = (
            self._heuristic_weight * heuristic_score01 + self._ml_weight * ml_score01
        )

        # Merge all contributions
        all_contributions = {**heuristic_contributions, **ml_contributions}

        risk_score = _clamp_int(100.0 * combined_score01, lo=0, hi=100)

        if risk_score > medium_max:
            severity = "HIGH"
        elif risk_score > low_max:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return RiskAssessment(
            risk_score=risk_score,
            severity=severity,
            signals=merged,
            contributions=all_contributions,
            heuristic_score=heuristic_score01,
            ml_score=ml_score01,
        )


