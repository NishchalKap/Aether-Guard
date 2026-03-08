from __future__ import annotations

from aether_guard.config import settings
from aether_guard.detection import get_all_detectors
from aether_guard.detection.pipeline import DetectorPipeline
from aether_guard.detection.signals import Signal
from aether_guard.explainability.alerts import build_explainable_alert
from aether_guard.schemas import ExplainableAlert
from aether_guard.services.alert_store import AlertStore
from aether_guard.services.risk_engine import RiskEngine


class PhishingAnalysisService:
    """
    Orchestrates phishing analysis.

    This layer exists so the API can stay thin and so we can later:
    - chain multiple detectors (heuristics + ML model + URL sandbox)
    - add policy rules per institution
    - attach audit logging with privacy controls
    """

    def __init__(self) -> None:
        # Load all registered detectors dynamically
        detectors = get_all_detectors()
        self._pipeline = DetectorPipeline(
            detectors=detectors,
            max_workers=4,
        )
        self._risk = RiskEngine()
        self._alerts = AlertStore(max_items=settings.max_alert_history)

    def analyze(
        self, *, text: str, sender: str | None, links: list[str]
    ) -> tuple[int, str, ExplainableAlert, dict[str, float], list[Signal], dict[str, float]]:
        """
        Analyze email content for security threats.

        Returns:
            Tuple of (risk_score, severity, explanation, merged_signals, raw_signals, contributions)
        """
        signals_list = self._pipeline.run(text=text, sender=sender, links=links)
        assessment = self._risk.score(
            signals=signals_list,
            low_max=settings.risk_low_max,
            medium_max=settings.risk_medium_max,
        )

        explanation = build_explainable_alert(risk_score=assessment.risk_score, signals=assessment.signals)

        # Store only derived signals for dashboard history, if enabled.
        if settings.store_signal_history:
            self._alerts.add(
                risk_score=assessment.risk_score,
                severity=explanation.severity,
                title=explanation.title,
                signals=assessment.signals,
            )

        return (
            assessment.risk_score,
            assessment.severity,
            explanation,
            assessment.signals,
            signals_list,
            assessment.contributions,
        )

    def list_alerts(self, *, limit: int = 50):
        return self._alerts.list(limit=limit)

    def stats(self):
        return self._alerts.stats()


