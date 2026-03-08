from __future__ import annotations

from fastapi import APIRouter, Query

from aether_guard.schemas import (
    AlertListResponse,
    DetectorMetrics,
    DetectorTelemetryResponse,
    RiskStatsResponse,
)
from aether_guard.services.container import phishing_service
from aether_guard.services.telemetry import get_telemetry


router = APIRouter(tags=["dashboard"])


@router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="List recent security alerts",
    description="""
    Retrieve privacy-safe alert history for dashboard visualization.

    Returns only derived signals and risk scores (no raw email content).
    Alerts are sorted by creation time (most recent first).
    """,
)
def list_alerts(
    limit: int = Query(
        default=50,
        ge=1,
        le=500,
        description="Maximum number of alerts to return",
    )
) -> AlertListResponse:
    """
    List recent security alerts.

    Privacy: Only signal-derived data is returned. No raw email content.
    """
    return AlertListResponse(items=phishing_service.list_alerts(limit=limit))


@router.get(
    "/stats",
    response_model=RiskStatsResponse,
    summary="Get risk statistics",
    description="""
    Retrieve aggregated risk statistics for dashboard visualization.

    Provides:
    - Total number of alerts analyzed
    - Distribution by severity level (low/medium/high)

    Useful for:
    - Threat frequency monitoring
    - Severity distribution charts
    - Security trend analysis
    """,
)
def risk_stats() -> RiskStatsResponse:
    """
    Get aggregated risk statistics.

    Returns summary statistics suitable for dashboard visualization.
    """
    s = phishing_service.stats()
    return RiskStatsResponse(total_alerts=int(s["total_alerts"]), by_severity=s["by_severity"])  # type: ignore[arg-type]


@router.get(
    "/detectors",
    response_model=DetectorTelemetryResponse,
    summary="Get detector telemetry",
    description="""
    Retrieve detector performance metrics and telemetry data.

    Provides:
    - Execution counts and timing
    - Reliability scores
    - Error rates
    - Top signals emitted by each detector

    Useful for:
    - Detector performance monitoring
    - Identifying slow or unreliable detectors
    - Understanding detector usage patterns
    """,
)
def detector_telemetry() -> DetectorTelemetryResponse:
    """
    Get detector telemetry and performance metrics.

    Returns telemetry data for all registered detectors.
    """
    telemetry = get_telemetry()
    summary = telemetry.get_summary()

    detectors_dict = {
        name: DetectorMetrics(
            detector_name=name,
            execution_count=data["execution_count"],
            avg_execution_time=data["avg_execution_time"],
            reliability=data["reliability"],
            error_count=data["error_count"],
            top_signals=data["top_signals"],
        )
        for name, data in summary["detectors"].items()
    }

    return DetectorTelemetryResponse(
        total_detectors=summary["total_detectors"],
        total_executions=summary["total_executions"],
        total_errors=summary["total_errors"],
        overall_reliability=summary["overall_reliability"],
        avg_execution_time=summary["avg_execution_time"],
        detectors=detectors_dict,
    )


