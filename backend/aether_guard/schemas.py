from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str
    timestamp_utc: datetime


class PhishingAnalyzeRequest(BaseModel):
    """
    Minimal request schema for the phishing prototype.

    Notes:
    - We accept email-like text (subject/body combined), and optional sender + links if available.
    - For privacy, callers can omit sender and pass redacted content.
    """

    text: str = Field(min_length=1, max_length=200_000)
    sender: str | None = Field(default=None, max_length=320)
    links: list[str] = Field(default_factory=list, max_length=2000)


class EmailAnalyzeRequest(BaseModel):
    """
    Unified email analysis request schema.

    This is the primary endpoint for analyzing emails for phishing and security threats.
    All fields are optional except email_text to support various input scenarios.

    Privacy:
    - Raw email content is never stored or logged by default.
    - Only derived signals and risk scores are persisted.
    """

    email_text: str = Field(
        min_length=1,
        max_length=200_000,
        description="The email body text (subject + body combined)",
        examples=["URGENT: Your account will be locked. Click here to verify: https://example.com/login"],
    )
    sender: str | None = Field(
        default=None,
        max_length=320,
        description="Email sender address (optional, for domain analysis)",
        examples=["it-support@gmail.com"],
    )
    links: list[str] = Field(
        default_factory=list,
        max_length=2000,
        description="List of URLs/links found in the email (optional, will be extracted from text if not provided)",
        examples=[["https://example.com/login", "https://suspicious-site.com/verify"]],
    )


Severity = Literal["low", "medium", "high"]


class ExplainableAlert(BaseModel):
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    title: str
    explanation: str
    what_we_saw: list[str] = Field(default_factory=list)
    recommended_action: str
    teach_back: str


class PhishingAnalyzeResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    explanation: ExplainableAlert
    # derived signals returned for transparency/debugging; safe by design (no raw email content)
    signals: dict[str, float] = Field(default_factory=dict)


class SignalDetail(BaseModel):
    """Detailed signal information for transparency."""

    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    evidence: str | None = None


class EmailAnalyzeResponse(BaseModel):
    """
    Unified email analysis response.

    Provides comprehensive threat analysis including:
    - Risk score and severity classification
    - Explainable alert with recommended actions
    - Detailed signal breakdown
    - Privacy-safe: no raw email content included
    """

    risk_score: int = Field(
        ge=0,
        le=100,
        description="Overall risk score from 0 (safe) to 100 (high risk)",
        examples=[72],
    )
    severity: Severity = Field(
        description="Risk severity classification",
        examples=["high"],
    )
    alert: ExplainableAlert = Field(
        description="Human-readable alert with explanation, recommended action, and educational teach-back",
    )
    signals: dict[str, float] = Field(
        default_factory=dict,
        description="Merged signal confidence scores (signal_name -> confidence 0-1)",
        examples=[{"credential_request": 0.85, "urgent_language": 0.72, "suspicious_domain": 0.45}],
    )
    signal_details: list[SignalDetail] = Field(
        default_factory=list,
        description="Detailed breakdown of all signals detected by individual detectors",
    )
    contributions: dict[str, float] = Field(
        default_factory=dict,
        description="Signal contribution to final risk score (signal_name -> contribution)",
        examples=[{"credential_request": 0.28, "urgent_language": 0.12}],
    )


class AlertRecord(BaseModel):
    """
    Privacy-safe record for dashboard history.
    Stores only derived signals and outcomes (no raw text/sender/links).
    """

    id: str
    created_at_utc: datetime
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    title: str
    signals: dict[str, float] = Field(default_factory=dict)


class AlertListResponse(BaseModel):
    items: list[AlertRecord]


class RiskStatsResponse(BaseModel):
    """
    Aggregated risk statistics for dashboard visualization.

    Privacy-safe: Contains only aggregated counts, no individual alert details.
    """

    total_alerts: int = Field(
        ge=0,
        description="Total number of alerts analyzed",
        examples=[1250],
    )
    by_severity: dict[Severity, int] = Field(
        description="Alert count grouped by severity level",
        examples=[{"low": 800, "medium": 350, "high": 100}],
    )


class DetectorContribution(BaseModel):
    """Detector contribution to overall threat detection."""

    detector_name: str
    signal_count: int = Field(ge=0)
    avg_confidence: float = Field(ge=0.0, le=1.0)


class ThreatFrequency(BaseModel):
    """Threat frequency metrics for time-series visualization."""

    time_period: str  # e.g., "2024-01-15"
    alert_count: int = Field(ge=0)
    high_severity_count: int = Field(ge=0)


class DetectorMetrics(BaseModel):
    """Detector performance metrics."""

    detector_name: str
    execution_count: int = Field(ge=0)
    avg_execution_time: float = Field(ge=0.0)
    reliability: float = Field(ge=0.0, le=1.0)
    error_count: int = Field(ge=0)
    top_signals: dict[str, int] = Field(default_factory=dict)


class DetectorTelemetryResponse(BaseModel):
    """Detector telemetry summary."""

    total_detectors: int
    total_executions: int
    total_errors: int
    overall_reliability: float = Field(ge=0.0, le=1.0)
    avg_execution_time: float = Field(ge=0.0)
    detectors: dict[str, DetectorMetrics]


