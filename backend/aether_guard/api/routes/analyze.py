from __future__ import annotations

from fastapi import APIRouter

from aether_guard.detection.signals import Signal
from aether_guard.schemas import (
    EmailAnalyzeRequest,
    EmailAnalyzeResponse,
    PhishingAnalyzeRequest,
    PhishingAnalyzeResponse,
    SignalDetail,
)
from aether_guard.services.container import phishing_service


router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post(
    "/email",
    response_model=EmailAnalyzeResponse,
    summary="Analyze email for phishing and security threats",
    description="""
    Unified email analysis endpoint that runs multiple detectors in parallel to identify:
    - Phishing patterns
    - Suspicious links and domains
    - Urgent language tactics
    - Credential harvesting attempts
    - Domain spoofing indicators

    Returns a comprehensive risk assessment with explainable alerts and detailed signal breakdown.
    """,
)
def analyze_email(payload: EmailAnalyzeRequest) -> EmailAnalyzeResponse:
    """
    Analyze an email for security threats.

    This endpoint:
    1. Runs all registered detectors in parallel
    2. Aggregates signals into a risk score
    3. Generates explainable alerts
    4. Stores privacy-safe signal history (if enabled)

    Privacy: Raw email content is never stored or logged.
    """
    # Use the same service but with unified response format
    risk_score, severity, explanation, signals, raw_signals, contributions = phishing_service.analyze(
        text=payload.email_text,
        sender=payload.sender,
        links=payload.links,
    )

    # Convert raw signals to SignalDetail for detailed breakdown
    signal_details: list[SignalDetail] = [
        SignalDetail(
            name=s.name,
            confidence=s.confidence,
            source=s.source,
            evidence=s.evidence,
        )
        for s in raw_signals
    ]

    return EmailAnalyzeResponse(
        risk_score=risk_score,
        severity=severity,  # type: ignore[arg-type]
        alert=explanation,
        signals=signals,
        signal_details=signal_details,
        contributions=contributions,
    )


@router.post(
    "/phishing",
    response_model=PhishingAnalyzeResponse,
    summary="Legacy phishing analysis endpoint",
    description="Legacy endpoint for backward compatibility. Use /analyze/email for new integrations.",
    deprecated=True,
)
def analyze_phishing(payload: PhishingAnalyzeRequest) -> PhishingAnalyzeResponse:
    """
    Legacy phishing analysis endpoint.

    This endpoint is maintained for backward compatibility.
    New integrations should use POST /v1/analyze/email instead.
    """
    risk_score, severity, explanation, signals, _, _ = phishing_service.analyze(
        text=payload.text,
        sender=payload.sender,
        links=payload.links,
    )
    return PhishingAnalyzeResponse(
        risk_score=risk_score,
        severity=explanation.severity,
        explanation=explanation,
        signals=signals,
    )


