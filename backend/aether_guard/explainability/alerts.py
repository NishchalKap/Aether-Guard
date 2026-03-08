from __future__ import annotations

from aether_guard.schemas import ExplainableAlert, Severity


def _severity_from_score(score: int) -> Severity:
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


# Signal-to-explanation mapping rules
_SIGNAL_EXPLANATIONS: dict[str, tuple[float, str]] = {
    "credential_request": (0.5, "The message appears to ask for login credentials, password reset, or account verification."),
    "urgent_language": (0.5, "It uses urgent or time-pressure language to push quick action without verification."),
    "impersonation_language": (0.5, "It appears to impersonate a trusted organization, IT support, or security team."),
    "suspicious_url_shape": (0.4, "The link(s) have structural characteristics commonly seen in phishing URLs (e.g., many subdomains, IP addresses)."),
    "suspicious_domain": (0.4, "The domain(s) show suspicious characteristics like typosquatting, suspicious TLDs, or obfuscation."),
    "url_shortener": (0.3, "The message uses URL shortener services, which hide the true destination and are commonly used in phishing."),
    "link_reputation_risk": (0.4, "The link(s) show risk indicators often seen in scams (e.g., punycode, IP-based domains)."),
    "sender_link_domain_mismatch": (0.7, "The sender domain and link domain(s) do not match, suggesting potential spoofing."),
    "url_density": (0.6, "It contains multiple links, which increases the chance of malicious redirects."),
    "external_sender_indicator": (0.8, "The sender domain appears inconsistent with the claimed organization (e.g., personal email claiming to be IT support)."),
    "detector_error": (0.5, "Some detection components encountered errors; the risk assessment may be incomplete."),
}


def build_explainable_alert(*, risk_score: int, signals: dict[str, float]) -> ExplainableAlert:
    """
    Convert model/detector signals into an end-user explanation.

    IMPORTANT: Explanations must not include raw email content by default.
    They should reference *observable indicators* (signals) in plain language.
    """

    severity = _severity_from_score(risk_score)

    what_we_saw: list[str] = []
    # Use signal-to-explanation mapping rules
    for signal_name, (threshold, explanation) in _SIGNAL_EXPLANATIONS.items():
        confidence = signals.get(signal_name, 0.0)
        if confidence >= threshold:
            what_we_saw.append(explanation)

    if not what_we_saw:
        what_we_saw.append("No strong phishing indicators were detected by the security checks.")

    if severity == "high":
        title = "Potential Phishing Attempt"
        recommended_action = (
            "Do not click links or open attachments. Verify via the official campus portal or a known phone number."
        )
        teach_back = (
            "Phishing often creates urgency and asks you to log in or verify details. "
            "Always navigate to sites by typing the official address yourself."
        )
        explanation = "High risk: this message resembles common phishing patterns."
    elif severity == "medium":
        title = "Suspicious Message Detected"
        recommended_action = (
            "Be cautious. Avoid entering credentials from the message link; verify using an official source."
        )
        teach_back = (
            "A safe habit: hover over links to preview the destination, and verify the sender domain carefully."
        )
        explanation = "Moderate risk: some suspicious indicators were found."
    else:
        title = "Low Risk Message"
        recommended_action = "No immediate action needed, but stay alert for unusual link destinations or requests."
        teach_back = "If a message asks for credentials, verify independently even if it looks official."
        explanation = "Low risk: few suspicious indicators were found."

    return ExplainableAlert(
        severity=severity,
        risk_score=risk_score,
        title=title,
        explanation=explanation,
        what_we_saw=what_we_saw,
        recommended_action=recommended_action,
        teach_back=teach_back,
    )


