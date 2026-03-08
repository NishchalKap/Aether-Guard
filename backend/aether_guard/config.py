from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration for the backend.

    Privacy defaults:
    - Do not store or log raw user content unless explicitly enabled.
    """

    model_config = SettingsConfigDict(
        env_prefix="AETHER_GUARD_",
        env_file=".env",
        extra="ignore",
    )

    app_name: str = "Aether-Guard"
    api_v1_prefix: str = "/v1"
    environment: str = "dev"

    # Privacy / telemetry
    enable_request_logging: bool = False
    store_raw_inputs: bool = False
    store_signal_history: bool = True
    max_alert_history: int = 500

    # Risk thresholds (0-100 scale)
    risk_low_max: int = 29
    risk_medium_max: int = 69
    # high is 70+

    # Risk engine signal weights (sum should ideally be <= 1.0 for normalized scoring)
    # These can be overridden via environment variables: AETHER_GUARD_RISK_WEIGHT_<SIGNAL_NAME>
    # Example: AETHER_GUARD_RISK_WEIGHT_CREDENTIAL_REQUEST=0.35
    risk_weights: dict[str, float] = {
        "credential_request": 0.28,
        "suspicious_url_shape": 0.20,
        "suspicious_domain": 0.18,
        "impersonation_language": 0.15,
        "urgent_language": 0.12,
        "url_shortener": 0.10,
        "link_reputation_risk": 0.15,
        "sender_link_domain_mismatch": 0.14,
        "external_sender_indicator": 0.07,
        "url_density": 0.04,
        "detector_error": 0.08,
    }

    # Baseline risk offset (applied before scaling to 0-100)
    risk_base: float = 0.02

    # Hybrid scoring weights (heuristic vs ML)
    hybrid_heuristic_weight: float = 0.6
    hybrid_ml_weight: float = 0.4

    # ML signal weights (added to risk_weights)
    ml_signal_weights: dict[str, float] = {
        "ml_phishing_probability": 0.25,
        "ml_suspicious_intent": 0.20,
        "ml_url_risk_score": 0.18,
        "ml_detector_error": 0.05,
    }


settings = Settings()


