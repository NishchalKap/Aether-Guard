"""Detector modules (heuristics + ML-backed detectors).

Importing this module triggers auto-registration of all detectors.
"""

# Import all detectors to trigger registration
from aether_guard.detection import (
    credential_request_detector,
    domain_spoofing,
    link_reputation,
    phishing_heuristic,
    suspicious_domain_detector,
    transformer_phishing,
    urgent_language_detector,
    url_ml_detector,
    url_shortener_detector,
)

# Registry is now populated
from aether_guard.detection.registry import DETECTOR_REGISTRY, get_all_detectors

__all__ = [
    "DETECTOR_REGISTRY",
    "get_all_detectors",
]

