from __future__ import annotations

import logging
import re
from pathlib import Path
from urllib.parse import urlparse

from aether_guard.detection.ml_base import MLDetector
from aether_guard.detection.registry import register_detector
from aether_guard.detection.signals import Signal

logger = logging.getLogger(__name__)

try:
    import torch
    import torch.nn as nn

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class SimpleURLClassifier(nn.Module):
    """
    Simple neural network for URL risk classification.

    Features:
    - Domain length
    - Entropy
    - Special characters
    - TLD risk score
    - Path length
    """

    def __init__(self, input_size: int = 10, hidden_size: int = 32):
        super().__init__()
        self.fc1 = nn.Linear(input_size, hidden_size)
        self.fc2 = nn.Linear(hidden_size, hidden_size // 2)
        self.fc3 = nn.Linear(hidden_size // 2, 1)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        x = self.sigmoid(self.fc3(x))
        return x


def extract_url_features(url: str) -> list[float]:
    """
    Extract handcrafted features from URL for ML model.

    Returns:
        Feature vector: [domain_len, path_len, entropy, special_chars, tld_risk, ...]
    """
    try:
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()
        path = parsed.path or ""
    except Exception:
        domain = ""
        path = ""

    features = []

    # Domain length (normalized)
    domain_len = len(domain)
    features.append(min(domain_len / 100.0, 1.0))

    # Path length (normalized)
    path_len = len(path)
    features.append(min(path_len / 200.0, 1.0))

    # Entropy (character diversity)
    if domain:
        char_counts = {}
        for char in domain:
            char_counts[char] = char_counts.get(char, 0) + 1
        entropy = 0.0
        for count in char_counts.values():
            p = count / len(domain)
            entropy -= p * (p.bit_length() - 1) if p > 0 else 0
        features.append(min(entropy / 5.0, 1.0))  # Normalize
    else:
        features.append(0.0)

    # Special characters ratio
    special_chars = len(re.findall(r"[^a-z0-9.\-]", domain + path))
    total_chars = len(domain + path)
    features.append(min(special_chars / max(total_chars, 1), 1.0))

    # TLD risk (common suspicious TLDs)
    suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"}
    tld_risk = 1.0 if any(tld in domain for tld in suspicious_tlds) else 0.0
    features.append(tld_risk)

    # Number of subdomains
    subdomain_count = domain.count(".")
    features.append(min(subdomain_count / 5.0, 1.0))

    # Has IP address
    has_ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain))
    features.append(1.0 if has_ip else 0.0)

    # Has punycode
    has_punycode = "xn--" in domain
    features.append(1.0 if has_punycode else 0.0)

    # URL length (normalized)
    url_len = len(url)
    features.append(min(url_len / 200.0, 1.0))

    # Has suspicious keywords in path
    suspicious_keywords = ["login", "verify", "password", "secure", "update", "account"]
    has_keywords = any(kw in path.lower() for kw in suspicious_keywords)
    features.append(1.0 if has_keywords else 0.0)

    return features


@register_detector
class UrlMLRiskDetector(MLDetector):
    """
    ML-based URL risk classifier.

    Uses a neural network to classify URLs based on structural features.
    Model location: ai_models/url_classifier/
    """

    name = "url_ml_risk_v1"

    def __init__(self, *, model_path: Path | str | None = None, device: str | None = None):
        """
        Initialize URL ML risk detector.

        Args:
            model_path: Path to model file. Defaults to ai_models/url_classifier/
            device: PyTorch device
        """
        if model_path is None:
            project_root = Path(__file__).parent.parent.parent.parent
            model_path = project_root / "ai_models" / "url_classifier" / "model.pt"

        super().__init__(model_path=model_path, device=device)
        self._feature_size = 10

    def _load_model(self):
        """Load URL classifier model."""
        if not TORCH_AVAILABLE:
            raise RuntimeError("PyTorch is required but not installed.")

        model_path_str = str(self._model_path)

        # Check if model exists
        if not Path(model_path_str).exists():
            logger.warning(
                f"Model file {model_path_str} does not exist. "
                "Creating placeholder model. Train a real model for production use."
            )
            # Create a placeholder model
            model = SimpleURLClassifier(input_size=self._feature_size)
            logger.warning("Using untrained placeholder model. Train with real data for production.")
            return model

        # Load actual model
        try:
            model = SimpleURLClassifier(input_size=self._feature_size)
            model.load_state_dict(torch.load(model_path_str, map_location=self._device))
            return model
        except Exception as e:
            logger.error(f"Failed to load model from {model_path_str}: {e}")
            # Fallback to placeholder
            logger.warning("Falling back to placeholder model")
            return SimpleURLClassifier(input_size=self._feature_size)

    def _preprocess(self, *, text: str, sender: str | None, links: list[str]) -> dict:
        """
        Extract features from URLs.

        Returns:
            Dictionary with 'features' tensor
        """
        import torch

        # Extract URLs from text if not provided
        url_pattern = r"https?://[^\s\)>\"]+"
        text_urls = re.findall(url_pattern, text, flags=re.IGNORECASE)
        all_urls = list(set((links or []) + text_urls))

        if not all_urls:
            # Return zero features if no URLs
            features = torch.zeros((1, self._feature_size), device=self._device)
            return {"features": features, "urls": []}

        # Extract features for each URL and take max risk
        url_features = []
        for url in all_urls:
            features = extract_url_features(url)
            url_features.append(features)

        # Use max risk URL (most suspicious)
        max_features = max(url_features, key=sum)  # Sum as proxy for risk

        features_tensor = torch.tensor([max_features], dtype=torch.float32, device=self._device)

        return {"features": features_tensor, "urls": all_urls}

    def _infer(self, inputs: dict):
        """Run URL classifier inference."""
        if self._model is None:
            raise RuntimeError("Model not loaded.")

        import torch

        with torch.no_grad():
            features = inputs["features"]
            outputs = self._model(features)
            return outputs

    def _postprocess(self, outputs, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        """
        Convert model outputs to URL risk signals.
        """
        import torch

        # Extract risk probability
        risk_prob = float(outputs[0][0].item())

        return [
            Signal(
                name="ml_url_risk_score",
                confidence=risk_prob,
                source=self.name,
                evidence=f"ML model predicted {risk_prob:.2%} URL risk probability",
            )
        ]

