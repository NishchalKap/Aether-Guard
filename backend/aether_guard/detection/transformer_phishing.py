from __future__ import annotations

import logging
from pathlib import Path

from aether_guard.detection.ml_base import MLDetector
from aether_guard.detection.registry import register_detector
from aether_guard.detection.signals import Signal

logger = logging.getLogger(__name__)

try:
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("transformers library not available. TransformerPhishingDetector will not function.")


@register_detector
class TransformerPhishingDetector(MLDetector):
    """
    Transformer-based phishing detection using HuggingFace models.

    Uses a fine-tuned transformer (e.g., BERT, RoBERTa) to classify email text
    as phishing or legitimate.

    Model location: ai_models/phishing_transformer/
    """

    name = "transformer_phishing_v1"

    def __init__(self, *, model_path: Path | str | None = None, device: str | None = None):
        """
        Initialize transformer phishing detector.

        Args:
            model_path: Path to model directory. Defaults to ai_models/phishing_transformer/
            device: PyTorch device ('cuda', 'cpu', or None for auto-detect)
        """
        if model_path is None:
            # Default model path relative to project root
            project_root = Path(__file__).parent.parent.parent.parent
            model_path = project_root / "ai_models" / "phishing_transformer"

        super().__init__(model_path=model_path, device=device)
        self._tokenizer = None
        self._max_length = 512  # Standard transformer max length

    def _load_model(self):
        """Load HuggingFace transformer model."""
        if not TRANSFORMERS_AVAILABLE:
            raise RuntimeError("transformers library is required but not installed.")

        model_path_str = str(self._model_path)

        # Check if model exists
        if not Path(model_path_str).exists():
            logger.warning(
                f"Model path {model_path_str} does not exist. "
                "Using placeholder model. Install a real model for production use."
            )
            # Use a lightweight placeholder model for development
            # In production, this should load a fine-tuned phishing model
            try:
                # Try to load a small general-purpose model as fallback
                model = AutoModelForSequenceClassification.from_pretrained("distilbert-base-uncased", num_labels=2)
                self._tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
                logger.warning("Using placeholder model. Replace with fine-tuned phishing model for production.")
                return model
            except Exception as e:
                raise RuntimeError(f"Failed to load placeholder model: {e}")

        # Load actual model
        try:
            model = AutoModelForSequenceClassification.from_pretrained(model_path_str)
            self._tokenizer = AutoTokenizer.from_pretrained(model_path_str)
            return model
        except Exception as e:
            logger.error(f"Failed to load model from {model_path_str}: {e}")
            raise

    def _preprocess(self, *, text: str, sender: str | None, links: list[str]) -> dict:
        """
        Tokenize email text for transformer input.

        Combines text with sender/links context if needed.
        """
        if self._tokenizer is None:
            raise RuntimeError("Tokenizer not loaded. Call _load_model() first.")

        # Combine text with sender context
        full_text = text
        if sender:
            full_text = f"From: {sender}\n\n{text}"

        # Truncate if too long
        if len(full_text) > self._max_length * 4:  # Rough character estimate
            full_text = full_text[: self._max_length * 4]

        # Tokenize
        encoded = self._tokenizer(
            full_text,
            truncation=True,
            padding="max_length",
            max_length=self._max_length,
            return_tensors="pt",
        )

        # Move to device
        return {k: v.to(self._device) for k, v in encoded.items()}

    def _infer(self, inputs: dict):
        """Run transformer inference."""
        import torch

        if self._model is None:
            raise RuntimeError("Model not loaded.")

        with torch.no_grad():  # Disable gradient computation for inference
            outputs = self._model(**inputs)
            return outputs

    def _postprocess(self, outputs, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        """
        Convert model outputs to phishing probability signals.

        Assumes binary classification: [legitimate, phishing]
        """
        import torch

        # Extract logits
        logits = outputs.logits if hasattr(outputs, "logits") else outputs

        # Apply softmax to get probabilities
        probs = torch.softmax(logits, dim=-1)

        # Get phishing probability (assuming index 1 is phishing)
        phishing_prob = float(probs[0][1].item())

        # Generate signals
        signals = [
            Signal(
                name="ml_phishing_probability",
                confidence=phishing_prob,
                source=self.name,
                evidence=f"Transformer model predicted {phishing_prob:.2%} phishing probability",
            )
        ]

        # Add suspicious intent signal if probability is high
        if phishing_prob >= 0.7:
            signals.append(
                Signal(
                    name="ml_suspicious_intent",
                    confidence=phishing_prob,
                    source=self.name,
                    evidence="High ML confidence for suspicious/phishing intent detected",
                )
            )

        return signals


# Import torch at module level for type hints
try:
    import torch
except ImportError:
    pass

