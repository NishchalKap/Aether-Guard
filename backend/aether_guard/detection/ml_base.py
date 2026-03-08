from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

from aether_guard.detection.base import Detector
from aether_guard.detection.signals import Signal

logger = logging.getLogger(__name__)

try:
    import torch

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available. ML detectors will not function.")


class MLDetector(Detector, ABC):
    """
    Base class for ML-based detectors using PyTorch.

    Handles:
    - Model loading and caching
    - Device selection (ROCm/CUDA/CPU)
    - Batch inference preparation
    - Error handling and fallback

    Subclasses should implement:
    - `_load_model()`: Load PyTorch model
    - `_infer()`: Run inference on preprocessed inputs
    - `_preprocess()`: Convert inputs to model format
    - `_postprocess()`: Convert model outputs to Signals
    """

    def __init__(self, *, model_path: Path | str | None = None, device: str | None = None):
        """
        Initialize ML detector.

        Args:
            model_path: Path to model file/directory. If None, uses default location.
            device: PyTorch device ('cuda', 'cpu', or None for auto-detect).
        """
        self._model = None
        self._model_path = Path(model_path) if model_path else None
        self._device = self._select_device(device)
        self._model_loaded = False

    def _select_device(self, device: str | None) -> str:
        """
        Select PyTorch device with ROCm priority.

        Priority:
        1. User-specified device
        2. ROCm (if available)
        3. CUDA (if available)
        4. CPU (fallback)

        Returns:
            Device string for PyTorch.
        """
        if device:
            return device

        if not TORCH_AVAILABLE:
            return "cpu"

        # Check for ROCm (AMD GPU)
        if torch.cuda.is_available():
            # ROCm devices show up as CUDA devices in PyTorch
            # Check if we're on ROCm by checking device name or environment
            try:
                device_name = torch.cuda.get_device_name(0)
                if "amd" in device_name.lower() or "rocm" in str(torch.version.cuda).lower():
                    logger.info(f"Using ROCm device: {device_name}")
                    return "cuda"
            except Exception:
                pass

            # Regular CUDA
            logger.info("Using CUDA device")
            return "cuda"

        logger.info("Using CPU device")
        return "cpu"

    def _ensure_model_loaded(self) -> None:
        """Load model if not already loaded."""
        if self._model_loaded and self._model is not None:
            return

        if not TORCH_AVAILABLE:
            raise RuntimeError("PyTorch is required for ML detectors but is not installed.")

        try:
            self._model = self._load_model()
            self._model.to(self._device)
            self._model.eval()  # Set to evaluation mode
            self._model_loaded = True
            logger.info(f"Loaded {self.name} model on device: {self._device}")
        except Exception as e:
            logger.error(f"Failed to load model for {self.name}: {e}")
            raise

    @abstractmethod
    def _load_model(self):
        """
        Load PyTorch model.

        Returns:
            Loaded PyTorch model.
        """
        raise NotImplementedError

    @abstractmethod
    def _preprocess(self, *, text: str, sender: str | None, links: list[str]) -> dict:
        """
        Preprocess inputs for model inference.

        Args:
            text: Email text
            sender: Sender address
            links: List of URLs

        Returns:
            Preprocessed inputs (e.g., tokenized text, features)
        """
        raise NotImplementedError

    @abstractmethod
    def _infer(self, inputs: dict):
        """
        Run model inference.

        Args:
            inputs: Preprocessed inputs

        Returns:
            Model outputs (raw predictions)
        """
        raise NotImplementedError

    @abstractmethod
    def _postprocess(self, outputs, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        """
        Convert model outputs to Signals.

        Args:
            outputs: Raw model predictions
            text: Original email text (for evidence)
            sender: Original sender (for evidence)
            links: Original links (for evidence)

        Returns:
            List of Signal objects
        """
        raise NotImplementedError

    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        """
        Analyze inputs using ML model.

        This is the main entry point that orchestrates:
        1. Model loading (if needed)
        2. Preprocessing
        3. Inference
        4. Postprocessing

        Returns:
            List of Signal objects
        """
        if not TORCH_AVAILABLE:
            logger.warning(f"{self.name}: PyTorch not available, returning empty signals")
            return []

        try:
            self._ensure_model_loaded()
            inputs = self._preprocess(text=text, sender=sender, links=links)
            outputs = self._infer(inputs)
            signals = self._postprocess(outputs, text=text, sender=sender, links=links)
            return signals
        except Exception as e:
            logger.error(f"{self.name} failed during analysis: {e}", exc_info=True)
            # Return error signal instead of crashing
            return [
                Signal(
                    name="ml_detector_error",
                    confidence=1.0,
                    source=self.name,
                    evidence=f"ML detector encountered an error: {str(e)[:100]}",
                )
            ]

