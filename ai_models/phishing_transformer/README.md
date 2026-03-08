# Phishing Transformer Model

## Overview

This directory will contain a fine-tuned transformer model for phishing email detection, optimized for AMD ROCm acceleration.

## Architecture

- **Base Model**: BERT/RoBERTa or similar transformer architecture
- **Fine-tuning**: Trained on educational institution phishing datasets
- **Inference**: PyTorch with ROCm backend for AMD GPU acceleration

## ROCm Compatibility

### Requirements

- AMD GPU with ROCm support (e.g., AMD Instinct, Radeon Pro, Ryzen AI)
- PyTorch compiled with ROCm
- ROCm drivers installed

### Usage (Future)

```python
import torch
from aether_guard.ai_models.phishing_transformer import PhishingTransformerDetector

# Model automatically uses ROCm if available
detector = PhishingTransformerDetector()
signals = detector.analyze(text=email_text, sender=sender, links=links)
```

### Model Integration

The model will integrate with the detector pipeline:

```python
from aether_guard.detection.registry import register_detector

@register_detector
class PhishingTransformerDetector(Detector):
    name = "phishing_transformer_v1"
    
    def __init__(self):
        # Load model with ROCm device
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = load_transformer_model(device=self.device)
    
    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        # Run inference on AMD GPU
        ...
```

## Training

- Dataset: Educational phishing emails (anonymized)
- Privacy: No raw email content stored in model weights
- Fine-tuning: Domain adaptation for academic contexts

## Status

🚧 **Placeholder** - Model training and integration pending

