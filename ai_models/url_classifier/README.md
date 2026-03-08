# URL Risk Classifier

## Overview

This directory will contain a deep learning model for URL/link risk classification, designed for AMD ROCm acceleration.

## Architecture

- **Model Type**: CNN/LSTM hybrid or transformer-based sequence model
- **Input**: URL strings, domain features, link context
- **Output**: Risk probability scores for various threat categories
- **Inference**: PyTorch with ROCm backend

## ROCm Compatibility

### Requirements

- AMD GPU with ROCm support
- PyTorch with ROCm
- ROCm drivers

### Usage (Future)

```python
from aether_guard.ai_models.url_classifier import URLRiskClassifier

classifier = URLRiskClassifier()
risk_score = classifier.classify_url(url="https://example.com/suspicious")
```

### Integration

Will integrate as a detector:

```python
@register_detector
class URLRiskClassifierDetector(Detector):
    name = "url_risk_classifier_v1"
    
    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        # Classify each URL
        for link in links:
            risk = self.classifier.classify_url(link)
            ...
```

## Features

- Malicious URL detection
- Phishing link classification
- Domain reputation scoring
- Redirect chain analysis

## Status

🚧 **Placeholder** - Model development pending

