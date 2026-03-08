# Login Anomaly Detection Model

## Overview

This directory will contain behavioral anomaly detection models for identifying suspicious login patterns and identity misuse.

## Architecture

- **Model Type**: Time-series anomaly detection (LSTM, Transformer, or Isolation Forest hybrid)
- **Features**: 
  - Login timing patterns
  - IP geolocation anomalies
  - Device fingerprint changes
  - Failed login patterns
  - Session duration anomalies
- **Inference**: PyTorch with ROCm backend for AMD GPU acceleration

## ROCm Compatibility

### Requirements

- AMD GPU with ROCm support
- PyTorch with ROCm
- ROCm drivers

### Usage (Future)

```python
from aether_guard.ai_models.login_anomaly_model import LoginAnomalyDetector

detector = LoginAnomalyDetector()
signals = detector.analyze_login_event(
    user_id="user123",
    ip_address="192.168.1.1",
    timestamp=datetime.now(),
    device_fingerprint="...",
    success=True
)
```

### Integration

```python
@register_detector
class LoginAnomalyDetector(Detector):
    name = "login_anomaly_v1"
    
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = load_anomaly_model(device=self.device)
        self.user_profiles = UserProfileStore()  # Privacy-safe aggregated patterns
    
    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        # For login events, analyze behavioral patterns
        # LSTM/Transformer inference on AMD GPU
        ...
```

## Features

- Unusual login location detection
- Device fingerprint anomaly detection
- Time-based pattern analysis
- Failed login attempt clustering
- Session hijacking indicators

## Privacy

- User IDs anonymized/hashed
- Only aggregated behavioral patterns stored
- No raw login credentials or personal data

## Status

🚧 **Placeholder** - Model development pending
