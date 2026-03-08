# Document Tamper Detection Model

## Overview

This directory will contain models for detecting tampering, malicious content, and anomalies in uploaded documents (PDFs, Word docs, images, etc.).

## Architecture

- **OCR Engine**: Extract text and metadata from documents (Tesseract, PyMuPDF, etc.)
- **ML Model**: Deep learning model for tamper detection (CNN/Transformer hybrid)
- **Macro Analysis**: Static analysis of embedded macros/scripts
- **Inference**: PyTorch with ROCm backend for AMD GPU acceleration

## ROCm Compatibility

### Requirements

- AMD GPU with ROCm support
- PyTorch compiled with ROCm
- ROCm drivers installed

### Usage (Future)

```python
from aether_guard.ai_models.document_tamper_model import DocumentTamperDetector

detector = DocumentTamperDetector()
signals = detector.analyze_document(file_path="document.pdf")
```

### Integration

```python
@register_detector
class DocumentTamperDetector(Detector):
    name = "document_tamper_v1"
    
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = load_tamper_model(device=self.device)
        self.ocr = setup_ocr_engine()
    
    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        # For document uploads, analyze file content
        # OCR + ML inference on AMD GPU
        ...
```

## Features

- Document structure anomaly detection
- Hidden content detection
- Malicious macro identification
- Metadata inconsistency detection
- Image manipulation detection (for scanned documents)

## Privacy

- Documents processed in-memory only
- No raw document content persisted
- Only derived signals stored

## Status

🚧 **Placeholder** - Model development pending
