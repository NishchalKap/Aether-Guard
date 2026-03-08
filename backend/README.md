# Backend — Aether‑Guard API

## Runtime requirements

- **Python 3.11 or 3.12** for local development (recommended)

Why:
- FastAPI depends on Pydantic v2, which depends on `pydantic-core` (a compiled extension).
- On very new Python versions (e.g., **3.14**), prebuilt wheels may be unavailable on Windows, causing installs
  to fall back to native builds (Rust/MSVC toolchain required).

## Run with Docker (recommended if your host Python is 3.14)

From repo root:

```bash
docker compose -f infrastructure/docker/docker-compose.yml up --build
```

Then open:
- `http://localhost:8000/v1/health`
- `http://localhost:8000/docs`

## Run locally (Python 3.11/3.12)

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
uvicorn aether_guard.main:app --host 0.0.0.0 --port 8000 --reload
```

## Prototype endpoint

- `POST /v1/analyze/phishing`
- `GET /v1/alerts` (privacy-safe history: derived signals only)
- `GET /v1/stats` (privacy-safe aggregate stats)

Example body:

```json
{
  "text": "URGENT: Your account will be locked. Verify your password here: https://example.com/login",
  "sender": "it-support@gmail.com",
  "links": ["https://example.com/login"]
}
```


