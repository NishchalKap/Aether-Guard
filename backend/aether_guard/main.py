from __future__ import annotations

from fastapi import FastAPI

from aether_guard.api.router import api_router
from aether_guard.config import settings


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="""
        **Aether-Guard** is a privacy-first, explainable AI cybersecurity system designed for educational institutions.

        ## Features

        - **Email Threat Analysis**: Detect phishing, suspicious links, domain spoofing, and credential harvesting attempts
        - **Explainable AI**: Get plain-language explanations of security risks
        - **Privacy-First**: Raw email content is never stored or logged
        - **Modular Detectors**: Pluggable detection system with multiple specialized detectors
        - **AMD ROCm Compatible**: Designed for AMD GPU acceleration (future ML models)

        ## Privacy

        This API follows strict privacy principles:
        - Raw email content is never persisted
        - Only derived signals and risk scores are stored
        - All analysis is explainable and transparent

        ## Authentication

        Currently open (add authentication middleware as needed for production).
        """,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        contact={
            "name": "Aether-Guard",
            "url": "https://github.com/your-org/aether-guard",
        },
        license_info={
            "name": "MIT",
        },
    )

    app.include_router(api_router, prefix=settings.api_v1_prefix)
    return app


app = create_app()


