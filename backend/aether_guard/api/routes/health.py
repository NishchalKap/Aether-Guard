from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from aether_guard.config import settings
from aether_guard.schemas import HealthResponse


router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
    description="Returns service health status and current timestamp. Useful for monitoring and load balancers.",
)
def health() -> HealthResponse:
    """
    Health check endpoint.

    Returns service name and current UTC timestamp.
    """
    return HealthResponse(
        service=settings.app_name,
        timestamp_utc=datetime.now(timezone.utc),
    )


