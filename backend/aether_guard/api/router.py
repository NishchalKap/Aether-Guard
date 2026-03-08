from __future__ import annotations

from fastapi import APIRouter

from aether_guard.api.routes import analyze, dashboard, health


api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(analyze.router)
api_router.include_router(dashboard.router)


