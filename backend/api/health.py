"""Health / readiness endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from core.container import settings_dep, volatility_dep
from core.config import Settings
from core.security import ALLOWED_PLUGINS
from models.responses import HealthResponse
from services.volatility_service import VolatilityService

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(
    vol: VolatilityService = Depends(volatility_dep),
    settings: Settings = Depends(settings_dep),
) -> HealthResponse:
    available = vol.is_available()
    return HealthResponse(
        status="ok",
        volatility_available=available,
        volatility_version=vol.version() if available else None,
        image_dir=str(settings.image_dir),
        plugins_allowed=len(ALLOWED_PLUGINS),
    )
