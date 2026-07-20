"""Activity log endpoints — recent Volatility executions and their outcomes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from core.container import activity_dep
from services.activity import ActivityLog

router = APIRouter(tags=["activity"])


@router.get("/activity")
def list_activity(
    limit: int = Query(default=200, ge=1, le=500),
    activity: ActivityLog = Depends(activity_dep),
) -> dict:
    return {"events": activity.list(limit)}


@router.delete("/activity")
def clear_activity(activity: ActivityLog = Depends(activity_dep)) -> dict:
    return {"cleared": activity.clear()}
