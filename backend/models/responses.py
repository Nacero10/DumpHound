"""Outbound response models (Pydantic v2)."""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"
    volatility_available: bool
    volatility_version: str | None = None
    image_dir: str
    plugins_allowed: int


class ImageInfo(BaseModel):
    name: str
    size_bytes: int
    modified: datetime


class ImageListResponse(BaseModel):
    images: list[ImageInfo]


class PluginInfo(BaseModel):
    name: str
    os: str
    category: str
    produces_table: bool


class PluginListResponse(BaseModel):
    plugins: list[PluginInfo]


class RunResponse(BaseModel):
    """Synchronous run result (CSV text + parsed row count)."""

    plugin: str
    rows: int
    renderer: str
    csv: str
    stderr: str | None = None


class Finding(BaseModel):
    level: str = Field(..., pattern="^(alert|warn|info)$")
    rule: str
    technique: str | None = None
    target: str
    detail: str


class DetectResponse(BaseModel):
    findings: list[Finding]
    counts: dict[str, int]


class JobState(str, Enum):
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"


class JobResponse(BaseModel):
    id: str
    state: JobState
    kind: str
    created: datetime
    finished: datetime | None = None
    error: str | None = None
    artifacts: list[ArtifactMeta] = Field(default_factory=list)


class ArtifactMeta(BaseModel):
    token: str
    filename: str
    size_bytes: int
    sha256: str


class ErrorEnvelope(BaseModel):
    code: str
    message: str


# Resolve forward reference (JobResponse references ArtifactMeta).
JobResponse.model_rebuild()
