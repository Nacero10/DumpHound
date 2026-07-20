"""Inbound request models (Pydantic v2)."""
from __future__ import annotations

from pydantic import BaseModel, Field


class RunRequest(BaseModel):
    image: str = Field(..., description="Memory image filename inside the image dir")
    plugin: str = Field(..., description="Allowlisted Volatility plugin")
    options: dict[str, str | None] = Field(default_factory=dict)
    renderer: str = Field(default="csv", pattern="^(csv|json|jsonl|pretty|quick)$")


class InodeDumpRequest(BaseModel):
    image: str
    inode: str = Field(..., description="InodeAddr (0x...) or inode number")


class RecoverFsRequest(BaseModel):
    image: str


class DetectRequest(BaseModel):
    """Run the detection engine over already-parsed records (client-supplied)."""

    os: str = Field(default="linux", pattern="^(linux|windows)$")
    records: list[dict] = Field(default_factory=list)
    pagecache: list[dict] = Field(default_factory=list)
    modules: list[dict] = Field(default_factory=list)
    syscalls: list[dict] = Field(default_factory=list)
