"""Centralized, environment-driven configuration.

All settings are prefixed ``VOL_`` and may be supplied via environment
variables or a ``.env`` file. Pydantic v2 / pydantic-settings.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings.

    Every path is resolved to an absolute path at construction time so the
    security guards downstream can reason about containment reliably.
    """

    model_config = SettingsConfigDict(
        env_prefix="VOL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Volatility execution -------------------------------------------------
    bin: str = Field(default="vol", description="Path to the Volatility 3 CLI")
    image_dir: Path = Field(default=Path("./images"))
    output_dir: Path = Field(default=Path("./dumps"))
    symbol_dir: Path | None = Field(default=None)
    timeout: int = Field(default=900, ge=1, description="Per-call timeout (s)")
    workers: int = Field(default=2, ge=1, le=32)
    offline: bool = Field(default=True, description="Pass --offline to vol")

    # --- Detection rules ------------------------------------------------------
    rules_dir: Path = Field(default=Path("./rules"))

    # --- HTTP server ----------------------------------------------------------
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8799, ge=1, le=65535)
    frontend_dist: Path | None = Field(
        default=None, description="Built React dist/ served at / (optional)"
    )

    # --- Security -------------------------------------------------------------
    rate_limit_per_minute: int = Field(default=60, ge=1)
    cors_origins: list[str] = Field(default_factory=lambda: ["http://127.0.0.1:5173", "http://localhost:5173"])
    audit_log: Path = Field(default=Path("./audit.log"))
    log_level: str = Field(default="INFO")

    @field_validator("image_dir", "output_dir", "rules_dir", mode="after")
    @classmethod
    def _abs(cls, v: Path) -> Path:
        return v.expanduser().resolve()

    @field_validator("symbol_dir", "frontend_dist", mode="after")
    @classmethod
    def _abs_opt(cls, v: Path | None) -> Path | None:
        return v.expanduser().resolve() if v else None

    def ensure_dirs(self) -> None:
        """Create the directories the service needs to write to."""
        self.image_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton (FastAPI dependency-friendly)."""
    return Settings()
