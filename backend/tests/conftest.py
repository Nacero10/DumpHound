"""Shared pytest fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the backend package importable when running `pytest` from repo root.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.config import Settings  # noqa: E402


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    img = tmp_path / "images"
    out = tmp_path / "dumps"
    img.mkdir()
    out.mkdir()
    # Plant a fake image so resolve_image() succeeds.
    (img / "memdump.mem").write_bytes(b"\x00" * 16)
    rules = BACKEND_ROOT / "rules"
    return Settings(
        bin="vol",
        image_dir=img,
        output_dir=out,
        rules_dir=rules,
        offline=True,
    )


@pytest.fixture
def rules_dir() -> Path:
    return BACKEND_ROOT / "rules"
