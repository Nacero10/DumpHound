"""Internal domain dataclass for recovered artifacts."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Artifact:
    token: str
    path: Path
    sha256: str
    size_bytes: int

    @property
    def filename(self) -> str:
        return self.path.name
