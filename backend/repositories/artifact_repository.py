"""Artifact repository.

Maps opaque download tokens to on-disk paths and records a sha256 so the
download endpoint can serve files without ever accepting a client-supplied
path. This is the artifact-isolation boundary.
"""
from __future__ import annotations

import hashlib
import secrets
import threading
from pathlib import Path

from models.artifacts import Artifact


class ArtifactRepository:
    def __init__(self) -> None:
        self._by_token: dict[str, Artifact] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def register(self, path: Path) -> Artifact:
        """Register an on-disk file and return its Artifact (with a fresh token)."""
        token = secrets.token_urlsafe(24)
        art = Artifact(
            token=token,
            path=path,
            sha256=self._sha256(path),
            size_bytes=path.stat().st_size,
        )
        with self._lock:
            self._by_token[token] = art
        return art

    def get(self, token: str) -> Artifact | None:
        with self._lock:
            return self._by_token.get(token)
