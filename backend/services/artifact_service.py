"""Artifact service: registers recovered files and resolves download tokens."""
from __future__ import annotations

from pathlib import Path

from core.exceptions import NotFoundError
from models.artifacts import Artifact
from repositories.artifact_repository import ArtifactRepository


class ArtifactService:
    def __init__(self, repo: ArtifactRepository) -> None:
        self.repo = repo

    def register_dir(self, directory: Path) -> list[Artifact]:
        """Register every regular file produced under *directory*."""
        artifacts: list[Artifact] = []
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                artifacts.append(self.repo.register(path))
        return artifacts

    def resolve(self, token: str) -> Artifact:
        art = self.repo.get(token)
        if art is None or not art.path.is_file():
            raise NotFoundError("Artifact not found or expired")
        return art
