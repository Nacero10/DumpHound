"""Dump service.

Coordinates the InodePages / RecoverFs flows: ask Volatility to write into an
isolated, token-named output directory, then register every produced file with
the artifact service so it can be downloaded via opaque token.
"""
from __future__ import annotations

import secrets

from models.artifacts import Artifact
from services.artifact_service import ArtifactService
from services.volatility_service import VolatilityService


class DumpService:
    def __init__(self, vol: VolatilityService, artifacts: ArtifactService) -> None:
        self.vol = vol
        self.artifacts = artifacts

    def dump_inode(self, image: str, inode: str) -> tuple[list[Artifact], str]:
        token = secrets.token_hex(12)
        out_dir, stderr = self.vol.dump_inode(image, inode, token)
        return self.artifacts.register_dir(out_dir), stderr

    def recover_fs(self, image: str) -> tuple[list[Artifact], str]:
        token = secrets.token_hex(12)
        out_dir, stderr = self.vol.recover_fs(image, token)
        return self.artifacts.register_dir(out_dir), stderr
