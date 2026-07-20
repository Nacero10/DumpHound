"""Dump + secure download endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse

from core.container import artifact_dep, audit_dep, dump_dep
from core.logging import AuditLogger
from models.requests import InodeDumpRequest, RecoverFsRequest
from models.responses import ArtifactMeta
from services.artifact_service import ArtifactService
from services.dump_service import DumpService

router = APIRouter(prefix="/dumps", tags=["dumps"])


def _to_meta(artifacts) -> list[ArtifactMeta]:
    return [
        ArtifactMeta(
            token=a.token, filename=a.filename, size_bytes=a.size_bytes, sha256=a.sha256
        )
        for a in artifacts
    ]


@router.post("/inode", response_model=list[ArtifactMeta])
def dump_inode(
    req: InodeDumpRequest, dumps: DumpService = Depends(dump_dep)
) -> list[ArtifactMeta]:
    artifacts, _ = dumps.dump_inode(req.image, req.inode)
    return _to_meta(artifacts)


@router.post("/recoverfs", response_model=list[ArtifactMeta])
def recover_fs(
    req: RecoverFsRequest, dumps: DumpService = Depends(dump_dep)
) -> list[ArtifactMeta]:
    artifacts, _ = dumps.recover_fs(req.image)
    return _to_meta(artifacts)


@router.get("/download/{token}")
def download(
    token: str,
    artifacts: ArtifactService = Depends(artifact_dep),
    audit: AuditLogger = Depends(audit_dep),
):
    art = artifacts.resolve(token)  # raises NotFoundError on bad/expired token
    audit.record("download", token=token, sha256=art.sha256, filename=art.filename)
    return FileResponse(
        path=art.path,
        filename=art.filename,
        media_type="application/octet-stream",
        headers={"X-Content-SHA256": art.sha256},
    )
