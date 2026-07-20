"""Asynchronous job endpoints (long Volatility runs) + SSE progress stream."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from core.container import artifact_dep, dump_dep, job_dep
from core.exceptions import NotFoundError
from models.jobs import Job
from models.requests import InodeDumpRequest, RecoverFsRequest
from models.responses import ArtifactMeta, JobResponse, JobState
from services.artifact_service import ArtifactService
from services.dump_service import DumpService
from services.job_service import JobService

router = APIRouter(prefix="/jobs", tags=["jobs"])


def _job_to_response(job: Job, artifacts: ArtifactService) -> JobResponse:
    metas: list[ArtifactMeta] = []
    for token in job.artifact_tokens:
        art = artifacts.repo.get(token)
        if art:
            metas.append(
                ArtifactMeta(
                    token=art.token,
                    filename=art.filename,
                    size_bytes=art.size_bytes,
                    sha256=art.sha256,
                )
            )
    return JobResponse(
        id=job.id,
        state=JobState(job.state.value),
        kind=job.kind,
        created=datetime.fromtimestamp(job.created, tz=timezone.utc),
        finished=datetime.fromtimestamp(job.finished, tz=timezone.utc) if job.finished else None,
        error=job.error,
        artifacts=metas,
    )


@router.post("/recoverfs", response_model=JobResponse)
def submit_recoverfs(
    req: RecoverFsRequest,
    jobs: JobService = Depends(job_dep),
    dumps: DumpService = Depends(dump_dep),
    artifacts: ArtifactService = Depends(artifact_dep),
) -> JobResponse:
    job = Job(kind="recoverfs", image=req.image)

    def work(j: Job) -> None:
        j.log_lines.append("starting RecoverFs")
        produced, _ = dumps.recover_fs(j.image)
        j.artifact_tokens.extend(a.token for a in produced)
        j.log_lines.append(f"recovered {len(produced)} artifact(s)")

    jobs.submit(job, work)
    return _job_to_response(job, artifacts)


@router.post("/inode", response_model=JobResponse)
def submit_inode(
    req: InodeDumpRequest,
    jobs: JobService = Depends(job_dep),
    dumps: DumpService = Depends(dump_dep),
    artifacts: ArtifactService = Depends(artifact_dep),
) -> JobResponse:
    job = Job(kind="inode", image=req.image)

    def work(j: Job) -> None:
        j.log_lines.append(f"dumping inode {req.inode}")
        produced, _ = dumps.dump_inode(j.image, req.inode)
        j.artifact_tokens.extend(a.token for a in produced)
        j.log_lines.append(f"produced {len(produced)} file(s)")

    jobs.submit(job, work)
    return _job_to_response(job, artifacts)


@router.get("/{job_id}", response_model=JobResponse)
def get_job(
    job_id: str,
    jobs: JobService = Depends(job_dep),
    artifacts: ArtifactService = Depends(artifact_dep),
) -> JobResponse:
    job = jobs.repo.get(job_id)
    if job is None:
        raise NotFoundError("Job not found")
    return _job_to_response(job, artifacts)


@router.get("/{job_id}/stream")
async def stream_job(job_id: str, jobs: JobService = Depends(job_dep)) -> StreamingResponse:
    return StreamingResponse(
        jobs.stream(job_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
