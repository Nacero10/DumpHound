"""Job service.

Runs long Volatility operations on a bounded thread pool and exposes their
progress via Server-Sent Events. Job state lives in the JobRepository so it can
be polled or streamed.
"""
from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import AsyncIterator, Callable

from core.config import Settings
from models.jobs import Job
from repositories.job_repository import JobRepository

log = logging.getLogger("proctree.jobs")


class JobService:
    def __init__(self, settings: Settings, repo: JobRepository) -> None:
        self.repo = repo
        self._pool = ThreadPoolExecutor(max_workers=settings.workers, thread_name_prefix="vol-job")

    def submit(self, job: Job, work: Callable[[Job], None]) -> Job:
        """Register *job* and run *work(job)* on the pool."""
        self.repo.add(job)

        def _runner() -> None:
            job.mark_running()
            self.repo.update(job)
            try:
                work(job)
                job.mark_succeeded()
            except Exception as exc:  # noqa: BLE001 - capture into job state
                log.exception("job failed")
                job.mark_failed(str(exc))
            finally:
                self.repo.update(job)

        self._pool.submit(_runner)
        return job

    async def stream(self, job_id: str) -> AsyncIterator[str]:
        """Yield SSE frames describing the job until it reaches a terminal state."""
        last_state = None
        last_log = 0
        while True:
            job = self.repo.get(job_id)
            if job is None:
                yield 'event: error\ndata: {"message":"unknown job"}\n\n'
                return
            if job.state.value != last_state:
                last_state = job.state.value
                yield f'event: state\ndata: {{"state":"{last_state}"}}\n\n'
            while last_log < len(job.log_lines):
                line = job.log_lines[last_log].replace("\n", " ")
                yield f"event: log\ndata: {line}\n\n"
                last_log += 1
            if job.state.value in ("succeeded", "failed"):
                yield f'event: done\ndata: {{"state":"{job.state.value}"}}\n\n'
                return
            await asyncio.sleep(0.5)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
