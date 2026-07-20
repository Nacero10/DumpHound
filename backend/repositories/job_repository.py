"""Job repository.

In-memory, thread-safe store. Swappable for a Redis/DB-backed implementation
without touching the service layer (repository pattern).
"""
from __future__ import annotations

import threading

from models.jobs import Job


class JobRepository:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()

    def add(self, job: Job) -> Job:
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        with self._lock:
            return list(self._jobs.values())

    def update(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.id] = job
