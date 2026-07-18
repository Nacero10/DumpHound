"""Internal domain dataclasses for jobs (repository layer)."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from .responses import JobState


@dataclass
class Job:
    kind: str
    image: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    state: JobState = JobState.pending
    created: float = field(default_factory=time.time)
    finished: float | None = None
    error: str | None = None
    # token -> absolute path, populated as artifacts are produced
    artifact_tokens: list[str] = field(default_factory=list)
    log_lines: list[str] = field(default_factory=list)

    def mark_running(self) -> None:
        self.state = JobState.running

    def mark_succeeded(self) -> None:
        self.state = JobState.succeeded
        self.finished = time.time()

    def mark_failed(self, error: str) -> None:
        self.state = JobState.failed
        self.error = error
        self.finished = time.time()
