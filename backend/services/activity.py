"""In-memory activity log.

Records every Volatility subprocess execution with its full result — argv,
exit code, duration, output sizes, and a trimmed stderr — so an analyst can see
exactly *why* a command failed without reading the server console. Events live
in a bounded ring buffer (newest-first) and are also emitted to the JSON audit
log via the existing logger.
"""
from __future__ import annotations

import itertools
import logging
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field

log = logging.getLogger("proctree.activity")

_STDERR_CAP = 4000  # keep events small; full text is still in the console log


@dataclass
class ActivityEvent:
    id: int
    ts: float
    kind: str               # "run" | "dump_inode" | "recoverfs" | "version"
    status: str             # "ok" | "empty" | "error"
    argv: list[str]
    duration_ms: int
    returncode: int | None = None
    plugin: str | None = None
    image: str | None = None
    rows: int | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stderr: str | None = None       # trimmed
    message: str | None = None      # short human summary

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ActivityLog:
    maxlen: int = 500
    _events: deque[ActivityEvent] = field(default_factory=lambda: deque(maxlen=500))
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _ids: "itertools.count[int]" = field(default_factory=lambda: itertools.count(1))

    def __post_init__(self) -> None:
        # Honour a custom maxlen if provided.
        if self.maxlen != self._events.maxlen:
            self._events = deque(maxlen=self.maxlen)

    def record(
        self,
        *,
        kind: str,
        status: str,
        argv: list[str],
        duration_ms: int,
        returncode: int | None = None,
        plugin: str | None = None,
        image: str | None = None,
        rows: int | None = None,
        stdout: str = "",
        stderr: str = "",
        message: str | None = None,
    ) -> ActivityEvent:
        trimmed = stderr.strip()
        if len(trimmed) > _STDERR_CAP:
            trimmed = trimmed[:_STDERR_CAP] + "\n…(truncated)"
        ev = ActivityEvent(
            id=next(self._ids),
            ts=time.time(),
            kind=kind,
            status=status,
            argv=list(argv),
            duration_ms=duration_ms,
            returncode=returncode,
            plugin=plugin,
            image=image,
            rows=rows,
            stdout_bytes=len(stdout or ""),
            stderr_bytes=len(stderr or ""),
            stderr=trimmed or None,
            message=message,
        )
        with self._lock:
            self._events.appendleft(ev)
        log.info(
            "activity",
            extra={
                "extra_fields": {
                    "kind": kind,
                    "status": status,
                    "plugin": plugin,
                    "returncode": returncode,
                    "duration_ms": duration_ms,
                    "rows": rows,
                }
            },
        )
        return ev

    def list(self, limit: int = 200) -> list[dict]:
        with self._lock:
            return [e.as_dict() for e in list(self._events)[:limit]]

    def clear(self) -> int:
        with self._lock:
            n = len(self._events)
            self._events.clear()
            return n
