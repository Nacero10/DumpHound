"""Structured logging and a dedicated audit trail.

Application logs are emitted as single-line JSON to stdout (friendly to
container log collectors). Security-relevant events (plugin runs, dumps,
downloads) are additionally written to an append-only audit log.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key, val in getattr(record, "extra_fields", {}).items():
            payload[key] = val
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    # Tame noisy third parties
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


class AuditLogger:
    """Append-only audit log for security-relevant actions."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._log = logging.getLogger("proctree.audit")

    def record(self, action: str, **fields: Any) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            **fields,
        }
        line = json.dumps(entry, default=str)
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            # Never let an audit write failure break the request path.
            self._log.warning("audit write failed", extra={"extra_fields": entry})
        self._log.info("audit", extra={"extra_fields": entry})
