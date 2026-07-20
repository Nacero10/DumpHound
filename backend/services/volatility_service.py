"""Volatility execution service.

This is the **sole** module that spawns a subprocess. Everything funnels
through :meth:`_exec`, which receives an already-validated argv list (built by
``core.validators``) and never touches a shell. If the Volatility binary is not
present the service degrades gracefully so the rest of the API still boots.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

from core.config import Settings
from core.exceptions import VolatilityError
from core.logging import AuditLogger
from core.validators import (
    build_inode_dump_argv,
    build_recoverfs_argv,
    build_run_argv,
)
from services.activity import ActivityLog

log = logging.getLogger("dumphound.volatility")


def _utf8_env() -> dict[str, str]:
    """Force the vol child to emit UTF-8 and let us decode it tolerantly.

    Volatility renders filenames / argv that often contain non-Latin1 characters.
    On a Windows console (cp1252) the child crashes with UnicodeEncodeError and
    the parent can fail to decode the bytes, so vol appears to 'produce no output'
    and the run 502s. Forcing UTF-8 on both sides fixes it.
    """
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env

# Markers that mean vol printed an error/traceback instead of real output.
_FAILURE_MARKERS = (
    "unsatisfied requirement",
    "unable to validate",
    "no suitable address space",
    "traceback (most recent call last)",
    "translation layer requirement",
    "symbol table requirement",
    "symboltablerequirement",
    "could not be fulfilled",
    "volatility3.framework.exceptions",
)


def _has_failure_marker(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _FAILURE_MARKERS)


def _summarize(stdout: str, stderr: str) -> str:
    """Best one-line reason from vol output for the activity log."""
    for blob in (stdout, stderr):
        for line in (blob or "").splitlines():
            s = line.strip()
            low = s.lower()
            if any(m in low for m in _FAILURE_MARKERS) or low.startswith(("error", "exception")):
                return s[:300]
    tail = stderr.strip().splitlines()
    return tail[-1][:300] if tail else "command failed"


class VolatilityService:
    def __init__(
        self, settings: Settings, audit: AuditLogger, activity: ActivityLog | None = None
    ) -> None:
        self.settings = settings
        self.audit = audit
        self.activity = activity or ActivityLog()

    # --- availability ---------------------------------------------------------
    def is_available(self) -> bool:
        return shutil.which(self.settings.bin) is not None or Path(self.settings.bin).exists()

    def version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            out = subprocess.run(  # noqa: S603 - argv list, no shell
                [self.settings.bin, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=_utf8_env(),
                timeout=30,
                check=False,
            )
            return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else None
        except (OSError, subprocess.SubprocessError):
            return None

    # --- execution ------------------------------------------------------------
    def _exec(
        self,
        argv: list[str],
        cwd: Path | None = None,
        *,
        kind: str = "run",
        plugin: str | None = None,
        image: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if not self.is_available():
            raise VolatilityError(
                "Volatility binary not found. Set VOL_BIN to a valid vol path."
            )
        log.info("exec", extra={"extra_fields": {"argv": argv}})
        start = time.perf_counter()
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, never a shell string
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=_utf8_env(),
                timeout=self.settings.timeout,
                cwd=str(cwd) if cwd else None,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self.activity.record(
                kind=kind, status="error", argv=argv,
                duration_ms=int((time.perf_counter() - start) * 1000),
                plugin=plugin, image=image,
                message=f"timed out after {self.settings.timeout}s",
            )
            raise VolatilityError(f"Volatility timed out after {self.settings.timeout}s") from exc
        except OSError as exc:
            self.activity.record(
                kind=kind, status="error", argv=argv,
                duration_ms=int((time.perf_counter() - start) * 1000),
                plugin=plugin, image=image, message=f"launch failed: {exc}",
            )
            raise VolatilityError(f"Failed to launch Volatility: {exc}") from exc

        duration_ms = int((time.perf_counter() - start) * 1000)
        # Classify: error if rc!=0 with no stdout, or stdout carries a vol traceback.
        if (proc.returncode != 0 and not proc.stdout) or _has_failure_marker(proc.stdout):
            status, message = "error", _summarize(proc.stdout, proc.stderr)
        elif not proc.stdout.strip():
            status, message = "empty", "no output produced"
        else:
            status, message = "ok", None
        self.activity.record(
            kind=kind, status=status, argv=argv, duration_ms=duration_ms,
            returncode=proc.returncode, plugin=plugin, image=image,
            stdout=proc.stdout, stderr=proc.stderr, message=message,
        )
        return proc

    def run_table(
        self,
        image: str,
        plugin: str,
        options: dict[str, str | None] | None = None,
        renderer: str = "csv",
    ) -> tuple[str, str]:
        """Run a table-producing plugin; return ``(stdout, stderr)``."""
        argv = build_run_argv(self.settings, image, plugin, options, renderer)
        self.audit.record("run_plugin", image=image, plugin=plugin, renderer=renderer)
        proc = self._exec(argv, kind="run", plugin=plugin, image=image)
        # Volatility frequently emits FutureWarnings / partial-output tracebacks
        # on stderr while still producing valid stdout, so we do not treat a
        # non-zero rc as fatal when stdout is present.
        if not proc.stdout and proc.returncode != 0:
            raise VolatilityError(proc.stderr.strip() or "Volatility produced no output")
        return proc.stdout, proc.stderr

    def dump_inode(self, image: str, inode: str, token: str) -> tuple[Path, str]:
        argv, out_dir = build_inode_dump_argv(self.settings, image, inode, token)
        self.audit.record("dump_inode", image=image, inode=inode, token=token)
        proc = self._exec(argv, kind="dump_inode", plugin="linux.pagecache.InodePages", image=image)
        if proc.returncode != 0 and not list(out_dir.glob("*")):
            raise VolatilityError(proc.stderr.strip() or "InodePages dump failed")
        return out_dir, proc.stderr

    def recover_fs(self, image: str, token: str) -> tuple[Path, str]:
        argv, out_dir = build_recoverfs_argv(self.settings, image, token)
        self.audit.record("recoverfs", image=image, token=token)
        proc = self._exec(argv, kind="recoverfs", plugin="linux.pagecache.RecoverFs", image=image)
        if proc.returncode != 0 and not list(out_dir.glob("*")):
            raise VolatilityError(proc.stderr.strip() or "RecoverFs failed")
        return out_dir, proc.stderr
