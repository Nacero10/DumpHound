"""Plugin catalogue, synchronous plugin runs, and detection."""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends

from core.container import detection_dep, volatility_dep
from core.exceptions import VolatilityError
from core.security import ALLOWED_PLUGINS, TABLE_PLUGINS
from models.requests import DetectRequest, RunRequest
from models.responses import (
    DetectResponse,
    Finding,
    PluginInfo,
    PluginListResponse,
    RunResponse,
)
from services.detection_service import DetectionService
from services.volatility_service import VolatilityService

router = APIRouter(prefix="/plugins", tags=["plugins"])


def _categorize(name: str) -> tuple[str, str]:
    os_name = "windows" if name.startswith("windows.") else "linux"
    low = name.lower()
    if "pagecache" in low:
        cat = "pagecache"
    elif any(k in low for k in ("registry", "hive", "printkey", "userassist")):
        cat = "registry"
    elif any(
        k in low
        for k in (
            "malware", "malfind", "check_", "ssdt", "callback", "idt",
            "tty", "creds", "netfilter", "syscall", "hidden", "spoofing",
        )
    ):
        cat = "malware"
    elif any(k in low for k in ("net", "sock")):
        cat = "network"
    elif any(k in low for k in ("lsmod", "driver")) or ".modules." in low:
        cat = "modules"
    elif any(k in low for k in ("pstree", "pslist", "psscan", "psaux", "pidhash", "elf", "bash", "lsof", "library")):
        cat = "process"
    else:
        cat = "other"
    return os_name, cat


@router.get("", response_model=PluginListResponse)
def list_plugins() -> PluginListResponse:
    plugins = []
    for name in sorted(ALLOWED_PLUGINS):
        os_name, cat = _categorize(name)
        plugins.append(
            PluginInfo(name=name, os=os_name, category=cat, produces_table=name in TABLE_PLUGINS)
        )
    return PluginListResponse(plugins=plugins)


_FAILURE_MARKERS = (
    "unsatisfied requirement",
    "unable to validate",
    "no suitable address space",
    "no suitable requirements",
    "traceback (most recent call last)",
    "translation layer requirement",
    "symbol table requirement",
    "symboltablerequirement",
    "could not be fulfilled",
    "volatility3.framework.exceptions",
)


def _looks_like_error(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _FAILURE_MARKERS)


@router.post("/run", response_model=RunResponse)
def run_plugin(
    req: RunRequest, vol: VolatilityService = Depends(volatility_dep)
) -> RunResponse:
    # A plugin that can't run (bad symbols, N/A for this image) is an expected
    # outcome, not a server error. Return it gracefully with vol's real reason
    # instead of a 502 so the UI can show *why* it failed.
    try:
        stdout, stderr = vol.run_table(req.image, req.plugin, req.options, req.renderer)
    except VolatilityError as exc:
        return RunResponse(
            plugin=req.plugin,
            rows=0,
            renderer=req.renderer,
            csv="",
            stderr=str(exc) or "Volatility produced no output",
        )
    err = (stderr or "").strip()

    # vol can emit its error/traceback to stdout while exiting 0; that text is NOT
    # tabular data. Detect it so we never report it as "N rows" of results.
    if stdout and _looks_like_error(stdout):
        message = (stdout.strip() + ("\n" + err if err else "")).strip()
        return RunResponse(
            plugin=req.plugin, rows=0, renderer=req.renderer, csv="", stderr=message or None
        )

    rows = 0
    if req.renderer == "csv" and stdout:
        rows = max(sum(1 for _ in csv.reader(io.StringIO(stdout))) - 1, 0)

    # Header present but zero data rows, with a complaint on stderr → surface it.
    note = err or None
    return RunResponse(
        plugin=req.plugin, rows=rows, renderer=req.renderer, csv=stdout, stderr=note
    )


@router.post("/detect", response_model=DetectResponse)
def detect(
    req: DetectRequest, detection: DetectionService = Depends(detection_dep)
) -> DetectResponse:
    enriched, counts = detection.run(
        req.os, req.records, req.pagecache, req.modules, req.syscalls
    )
    findings = [
        Finding(
            level=f["level"],
            rule=f["rule"],
            technique=f.get("technique"),
            target=f["target"],
            detail=f["detail"],
        )
        for f in enriched
    ]
    return DetectResponse(findings=findings, counts=counts)
