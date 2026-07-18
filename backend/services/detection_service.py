"""Data-driven detection engine.

All rules live in ``rules/{linux,windows}.json`` + ``rules/mitre.json``. The
engine never hardcodes a rule; detectors only know *how* to evaluate a category
of rule against a category of evidence.

Structure (mirrors the architecture spec)::

    DetectionEngine
    ├── ProcessLineageDetector
    ├── CommandDetector
    ├── NetworkDetector
    ├── MalfindDetector
    ├── SpoofingDetector
    └── MitreMapper

Records are plain dicts (already parsed from Volatility CSV by the frontend or
by an upstream parser), so the engine has no Volatility dependency and is fully
unit-testable.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Finding value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    level: str
    rule: str
    technique: str | None
    target: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "rule": self.rule,
            "technique": self.technique,
            "target": self.target,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Matcher DSL — pure predicate evaluation against a single evidence dict
# ---------------------------------------------------------------------------


def _get(row: dict, *keys: str) -> str:
    """Case-insensitive fetch of the first present key; returns ''."""
    lowered = {k.lower(): v for k, v in row.items()}
    for k in keys:
        v = lowered.get(k.lower())
        if v not in (None, ""):
            return str(v)
    return ""


def _truthy(val: str) -> bool:
    return val.strip().lower() in {"1", "true", "yes", "y", "set"} or (
        bool(val.strip()) and val.strip().lower() not in {"0", "false", "no", "n", "-", "none"}
    )


class Matcher:
    """Evaluate a rule's ``match`` block against an evidence dict."""

    @staticmethod
    def path_matches(path: str, m: dict) -> bool:
        p = path.lower()
        if "path_eq" in m and path != m["path_eq"]:
            return False
        if "path_contains" in m and m["path_contains"].lower() not in p:
            return False
        if "path_not_contains" in m and m["path_not_contains"].lower() in p:
            return False
        if "path_contains_any" in m and not any(s.lower() in p for s in m["path_contains_any"]):
            return False
        if "path_ext" in m and not any(p.endswith(ext.lower()) for ext in m["path_ext"]):
            return False
        if "path_regex" in m and not re.search(m["path_regex"], path):
            return False
        return True

    @staticmethod
    def field_matches(row: dict, m: dict) -> bool:
        if "field_truthy" in m and not _truthy(_get(row, m["field_truthy"])):
            return False
        if "field_eq" in m:
            for key, expected in m["field_eq"].items():
                if _get(row, key).strip().upper() != str(expected).strip().upper():
                    return False
        if "field_regex" in m:
            spec = m["field_regex"]
            flags = re.IGNORECASE if "i" in spec.get("flags", "") else 0
            if not re.search(spec["pattern"], _get(row, spec["field"]), flags):
                return False
        return True

    @staticmethod
    def comm_in(row: dict, names: Iterable[str]) -> bool:
        comm = _get(row, "comm", "process", "name", "imagefilename").lower()
        return any(comm == n.lower() or comm.startswith(n.lower()) for n in names)


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


class _BaseDetector:
    category: str = ""

    def __init__(self, rules: dict) -> None:
        self.rules: list[dict] = rules.get(self.category, [])

    def _finding(self, rule: dict, target: str) -> Finding:
        return Finding(
            level=rule["level"],
            rule=rule["id"],
            technique=rule.get("technique"),
            target=target,
            detail=rule["detail"],
        )


class PagecacheDetector(_BaseDetector):
    category = "pagecache"

    def run(self, files: list[dict]) -> list[Finding]:
        out: list[Finding] = []
        for f in files:
            path = _get(f, "filepath", "path", "file")
            if not path:
                continue
            for rule in self.rules:
                if Matcher.path_matches(path, rule["match"]):
                    out.append(self._finding(rule, path))
        return out


class ProcessLineageDetector(_BaseDetector):
    category = "lineage"

    def run(self, records: list[dict]) -> list[Finding]:
        by_pid = {str(_get(r, "pid")): r for r in records if _get(r, "pid")}
        out: list[Finding] = []
        for child in records:
            ppid = _get(child, "ppid", "parent", "parentpid")
            parent = by_pid.get(str(ppid))
            if not parent:
                continue
            for rule in self.rules:
                m = rule["match"]
                if Matcher.comm_in(parent, m.get("parent_comm_in", [])) and Matcher.comm_in(
                    child, m.get("child_comm_in", [])
                ):
                    target = f"{_get(parent,'comm','process','name')}({ppid}) -> {_get(child,'comm','process','name')}({_get(child,'pid')})"
                    out.append(self._finding(rule, target))
        return out


class CommandDetector(_BaseDetector):
    category = "command"

    def run(self, records: list[dict]) -> list[Finding]:
        out: list[Finding] = []
        for r in records:
            cmd = _get(r, "command", "cmd", "args", "cmdline")
            if not cmd:
                continue
            for rule in self.rules:
                m = rule["match"]
                flags = re.I if "i" in m.get("cmd_flags", "") else 0
                if re.search(m["cmd_regex"], cmd, flags):
                    out.append(self._finding(rule, cmd[:160]))
        return out


class NetworkDetector(_BaseDetector):
    category = "network"

    def run(self, records: list[dict]) -> list[Finding]:
        out: list[Finding] = []
        for r in records:
            for rule in self.rules:
                m = rule["match"]
                proto = _get(r, "proto", "protocol").upper()
                state = _get(r, "state").upper()
                if "proto_in" in m and proto not in [p.upper() for p in m["proto_in"]]:
                    continue
                if "state_in" in m and state not in [s.upper() for s in m["state_in"]]:
                    continue
                port = _local_port(r)
                if "local_port_gte" in m and (port is None or port < m["local_port_gte"]):
                    continue
                if "local_port_not_in" in m and port in m["local_port_not_in"]:
                    continue
                target = f"{proto or 'sock'} {_get(r,'localaddr','local','source')}:{port if port is not None else '?'} {state}"
                out.append(self._finding(rule, target))
        return out


class MalfindDetector(_BaseDetector):
    category = "malfind"

    def run(self, records: list[dict]) -> list[Finding]:
        out: list[Finding] = []
        for r in records:
            prot = _get(r, "protection", "prot").lower()
            rwx = "rwx" in prot or _truthy(_get(r, "rwx"))
            row = dict(r)
            row["rwx"] = "1" if rwx else ""
            for rule in self.rules:
                m = rule["match"]
                if not Matcher.field_matches(row, m):
                    continue
                if "comm_in" in m and not Matcher.comm_in(r, m["comm_in"]):
                    continue
                # Skip the generic rwx rule if the JIT-specific rule already fired
                if rule["id"] == "rwx_region" and any(
                    Matcher.comm_in(r, jr["match"].get("comm_in", []))
                    for jr in self.rules
                    if jr["id"] == "rwx_region_jit"
                ):
                    continue
                target = f"{_get(r,'comm','process','name')}({_get(r,'pid')}) {_get(r,'address','start')}"
                out.append(self._finding(rule, target))
        return out


class SpoofingDetector(_BaseDetector):
    category = "spoofing"

    def run(self, records: list[dict]) -> list[Finding]:
        out: list[Finding] = []
        for r in records:
            for rule in self.rules:
                if Matcher.field_matches(r, rule["match"]):
                    target = f"{_get(r,'comm','process','name')}({_get(r,'pid')})"
                    out.append(self._finding(rule, target))
        return out


class ModuleDetector(_BaseDetector):
    category = "modules"

    def run(self, modules: list[dict]) -> list[Finding]:
        out: list[Finding] = []
        for mod in modules:
            for rule in self.rules:
                if Matcher.field_matches(mod, rule["match"]):
                    out.append(self._finding(rule, _get(mod, "name", "module name", "module")))
        return out


class SyscallDetector(_BaseDetector):
    category = "syscalls"

    def run(self, syscalls: list[dict]) -> list[Finding]:
        out: list[Finding] = []
        for row in syscalls:
            for rule in self.rules:
                if Matcher.field_matches(row, rule["match"]):
                    table = _get(row, "table name", "table", "table address", "name")
                    index = _get(row, "index", "idx")
                    symbol = _get(row, "symbol", "handler symbol") or "UNKNOWN"
                    target = f"{table or 'syscall'}[{index or '?'}] {symbol}".strip()
                    out.append(self._finding(rule, target))
        return out


def _local_port(row: dict) -> int | None:
    raw = _get(row, "localport", "local_port", "lport")
    if raw.isdigit():
        return int(raw)
    addr = _get(row, "localaddr", "local", "source", "laddr")
    if ":" in addr:
        tail = addr.rsplit(":", 1)[-1]
        if tail.isdigit():
            return int(tail)
    return None


# ---------------------------------------------------------------------------
# MITRE mapper
# ---------------------------------------------------------------------------


class MitreMapper:
    def __init__(self, mitre: dict) -> None:
        self.base = mitre.get("base_url", "https://attack.mitre.org/techniques/")
        self.techniques = mitre.get("techniques", {})

    def url(self, technique: str) -> str:
        parts = technique.split(".")
        if len(parts) == 2:
            return f"{self.base}{parts[0]}/{parts[1]}/"
        return f"{self.base}{parts[0]}/"

    def enrich(self, finding: Finding) -> dict[str, Any]:
        d = finding.as_dict()
        if finding.technique:
            ids = re.split(r"[·,]", finding.technique)
            d["mitre"] = [
                {
                    "id": tid.strip(),
                    "name": self.techniques.get(tid.strip(), {}).get("name"),
                    "tactic": self.techniques.get(tid.strip(), {}).get("tactic"),
                    "url": self.url(tid.strip()),
                }
                for tid in ids
                if tid.strip()
            ]
        return d


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


@lru_cache(maxsize=8)
def _load_rules(rules_dir: str, os_name: str) -> dict:
    path = Path(rules_dir) / f"{os_name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=2)
def _load_mitre(rules_dir: str) -> dict:
    return json.loads((Path(rules_dir) / "mitre.json").read_text(encoding="utf-8"))


class DetectionEngine:
    """Compose every detector and run them over an evidence bundle."""

    def __init__(self, rules_dir: Path, os_name: str = "linux") -> None:
        rules = _load_rules(str(rules_dir), os_name)
        self.mapper = MitreMapper(_load_mitre(str(rules_dir)))
        self.lineage = ProcessLineageDetector(rules)
        self.command = CommandDetector(rules)
        self.network = NetworkDetector(rules)
        self.malfind = MalfindDetector(rules)
        self.spoofing = SpoofingDetector(rules)
        self.pagecache = PagecacheDetector(rules)
        self.modules = ModuleDetector(rules)
        self.syscalls = SyscallDetector(rules)

    def analyze(
        self,
        records: list[dict] | None = None,
        pagecache: list[dict] | None = None,
        modules: list[dict] | None = None,
        syscalls: list[dict] | None = None,
    ) -> list[Finding]:
        records = records or []
        findings: list[Finding] = []
        findings += self.lineage.run(records)
        findings += self.command.run(records)
        findings += self.network.run(records)
        findings += self.malfind.run(records)
        findings += self.spoofing.run(records)
        findings += self.pagecache.run(pagecache or [])
        findings += self.modules.run(modules or [])
        findings += self.syscalls.run(syscalls or [])
        return findings

    def analyze_enriched(self, **kwargs) -> list[dict]:
        return [self.mapper.enrich(f) for f in self.analyze(**kwargs)]


class DetectionService:
    """Service-layer wrapper exposed via DI to the API."""

    def __init__(self, rules_dir: Path) -> None:
        self.rules_dir = rules_dir

    def run(
        self,
        os_name: str,
        records: list[dict],
        pagecache: list[dict],
        modules: list[dict],
        syscalls: list[dict] | None = None,
    ) -> tuple[list[dict], dict[str, int]]:
        engine = DetectionEngine(self.rules_dir, os_name)
        findings = engine.analyze(
            records=records, pagecache=pagecache, modules=modules, syscalls=syscalls or []
        )
        enriched = [engine.mapper.enrich(f) for f in findings]
        counts = {"alert": 0, "warn": 0, "info": 0}
        for f in findings:
            counts[f.level] = counts.get(f.level, 0) + 1
        return enriched, counts
