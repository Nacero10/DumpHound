"""Low-level security primitives.

These functions are pure and side-effect free so they can be unit-tested in
isolation. They raise :class:`SecurityError` / :class:`ValidationError` on any
violation. Nothing here ever interpolates user input into a shell string —
callers build ``argv`` lists element by element.
"""
from __future__ import annotations

import re
from pathlib import Path

from .exceptions import SecurityError, ValidationError

# ---------------------------------------------------------------------------
# Plugin allowlist. Only these Volatility plugins may ever be executed.
# Freeform plugin names are rejected outright.
# ---------------------------------------------------------------------------
ALLOWED_PLUGINS: frozenset[str] = frozenset(
    {
        # Linux process / memory
        "linux.pstree.PsTree",
        "linux.pslist.PsList",
        "linux.psaux.PsAux",
        "linux.psscan.PsScan",
        "linux.bash.Bash",
        "linux.lsof.Lsof",
        "linux.sockstat.Sockstat",
        "linux.envars.Envars",
        "linux.proc.Maps",
        "linux.elfs.Elfs",
        "linux.library_list.LibraryList",
        "linux.pidhashtable.PIDHashTable",
        "linux.capabilities.Capabilities",
        "linux.mountinfo.MountInfo",
        "linux.iomem.IOMem",
        "linux.kmsg.Kmsg",
        "linux.tty_check.tty_check",
        # Linux modules
        "linux.lsmod.Lsmod",
        "linux.malware.hidden_modules.Hidden_modules",
        "linux.malware.check_modules.Check_modules",
        # Linux malware / defense evasion / rootkit checks
        "linux.malware.malfind.Malfind",
        "linux.malware.process_spoofing.Process_spoofing",
        "linux.malware.check_syscall.Check_syscall",
        "linux.malware.check_idt.Check_idt",
        "linux.malware.check_afinfo.Check_afinfo",
        "linux.malware.check_creds.Check_creds",
        "linux.malware.netfilter.Netfilter",
        # Linux page cache
        "linux.pagecache.Files",
        "linux.pagecache.InodePages",
        "linux.pagecache.RecoverFs",
        # Windows process / memory
        "windows.pstree.PsTree",
        "windows.pslist.PsList",
        "windows.psscan.PsScan",
        "windows.cmdline.CmdLine",
        "windows.cmdscan.CmdScan",
        "windows.consoles.Consoles",
        "windows.dlllist.DllList",
        "windows.handles.Handles",
        "windows.getsids.GetSIDs",
        "windows.privileges.Privs",
        "windows.envars.Envars",
        # Windows network
        "windows.netscan.NetScan",
        "windows.netstat.NetStat",
        # Windows modules / drivers / kernel
        "windows.modules.Modules",
        "windows.driverscan.DriverScan",
        "windows.ssdt.SSDT",
        "windows.callbacks.Callbacks",
        # Windows malware / objects
        "windows.malfind.Malfind",
        "windows.filescan.FileScan",
        "windows.mutantscan.MutantScan",
        "windows.svcscan.SvcScan",
        # Windows registry
        "windows.registry.hivelist.HiveList",
        "windows.registry.printkey.PrintKey",
        "windows.registry.userassist.UserAssist",
    }
)

# Plugins that emit a tree / table to stdout (CSV consumable).
TABLE_PLUGINS: frozenset[str] = frozenset(
    p for p in ALLOWED_PLUGINS if not p.endswith((".InodePages", ".RecoverFs"))
)

_INODE_RE = re.compile(r"^(0x[0-9a-fA-F]+|\d+)$")
_OPTION_KEY_RE = re.compile(r"^[a-z0-9_-]+$")
_OPTION_VAL_RE = re.compile(r"^[A-Za-z0-9_./:=,+-]*$")


def validate_plugin(plugin: str) -> str:
    """Return *plugin* iff it is on the allowlist, else raise."""
    if plugin not in ALLOWED_PLUGINS:
        raise SecurityError(f"Plugin not permitted: {plugin!r}")
    return plugin


def resolve_image(name: str, image_dir: Path) -> Path:
    """Resolve a memory-image *name* safely inside ``image_dir``.

    Rejects any name containing path separators or ``..`` and verifies the
    resolved path is contained within ``image_dir`` (defeats symlink / traversal
    escapes).
    """
    if not name or any(c in name for c in ("/", "\\")) or ".." in name:
        raise SecurityError(f"Illegal image name: {name!r}")
    candidate = (image_dir / name).resolve()
    try:
        candidate.relative_to(image_dir.resolve())
    except ValueError as exc:  # pragma: no cover - defensive
        raise SecurityError("Image escapes image directory") from exc
    if not candidate.is_file():
        raise ValidationError(f"Image not found: {name!r}")
    return candidate


def validate_inode(inode: str) -> str:
    """Validate an inode address/number.

    Accepts a hex address (``0x88c1a2b40000``) or a decimal inode number.
    Injection payloads such as ``0x1; rm -rf /`` are rejected.
    """
    if not _INODE_RE.match(inode):
        raise ValidationError(f"Invalid inode token: {inode!r}")
    return inode


def validate_option(key: str, value: str | None) -> tuple[str, str | None]:
    """Validate a single ``--key value`` Volatility option pair."""
    if not _OPTION_KEY_RE.match(key):
        raise ValidationError(f"Invalid option key: {key!r}")
    if value is not None and not _OPTION_VAL_RE.match(value):
        raise ValidationError(f"Invalid option value for {key!r}")
    return key, value


def safe_output_subdir(output_dir: Path, token: str) -> Path:
    """Create/return an isolated output subdirectory keyed by *token*.

    *token* must be a hex/alphanumeric job identifier; this prevents one job's
    artifacts from landing in another job's directory.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", token):
        raise ValidationError("Invalid output token")
    sub = (output_dir / token).resolve()
    try:
        sub.relative_to(output_dir.resolve())
    except ValueError as exc:  # pragma: no cover - defensive
        raise SecurityError("Output escapes output directory") from exc
    sub.mkdir(parents=True, exist_ok=True)
    return sub
