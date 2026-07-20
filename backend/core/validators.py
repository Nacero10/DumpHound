"""Higher-level validators used by routers/services.

These compose the primitives in :mod:`core.security` into request-shaped
helpers and build the final, fully-validated ``argv`` list for Volatility.
"""
from __future__ import annotations

from pathlib import Path

from .config import Settings
from .security import (
    TABLE_PLUGINS,
    resolve_image,
    safe_output_subdir,
    validate_inode,
    validate_option,
    validate_plugin,
)


def build_run_argv(
    settings: Settings,
    image_name: str,
    plugin: str,
    options: dict[str, str | None] | None = None,
    renderer: str = "csv",
) -> list[str]:
    """Build a validated argv for a table-producing plugin run."""
    validate_plugin(plugin)
    if plugin not in TABLE_PLUGINS:
        from .exceptions import ValidationError

        raise ValidationError(f"{plugin} does not produce a table; use a dump endpoint")
    image = resolve_image(image_name, settings.image_dir)

    argv: list[str] = [settings.bin, "-q", "-f", str(image), "-r", renderer]
    if settings.symbol_dir:
        argv += ["-s", str(settings.symbol_dir)]
    if settings.offline:
        argv.append("--offline")
    argv.append(plugin)
    for key, value in (options or {}).items():
        k, v = validate_option(key, value)
        argv.append(f"--{k}")
        if v is not None:
            argv.append(v)
    return argv


def build_inode_dump_argv(
    settings: Settings, image_name: str, inode: str, out_token: str
) -> tuple[list[str], Path]:
    """Build argv for ``linux.pagecache.InodePages --inode <addr> --dump``."""
    image = resolve_image(image_name, settings.image_dir)
    addr = validate_inode(inode)
    out = safe_output_subdir(settings.output_dir, out_token)

    argv: list[str] = [settings.bin, "-f", str(image), "-o", str(out)]
    if settings.symbol_dir:
        argv += ["-s", str(settings.symbol_dir)]
    if settings.offline:
        argv.append("--offline")
    argv += ["linux.pagecache.InodePages", "--inode", addr, "--dump"]
    return argv, out


def build_recoverfs_argv(
    settings: Settings, image_name: str, out_token: str
) -> tuple[list[str], Path]:
    """Build argv for bulk ``linux.pagecache.RecoverFs`` extraction."""
    image = resolve_image(image_name, settings.image_dir)
    out = safe_output_subdir(settings.output_dir, out_token)

    argv: list[str] = [settings.bin, "-f", str(image), "-o", str(out)]
    if settings.symbol_dir:
        argv += ["-s", str(settings.symbol_dir)]
    if settings.offline:
        argv.append("--offline")
    argv.append("linux.pagecache.RecoverFs")
    return argv, out
