"""Security guard tests — path traversal, plugin allowlist, inode injection."""
from __future__ import annotations

import pytest

from core.exceptions import SecurityError, ValidationError
from core.security import (
    resolve_image,
    safe_output_subdir,
    validate_inode,
    validate_option,
    validate_plugin,
)
from core.validators import build_inode_dump_argv, build_run_argv


def test_plugin_allowlist_accepts_known():
    assert validate_plugin("linux.pstree.PsTree") == "linux.pstree.PsTree"


def test_plugin_allowlist_rejects_unknown():
    with pytest.raises(SecurityError):
        validate_plugin("linux.evil.RunShell")


@pytest.mark.parametrize("bad", ["../../etc/passwd", "a/b", "x\\y", "..", "../mem.mem"])
def test_resolve_image_rejects_traversal(settings, bad):
    with pytest.raises(SecurityError):
        resolve_image(bad, settings.image_dir)


def test_resolve_image_rejects_missing(settings):
    with pytest.raises(ValidationError):
        resolve_image("does-not-exist.mem", settings.image_dir)


def test_resolve_image_accepts_valid(settings):
    p = resolve_image("memdump.mem", settings.image_dir)
    assert p.name == "memdump.mem"


@pytest.mark.parametrize("good", ["0x88c1a2b40000", "12345", "0xABCDEF"])
def test_inode_valid(good):
    assert validate_inode(good) == good


@pytest.mark.parametrize("bad", ["0x1; rm -rf /", "$(whoami)", "12 34", "0xGG", "", "`id`"])
def test_inode_rejects_injection(bad):
    with pytest.raises(ValidationError):
        validate_inode(bad)


def test_option_key_validation():
    assert validate_option("pid", "1234") == ("pid", "1234")
    with pytest.raises(ValidationError):
        validate_option("pid; rm", "1")


def test_option_value_validation():
    with pytest.raises(ValidationError):
        validate_option("find", "name`whoami`")


def test_output_subdir_isolation(settings):
    sub = safe_output_subdir(settings.output_dir, "abc123")
    assert sub.is_dir()
    with pytest.raises(ValidationError):
        safe_output_subdir(settings.output_dir, "../escape")


def test_build_run_argv_is_argv_list(settings):
    argv = build_run_argv(settings, "memdump.mem", "linux.pstree.PsTree")
    assert argv[0] == "vol"
    assert "--offline" in argv
    assert argv[-1] == "linux.pstree.PsTree"
    # No element contains a shell metacharacter sequence
    assert not any(";" in a or "|" in a for a in argv)


def test_build_run_argv_rejects_dump_plugin(settings):
    with pytest.raises(ValidationError):
        build_run_argv(settings, "memdump.mem", "linux.pagecache.RecoverFs")


def test_inode_dump_argv_uses_inode_addr(settings):
    argv, out = build_inode_dump_argv(settings, "memdump.mem", "0x88c1a2b40000", "tok1")
    assert "--inode" in argv
    assert "0x88c1a2b40000" in argv
    assert "--dump" in argv
    assert out.is_dir()


def test_inode_dump_argv_rejects_injection(settings):
    with pytest.raises(ValidationError):
        build_inode_dump_argv(settings, "memdump.mem", "0x1; cat /etc/shadow", "tok2")
