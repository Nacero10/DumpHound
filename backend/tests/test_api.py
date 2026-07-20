"""API integration tests (FastAPI TestClient). No real Volatility needed."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path: Path, monkeypatch) -> TestClient:
    backend_root = Path(__file__).resolve().parents[1]
    img = tmp_path / "images"
    out = tmp_path / "dumps"
    img.mkdir()
    out.mkdir()
    (img / "memdump.mem").write_bytes(b"\x00" * 32)

    monkeypatch.setenv("VOL_IMAGE_DIR", str(img))
    monkeypatch.setenv("VOL_OUTPUT_DIR", str(out))
    monkeypatch.setenv("VOL_RULES_DIR", str(backend_root / "rules"))
    monkeypatch.setenv("VOL_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("VOL_BIN", "definitely-not-a-real-vol-binary")

    # Clear cached settings/container so env vars take effect.
    from core import config, container

    config.get_settings.cache_clear()
    container.get_container.cache_clear()

    from app import create_app

    return TestClient(create_app())


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["volatility_available"] is False
    assert body["plugins_allowed"] > 0


def test_list_images(client):
    r = client.get("/api/images")
    assert r.status_code == 200
    names = [i["name"] for i in r.json()["images"]]
    assert "memdump.mem" in names


def test_list_plugins(client):
    r = client.get("/api/plugins")
    assert r.status_code == 200
    plugins = r.json()["plugins"]
    assert any(p["name"] == "linux.pstree.PsTree" for p in plugins)


def test_run_plugin_rejects_disallowed(client):
    r = client.post(
        "/api/plugins/run", json={"image": "memdump.mem", "plugin": "linux.evil.Run"}
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "security_error"


def test_run_plugin_volatility_missing(client):
    r = client.post(
        "/api/plugins/run", json={"image": "memdump.mem", "plugin": "linux.pstree.PsTree"}
    )
    # vol binary intentionally absent -> graceful 200 with 0 rows and a reason,
    # so the UI can surface *why* it failed instead of an opaque 502.
    assert r.status_code == 200
    body = r.json()
    assert body["rows"] == 0
    assert body["csv"] == ""
    assert body["stderr"]  # carries the failure reason


def test_detect_endpoint(client):
    payload = {
        "os": "linux",
        "records": [{"pid": "1", "command": "history -c"}],
        "pagecache": [{"FilePath": "/etc/ld.so.preload"}],
        "modules": [],
    }
    r = client.post("/api/plugins/detect", json=payload)
    assert r.status_code == 200
    body = r.json()
    rules = {f["rule"] for f in body["findings"]}
    assert "ld_preload" in rules
    assert "history_clear" in rules
    assert body["counts"]["alert"] >= 1


def test_dump_rejects_inode_injection(client):
    r = client.post(
        "/api/dumps/inode", json={"image": "memdump.mem", "inode": "0x1; rm -rf /"}
    )
    assert r.status_code == 400


def test_download_unknown_token_404(client):
    r = client.get("/api/dumps/download/nonexistent-token")
    assert r.status_code == 404


def test_openapi_served(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200
<<<<<<< HEAD
    assert r.json()["info"]["title"] == "DumpHound API"
=======
    assert r.json()["info"]["title"] == "ProcTree Workbench API"
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e


def test_activity_log_records_and_lists():
    from services.activity import ActivityLog

    al = ActivityLog(maxlen=3)
    al.record(kind="run", status="error", argv=["vol", "x"], duration_ms=12,
              returncode=1, plugin="linux.pstree.PsTree", stderr="Unsatisfied requirement",
              message="symbols missing")
    al.record(kind="run", status="ok", argv=["vol", "y"], duration_ms=8,
              returncode=0, plugin="linux.lsmod.Lsmod", rows=42)
    events = al.list()
    assert events[0]["plugin"] == "linux.lsmod.Lsmod"   # newest first
    assert events[0]["status"] == "ok"
    assert events[1]["status"] == "error"
    assert events[1]["message"] == "symbols missing"
    # ring buffer caps length
    for i in range(5):
        al.record(kind="run", status="ok", argv=["vol", str(i)], duration_ms=1)
    assert len(al.list()) == 3


def test_activity_endpoint(client):
    r = client.get("/api/activity")
    assert r.status_code == 200
    assert "events" in r.json()
