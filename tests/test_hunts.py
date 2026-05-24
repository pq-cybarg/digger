"""Hunt library: registry, execution, individual canned hunts."""

from __future__ import annotations

import json
from pathlib import Path

from digger.core import Artifact, EvidenceStore
from digger.hunts import all_hunts, run_hunt
from digger.hunts.report import render_hunts_html, render_hunts_json, render_hunts_markdown


def test_registry_populated():
    hunts = all_hunts()
    assert len(hunts) >= 12
    ids = {h.id for h in hunts}
    for required in [
        "browser-spawns-shell", "encoded-powershell", "curl-pipe-bash",
        "dynamic-linker-hijack", "shell-init-hook", "interpreter-in-temp",
        "ssh-key-forced-command", "browser-extension-sweeping-perms",
        "uncommon-listener", "process-without-exe-path",
        "shai-hulud-packages",
    ]:
        assert required in ids, f"missing hunt: {required}"


def test_browser_spawns_shell_catches_chrome_to_bash(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(collector="processes", category="process",
                                subject="pid=1487 chrome",
                                data={"pid": 1487, "ppid": 1, "name": "Google Chrome",
                                      "exe": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                                      "cmdline": ["chrome"], "username": "alice"}))
    store.add_artifact(Artifact(collector="processes", category="process",
                                subject="pid=2204 bash",
                                data={"pid": 2204, "ppid": 1487, "name": "bash",
                                      "exe": "/bin/bash",
                                      "cmdline": ["/bin/bash", "-c", "echo hi"],
                                      "username": "alice"}))
    r = run_hunt(store, "browser-spawns-shell")
    assert r.count == 1
    row = r.rows[0]
    assert row["child_name"] == "bash"
    assert row["parent_name"] == "Google Chrome"
    store.close()


def test_encoded_powershell_catches_long_base64(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    big = "A" * 80
    store.add_artifact(Artifact(collector="processes", category="process",
                                subject="pid=900 powershell.exe",
                                data={"pid": 900, "ppid": 1, "name": "powershell.exe",
                                      "exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                                      "cmdline": ["powershell.exe", "-EncodedCommand", big],
                                      "username": "DOM\\victim"}))
    r = run_hunt(store, "encoded-powershell")
    assert r.count == 1
    store.close()


def test_ld_preload_caught(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(collector="env", category="environment", subject="interesting",
                                data={"values": {"LD_PRELOAD": "/tmp/.evil.so",
                                                  "PATH": "/usr/bin"}}))
    r = run_hunt(store, "dynamic-linker-hijack")
    assert r.count == 1
    assert r.rows[0]["variable"] == "LD_PRELOAD"
    store.close()


def test_no_rows_when_clean(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(collector="processes", category="process",
                                subject="pid=1 init",
                                data={"pid": 1, "ppid": 0, "name": "init",
                                      "exe": "/sbin/init", "cmdline": ["init"], "username": "root"}))
    r = run_hunt(store, "browser-spawns-shell")
    assert r.count == 0
    r2 = run_hunt(store, "encoded-powershell")
    assert r2.count == 0
    store.close()


def test_shai_hulud_hunt(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.add_artifact(Artifact(collector="npm_packages", category="inventory",
                                subject="npm:/proj",
                                data={"project": "/proj",
                                      "locked_packages": {"chalk": "5.6.1", "react": "19.0.0"},
                                      "declared_deps": {}, "declared_dev_deps": {}}))
    r = run_hunt(store, "shai-hulud-packages")
    assert r.count >= 1
    assert any("chalk@5.6.1" in row["package"] for row in r.rows)
    store.close()


def test_renderers_emit_output(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.set_meta("host", {"node": "demo"})
    store.add_artifact(Artifact(collector="env", category="environment", subject="interesting",
                                data={"values": {"LD_PRELOAD": "/tmp/x.so"}}))
    results = [run_hunt(store, "dynamic-linker-hijack")]
    j = json.loads(render_hunts_json(results))
    assert j[0]["count"] == 1
    md = render_hunts_markdown(results)
    assert "LD_PRELOAD" in md
    html = render_hunts_html(results, host={"node": "demo"})
    assert "LD_PRELOAD" in html
    assert "<svg" in html
    store.close()


def test_double_register_rejected():
    from digger.hunts.base import Hunt, register
    h = Hunt(id="browser-spawns-shell", title="dup", description="d",
             columns=[], fn=lambda s: [])
    try:
        register(h)
    except ValueError as exc:
        assert "duplicate" in str(exc)
    else:
        raise AssertionError("expected ValueError on duplicate hunt id")
