"""Android adb collector + AndroidSecurityDetector tests."""

from __future__ import annotations

import datetime as _dt


from digger.android import (
    AndroidCollectSummary,
    AndroidPackage,
    discover_binary,
    parse_dumpsys_package,
    parse_pm_list_packages,
)
from digger.android.collector import (
    _ingest_dump,
    _list_devices,
    _run_adb,
)
from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.android_security import (
    AndroidSecurityDetector,
    PLAY_STORE_PKGS,
    STALKERWARE_KNOWN_INSTALLERS,
)


# ---- binary discovery ---- #


def test_discover_binary_honors_env(monkeypatch, tmp_path):
    fake = tmp_path / "fake_adb"
    fake.write_text("#!/bin/sh\necho hi\n")
    fake.chmod(0o755)
    monkeypatch.setenv("DIGGER_ADB_BIN", str(fake))
    assert discover_binary() == str(fake)


def test_discover_binary_env_missing_returns_none(monkeypatch):
    monkeypatch.setenv("DIGGER_ADB_BIN", "/nonexistent/zzz")
    assert discover_binary() is None


def test_discover_binary_path_scan(monkeypatch):
    monkeypatch.delenv("DIGGER_ADB_BIN", raising=False)
    monkeypatch.setattr(
        "digger.android.collector.shutil.which",
        lambda name: "/usr/bin/adb" if name == "adb" else None,
    )
    assert discover_binary() == "/usr/bin/adb"


# ---- _run_adb error handling ---- #


def test_run_adb_handles_missing_binary():
    rc, out, err = _run_adb("/nonexistent/abs/adb", ["devices"],
                            timeout=2)
    assert rc != 0
    assert err.startswith("adb invocation failed")


def test_run_adb_serial_flag_constructed(monkeypatch):
    captured = {}

    class FakeProc:
        returncode = 0
        stdout = b"ok"
        stderr = b""

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(
        "digger.android.collector.subprocess.run", fake_run,
    )
    _run_adb("/bin/true", ["shell", "id"], serial="emulator-5554")
    assert "-s" in captured["cmd"]
    assert "emulator-5554" in captured["cmd"]


# ---- _list_devices parser ---- #


def test_list_devices_returns_only_authorized(monkeypatch):
    sample = (
        "List of devices attached\n"
        "emulator-5554\tdevice\n"
        "ABCD1234\toffline\n"
        "1Z21D\tunauthorized\n"
        "XYZ9999\tdevice\n"
    )

    monkeypatch.setattr(
        "digger.android.collector._run_adb",
        lambda binary, args, **kw: (0, sample, ""),
    )
    serials = _list_devices("/bin/adb")
    assert serials == ["emulator-5554", "XYZ9999"]


def test_list_devices_handles_failed_invocation(monkeypatch):
    monkeypatch.setattr(
        "digger.android.collector._run_adb",
        lambda binary, args, **kw: (1, "", "boom"),
    )
    assert _list_devices("/bin/adb") == []


# ---- pm list packages parser ---- #


def test_parse_pm_list_packages_basic():
    out = (
        "package:/data/app/foo/base.apk=com.example.foo "
        "installer=com.android.vending uid:10042\n"
        "package:/data/app/bar/base.apk=com.example.bar "
        "installer=com.android.shell uid:10043\n"
    )
    parsed = parse_pm_list_packages(out)
    assert len(parsed) == 2
    assert parsed[0]["name"] == "com.example.foo"
    assert parsed[0]["installer"] == "com.android.vending"
    assert parsed[1]["installer"] == "com.android.shell"


def test_parse_pm_list_packages_fallback_simple_form():
    out = "package:com.example.simple\n"
    parsed = parse_pm_list_packages(out)
    assert len(parsed) == 1
    assert parsed[0]["name"] == "com.example.simple"


def test_parse_pm_list_packages_with_path_no_installer():
    out = "package:/data/app/x/base.apk=com.example.no_installer\n"
    parsed = parse_pm_list_packages(out)
    assert len(parsed) == 1
    assert parsed[0]["name"] == "com.example.no_installer"
    assert parsed[0]["installer"] == ""


def test_parse_pm_list_packages_ignores_garbage():
    out = "garbage line\nlist of devices\n"
    parsed = parse_pm_list_packages(out)
    assert parsed == []


# ---- dumpsys package parser ---- #


def test_parse_dumpsys_package_grabs_version_and_installer():
    out = (
        "Package [com.example.foo] (1234):\n"
        "  versionName=1.0.0\n"
        "  versionCode=42\n"
        "  installerPackageName=com.android.vending\n"
        "  targetSdk=33\n"
        "  primaryCpuAbi=arm64-v8a\n"
        "  codePath=/data/app/foo/base.apk\n"
        "  flags=[ SYSTEM HAS_CODE ENABLED ]\n"
    )
    pkg = parse_dumpsys_package(out, "com.example.foo")
    assert pkg.name == "com.example.foo"
    assert pkg.version_name == "1.0.0"
    assert pkg.version_code == "42"
    assert pkg.install_source == "com.android.vending"
    assert pkg.target_sdk == "33"
    assert pkg.is_system is True
    assert "SYSTEM" in pkg.flags


def test_parse_dumpsys_package_debuggable():
    out = (
        "Package [com.example.foo]:\n"
        "  flags=[ DEBUGGABLE HAS_CODE ]\n"
    )
    pkg = parse_dumpsys_package(out, "com.example.foo")
    assert pkg.debuggable is True


def test_parse_dumpsys_package_collects_granted_permissions():
    out = (
        "Package [com.example.spy]:\n"
        "  versionName=1.0\n"
        "  install permissions:\n"
        "    android.permission.READ_SMS: granted=true\n"
        "    android.permission.RECORD_AUDIO: granted=true\n"
        "    android.permission.BIND_ACCESSIBILITY_SERVICE: granted=true\n"
        "  requested permissions:\n"
        "    android.permission.READ_CONTACTS\n"
        "    android.permission.READ_SMS\n"
    )
    pkg = parse_dumpsys_package(out, "com.example.spy")
    assert "android.permission.READ_SMS" in pkg.granted_permissions
    assert "android.permission.RECORD_AUDIO" in pkg.granted_permissions
    assert "android.permission.BIND_ACCESSIBILITY_SERVICE" \
        in pkg.granted_permissions
    assert "android.permission.READ_CONTACTS" in pkg.requested_permissions


def test_parse_dumpsys_package_no_install_source_for_sideload():
    out = "Package [com.x]:\n  versionName=1\n"
    pkg = parse_dumpsys_package(out, "com.x")
    assert pkg.install_source == ""


# ---- ingest helper + summary ---- #


def test_ingest_dump_writes_artifact(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        pkg = AndroidPackage(name="com.foo", version_name="1.0")
        _ingest_dump(store, "emulator-5554", pkg)
        arts = list(store.iter_artifacts(collector="android.package",
                                          category="mobile"))
        assert len(arts) == 1
        assert arts[0]["data"]["name"] == "com.foo"
    finally:
        store.close()


def test_summary_dataclass_defaults():
    s = AndroidCollectSummary(binary="/x/adb", serial=None)
    assert s.packages_listed == 0
    assert s.errors == []


# ---- detector helpers ---- #


def _seed_pkg(store, serial="ABCDEF", **kwargs):
    pkg = AndroidPackage(name="com.test.app")
    for k, v in kwargs.items():
        setattr(pkg, k, v)
    _ingest_dump(store, serial, pkg)


def test_play_store_pkgs_known_set():
    assert "com.android.vending" in PLAY_STORE_PKGS


def test_stalkerware_installer_set_includes_known():
    assert "com.android.fileinstall" in STALKERWARE_KNOWN_INSTALLERS


# ---- A1 sideload ---- #


def test_detector_a1_sideload_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   install_source="com.example.thirdparty",
                   is_system=False)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "sideload"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_a1_sideload_high_for_known_stalkerware_installer(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   install_source="com.android.fileinstall",
                   is_system=False)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "sideload"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_a1_no_finding_for_play_install(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   install_source="com.android.vending",
                   is_system=False)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "sideload"]
    finally:
        store.close()


def test_detector_a1_no_finding_for_system(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   install_source="com.some.thing",
                   is_system=True)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "sideload"]
    finally:
        store.close()


# ---- A2 accessibility abuse ---- #


def test_detector_a2_accessibility_abuse_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   install_source="com.example.sideload",
                   granted_permissions=[
                       "android.permission.BIND_ACCESSIBILITY_SERVICE",
                   ],
                   is_system=False)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "accessibility_abuse"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].mitre == "T1417"
    finally:
        store.close()


def test_detector_a2_no_finding_for_play_installed(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   install_source="com.android.vending",
                   granted_permissions=[
                       "android.permission.BIND_ACCESSIBILITY_SERVICE",
                   ],
                   is_system=False)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "accessibility_abuse"]
    finally:
        store.close()


def test_detector_a2_no_finding_for_system_accessibility(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   granted_permissions=[
                       "android.permission.BIND_ACCESSIBILITY_SERVICE",
                   ],
                   is_system=True)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "accessibility_abuse"]
    finally:
        store.close()


# ---- A3 device admin ---- #


def test_detector_a3_device_admin_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   install_source="com.example.sideload",
                   granted_permissions=[
                       "android.permission.BIND_DEVICE_ADMIN",
                   ],
                   is_system=False)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "device_admin_unexpected"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].mitre == "T1626"
    finally:
        store.close()


# ---- A4 swiss-army-knife permission combo ---- #


def test_detector_a4_permission_combo_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   install_source="com.example.sideload",
                   granted_permissions=[
                       "android.permission.READ_SMS",
                       "android.permission.READ_CONTACTS",
                       "android.permission.RECORD_AUDIO",
                   ],
                   is_system=False)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "permission_combo_swissarmy"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


def test_detector_a4_no_finding_for_partial_combo(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   install_source="com.example.sideload",
                   granted_permissions=[
                       "android.permission.READ_SMS",
                       "android.permission.READ_CONTACTS",
                   ],
                   is_system=False)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "permission_combo_swissarmy"]
    finally:
        store.close()


def test_detector_a4_uses_requested_perms_too(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_pkg(store,
                   install_source="com.example.sideload",
                   granted_permissions=[
                       "android.permission.READ_SMS",
                   ],
                   requested_permissions=[
                       "android.permission.READ_CONTACTS",
                       "android.permission.CAMERA",
                   ],
                   is_system=False)
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "permission_combo_swissarmy"]
        assert len(f) == 1
    finally:
        store.close()


# ---- A5 stale security patch ---- #


def test_detector_a5_stale_security_patch(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        # 2 years old.
        very_old = (_dt.date.today()
                    - _dt.timedelta(days=730)).isoformat()
        store.add_artifact(Artifact(
            collector="android.security_patch",
            category="mobile",
            subject="android:security_patch:ABCDEF",
            data={"serial": "ABCDEF", "raw": very_old},
        ))
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "stale_security_patch"]
        assert len(f) == 1
        assert f[0].severity == "high"  # >365 days
    finally:
        store.close()


def test_detector_a5_recent_patch_no_finding(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        recent = _dt.date.today().isoformat()
        store.add_artifact(Artifact(
            collector="android.security_patch",
            category="mobile",
            subject="android:security_patch:ABCDEF",
            data={"serial": "ABCDEF", "raw": recent},
        ))
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "stale_security_patch"]
    finally:
        store.close()


def test_detector_a5_handles_invalid_patch_date(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="android.security_patch",
            category="mobile",
            subject="android:security_patch:ABCDEF",
            data={"serial": "ABCDEF", "raw": "not a date"},
        ))
        det = AndroidSecurityDetector()
        # Should not crash.
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "stale_security_patch"]
    finally:
        store.close()


# ---- A6 install_non_market_apps ---- #


def test_detector_a6_non_market_install_enabled(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="android.install_non_market_apps",
            category="mobile",
            subject="android:install_non_market_apps:ABCDEF",
            data={"serial": "ABCDEF", "raw": "1"},
        ))
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "non_market_installs_enabled"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_detector_a6_non_market_install_disabled(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="android.install_non_market_apps",
            category="mobile",
            subject="android:install_non_market_apps:ABCDEF",
            data={"serial": "ABCDEF", "raw": "0"},
        ))
        det = AndroidSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "non_market_installs_enabled"]
    finally:
        store.close()


# ---- detector: registration / sigma ---- #


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        det = AndroidSecurityDetector()
        assert list(det.detect(store)) == []
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "android_security" in names


def test_detector_sigma_template_has_mobile_attack_tags():
    det = AndroidSecurityDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-android-security-template"
    assert "attack.t1417" in tpl["tags"]
    assert tpl["logsource"]["product"] == "android"
