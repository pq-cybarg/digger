"""macOS TCC detector tests."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.macos_tcc import (
    KNOWN_GOOD_BUNDLE_IDS,
    MacosTccDetector,
    _has_suspicious_path,
    _is_apple_client,
    _is_trusted_client,
    _tcc_entry_records,
    _trusted_bundle_set,
)


# ---- _is_apple_client ---- #


def test_is_apple_client_bundle_id():
    assert _is_apple_client("com.apple.systempreferences", 0) is True
    assert _is_apple_client("com.apple.controlcenter", 0) is True
    assert _is_apple_client("us.zoom.xos", 0) is False


def test_is_apple_client_path():
    assert _is_apple_client("/System/Library/CoreServices/x", 1) is True
    assert _is_apple_client("/usr/libexec/sshd-keygen-wrapper", 1) is True
    assert _is_apple_client("/Applications/Zoom.app/x", 1) is False


def test_is_apple_client_empty():
    assert _is_apple_client("", 0) is False
    assert _is_apple_client("x", 99) is False  # unknown type


# ---- _is_trusted_client ---- #


def test_is_trusted_client_known_bundles():
    assert _is_trusted_client("us.zoom.xos", 0) is True
    assert _is_trusted_client("com.tinyspeck.slackmacgap", 0) is True


def test_is_trusted_client_path_form_not_in_allowlist():
    # path-form clients are never directly allowlisted; the
    # operator can use the trusted-bundle env var only for type=0.
    assert _is_trusted_client("/Applications/Zoom.app/zoom", 1) is False


def test_is_trusted_client_unknown_bundle():
    assert _is_trusted_client("com.evil.app", 0) is False


def test_trusted_bundle_env_override(monkeypatch):
    monkeypatch.setenv("DIGGER_TCC_TRUSTED_CLIENTS",
                        "com.mycorp.app, com.other.thing")
    s = _trusted_bundle_set()
    assert "com.mycorp.app" in s
    assert "com.other.thing" in s


# ---- _has_suspicious_path ---- #


def test_has_suspicious_path_tmp():
    assert _has_suspicious_path("/tmp/x.app", 1) is True
    assert _has_suspicious_path("/private/var/folders/x/y", 1) is True


def test_has_suspicious_path_shared():
    assert _has_suspicious_path("/Users/Shared/evil.app/Contents/MacOS/evil", 1) is True


def test_has_suspicious_path_safe_path():
    assert _has_suspicious_path("/Applications/Zoom.app/x", 1) is False


def test_has_suspicious_path_not_path_type():
    # bundle-form client (type=0) — never suspicious-path
    assert _has_suspicious_path("/tmp/x", 0) is False


# ---- _tcc_entry_records ---- #


def _make_tcc_artifact(
    path: str,
    entries: list[dict],
):
    return Artifact(
        collector="macos.tcc",
        category="security_posture",
        subject=f"tcc:{path}",
        data={"path": path, "entries": entries, "count": len(entries)},
    )


def test_tcc_entry_records_flattens(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_tcc_artifact(
            "/Library/Application Support/com.apple.TCC/TCC.db",
            [{"client": "com.x", "service": "kTCCServiceCamera",
              "auth_value": 2, "client_type": 0}],
        ))
        store.add_artifact(_make_tcc_artifact(
            "/Users/alice/Library/Application Support/com.apple.TCC/TCC.db",
            [{"client": "com.y", "service": "kTCCServiceMicrophone",
              "auth_value": 2, "client_type": 0}],
        ))
        recs = _tcc_entry_records(store)
        assert len(recs) == 2
    finally:
        store.close()


def test_tcc_entry_records_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        assert _tcc_entry_records(store) == []
    finally:
        store.close()


# ---- detector ---- #


def _seed_entries(store: EvidenceStore,
                   entries: list[dict],
                   path: str = "/Library/Application Support/com.apple.TCC/TCC.db"):
    store.add_artifact(_make_tcc_artifact(path, entries))


# T1 FullDiskAccess


def test_detector_t1_fulldisk_nonapple_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.app",
            "service": "kTCCServiceSystemPolicyAllFiles",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "tcc_fulldisk_nonapple"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1543.001"
    finally:
        store.close()


def test_detector_t1_documents_folder_class(tmp_path):
    """Per-folder FullDiskAccess variants also fire T1."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.app",
            "service": "kTCCServiceSystemPolicyDocumentsFolder",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "tcc_fulldisk_nonapple"]
        assert len(f) == 1
    finally:
        store.close()


def test_detector_t1_skips_apple_client(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.apple.spotlight",
            "service": "kTCCServiceSystemPolicyAllFiles",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "tcc_fulldisk_nonapple"]
    finally:
        store.close()


def test_detector_t1_skips_trusted_client(tmp_path):
    """Allowlisted clients (Zoom etc) shouldn't fire."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "us.zoom.xos",
            "service": "kTCCServiceSystemPolicyAllFiles",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        assert findings == []
    finally:
        store.close()


def test_detector_t1_skips_denied_grant(tmp_path):
    """auth_value=0 (denied) should not fire any T1-T4 finding."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.app",
            "service": "kTCCServiceSystemPolicyAllFiles",
            "auth_value": 0, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        assert findings == []
    finally:
        store.close()


# T2 Accessibility / PostEvent / ListenEvent


def test_detector_t2_accessibility_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.spyware",
            "service": "kTCCServiceAccessibility",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "tcc_accessibility_nonapple"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].mitre == "T1056.001"
    finally:
        store.close()


def test_detector_t2_postevent_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.spyware",
            "service": "kTCCServicePostEvent",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "tcc_accessibility_nonapple"]
        assert len(f) == 1
        assert f[0].severity == "critical"
    finally:
        store.close()


# T3 suspicious path


def test_detector_t3_tmp_path_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "/tmp/install.app/Contents/MacOS/install",
            "service": "kTCCServiceAccessibility",
            "auth_value": 2, "client_type": 1,
        }])
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "tcc_suspicious_path_grant"]
        assert len(f) == 1
        assert f[0].severity == "critical"
    finally:
        store.close()


def test_detector_t3_shared_path_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "/Users/Shared/x.app/Contents/MacOS/x",
            "service": "kTCCServiceCamera",
            "auth_value": 2, "client_type": 1,
        }])
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "tcc_suspicious_path_grant"]
        assert len(f) == 1
    finally:
        store.close()


def test_detector_t3_skips_apple_system_path(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "/System/Library/CoreServices/iconservicesagent",
            "service": "kTCCServiceCamera",
            "auth_value": 2, "client_type": 1,
        }])
        findings = list(MacosTccDetector().detect(store))
        assert findings == []
    finally:
        store.close()


# T4 surveillance services


def test_detector_t4_camera_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.app",
            "service": "kTCCServiceCamera",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "tcc_screencap_camera_nonapple"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1125"
    finally:
        store.close()


def test_detector_t4_microphone_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.app",
            "service": "kTCCServiceMicrophone",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "tcc_screencap_camera_nonapple"]
        assert f[0].mitre == "T1123"
    finally:
        store.close()


def test_detector_t4_screencap_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.app",
            "service": "kTCCServiceScreenCapture",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "tcc_screencap_camera_nonapple"]
        assert f[0].mitre == "T1113"
    finally:
        store.close()


def test_detector_t4_appleevents_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.app",
            "service": "kTCCServiceAppleEvents",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "tcc_screencap_camera_nonapple"]
        assert f[0].mitre == "T1559.001"
    finally:
        store.close()


# T5 user-DB-only grant


def test_detector_t5_user_db_only_critical(tmp_path):
    """Grant in user TCC but no matching entry in system TCC =
    direct-write bypass shape."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [
            {"client": "com.someother.app",
             "service": "kTCCServiceCamera",
             "auth_value": 2, "client_type": 0},
        ], path="/Library/Application Support/com.apple.TCC/TCC.db")
        _seed_entries(store, [
            {"client": "com.evilcorp.app",
             "service": "kTCCServiceAccessibility",
             "auth_value": 2, "client_type": 0},
        ], path="/Users/alice/Library/Application Support/"
                 "com.apple.TCC/TCC.db")
        findings = list(MacosTccDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "tcc_user_db_only_grant"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["client"] == "com.evilcorp.app"
    finally:
        store.close()


def test_detector_t5_skipped_when_only_one_db_collected(tmp_path):
    """If only the user DB was collected, no T5."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [
            {"client": "com.evilcorp.app",
             "service": "kTCCServiceAccessibility",
             "auth_value": 2, "client_type": 0},
        ], path="/Users/alice/Library/Application Support/"
                 "com.apple.TCC/TCC.db")
        findings = list(MacosTccDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "tcc_user_db_only_grant"]
    finally:
        store.close()


def test_detector_t5_skipped_if_system_db_also_has_entry(tmp_path):
    """If the system DB also has the entry, user-DB-only doesn't apply."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [
            {"client": "com.evilcorp.app",
             "service": "kTCCServiceAccessibility",
             "auth_value": 2, "client_type": 0},
        ], path="/Library/Application Support/com.apple.TCC/TCC.db")
        _seed_entries(store, [
            {"client": "com.evilcorp.app",
             "service": "kTCCServiceAccessibility",
             "auth_value": 2, "client_type": 0},
        ], path="/Users/alice/Library/Application Support/"
                 "com.apple.TCC/TCC.db")
        findings = list(MacosTccDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "tcc_user_db_only_grant"]
    finally:
        store.close()


# ---- detector: misc ---- #


def test_detector_ignores_non_dangerous_service(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.app",
            "service": "kTCCServiceMediaLibrary",
            "auth_value": 2, "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        assert findings == []
    finally:
        store.close()


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        assert list(MacosTccDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_handles_invalid_auth_value(tmp_path):
    """Non-int auth_value shouldn't crash; just skip."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_entries(store, [{
            "client": "com.evilcorp.app",
            "service": "kTCCServiceAccessibility",
            "auth_value": "garbage", "client_type": 0,
        }])
        findings = list(MacosTccDetector().detect(store))
        assert findings == []
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "macos_tcc" in names


def test_detector_sigma_template_has_persistence_tag():
    det = MacosTccDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-macos-tcc-template"
    assert "attack.t1543.001" in tpl["tags"]
    assert tpl["logsource"]["product"] == "macos"


def test_known_good_bundles_includes_common():
    assert "us.zoom.xos" in KNOWN_GOOD_BUNDLE_IDS
    assert "com.tinyspeck.slackmacgap" in KNOWN_GOOD_BUNDLE_IDS
