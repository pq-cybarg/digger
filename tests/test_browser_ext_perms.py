"""Browser extension permission-combination detector tests."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.browser_ext_perms import (
    BrowserExtensionPermsDetector,
    _ext_perms,
    _has_all_urls,
)


def _make_ext_artifact(profile: str, *exts: dict) -> Artifact:
    return Artifact(
        collector="browser.chrome",
        category="browser",
        subject=f"chrome:extensions:{profile}",
        data={"profile": profile, "entries": list(exts)},
    )


def _seed(store: EvidenceStore, *exts: dict) -> None:
    store.add_artifact(_make_ext_artifact("default", *exts))


def _ext(eid: str, name: str = "", *,
          permissions=None, host_permissions=None) -> dict:
    return {
        "id": eid,
        "name": name or eid,
        "permissions": list(permissions or []),
        "host_permissions": list(host_permissions or []),
    }


# ---- helpers ---- #


def test_ext_perms_returns_set():
    assert _ext_perms({"permissions": ["a", "b"]}) == {"a", "b"}


def test_ext_perms_no_permissions_key():
    assert _ext_perms({}) == set()


def test_has_all_urls_in_host_perms():
    assert _has_all_urls({"host_permissions": ["<all_urls>"]}) is True


def test_has_all_urls_wildcard_pattern():
    assert _has_all_urls({"host_permissions": ["*://*/*"]}) is True


def test_has_all_urls_in_perms_field():
    # Older Chrome MV2 sometimes carried <all_urls> in permissions
    assert _has_all_urls({"permissions": ["<all_urls>"]}) is True


def test_has_all_urls_false():
    assert _has_all_urls(
        {"host_permissions": ["https://github.com/*"]}
    ) is False


# ---- B1 native messaging ---- #


def test_b1_native_messaging_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa", permissions=["nativeMessaging"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "native_messaging"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1071.001"
    finally:
        store.close()


def test_b1_no_finding_without_native_messaging(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa", permissions=["storage"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "native_messaging"]
    finally:
        store.close()


# ---- B2 webRequestBlocking + all_urls ---- #


def test_b2_webrequest_blocking_all_urls_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["webRequest",
                                         "webRequestBlocking"],
                            host_permissions=["<all_urls>"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "webrequest_blocking_all_urls"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["blocking"] is True
    finally:
        store.close()


def test_b2_webrequest_only_all_urls_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["webRequest"],
                            host_permissions=["<all_urls>"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "webrequest_blocking_all_urls"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].evidence["blocking"] is False
    finally:
        store.close()


def test_b2_no_finding_without_all_urls(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["webRequest"],
                            host_permissions=["https://github.com/*"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "webrequest_blocking_all_urls"]
    finally:
        store.close()


# ---- B3 all_urls + cookies + tabs ---- #


def test_b3_session_theft_combo_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["cookies", "tabs"],
                            host_permissions=["<all_urls>"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "all_urls_cookies_tabs"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1539"
    finally:
        store.close()


def test_b3_no_finding_missing_cookies(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["tabs"],
                            host_permissions=["<all_urls>"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "all_urls_cookies_tabs"]
    finally:
        store.close()


# ---- B4 proxy ---- #


def test_b4_proxy_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa", permissions=["proxy"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "proxy_permission"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1090"
    finally:
        store.close()


# ---- B5 debugger ---- #


def test_b5_debugger_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa", permissions=["debugger"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "debugger_permission"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1056.001"
    finally:
        store.close()


# ---- B6 spy stack ---- #


def test_b6_spy_stack_medium(tmp_path):
    """Only fires when no stronger finding (B2/B3) applies."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["tabs", "storage",
                                         "runtime", "scripting"],
                            host_permissions=["<all_urls>"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "spy_stack"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_b6_spy_stack_skipped_when_webrequest_covered(tmp_path):
    """If webRequest+all_urls already fires, spy_stack is redundant."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["tabs", "storage",
                                         "runtime", "scripting",
                                         "webRequest"],
                            host_permissions=["<all_urls>"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        kinds = {f.evidence.get("kind") for f in findings}
        assert "webrequest_blocking_all_urls" in kinds
        assert "spy_stack" not in kinds
    finally:
        store.close()


def test_b6_spy_stack_skipped_when_cookies_combo_covered(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["tabs", "storage",
                                         "runtime", "scripting",
                                         "cookies"],
                            host_permissions=["<all_urls>"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        kinds = {f.evidence.get("kind") for f in findings}
        assert "all_urls_cookies_tabs" in kinds
        assert "spy_stack" not in kinds
    finally:
        store.close()


def test_b6_no_finding_without_all_urls(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["tabs", "storage",
                                         "runtime", "scripting"],
                            host_permissions=["https://github.com/*"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "spy_stack"]
    finally:
        store.close()


# ---- B7 hardware bridge ---- #


def test_b7_usb_devices_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa", permissions=["usbDevices"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "hardware_bridge"]
        assert len(f) == 1
        assert f[0].severity == "medium"
    finally:
        store.close()


def test_b7_multiple_hardware_perms(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["usbDevices",
                                         "printerProvider",
                                         "platformKeys"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "hardware_bridge"]
        assert len(f) == 1
        assert len(f[0].evidence["permissions"]) == 3
    finally:
        store.close()


# ---- B8 declarativeNetRequest + many hosts ---- #


def test_b8_dnr_many_hosts_medium(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        many = [f"https://site{i}.example/*" for i in range(25)]
        _seed(store, _ext("aaa",
                            permissions=["declarativeNetRequest"],
                            host_permissions=many))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "decl_net_request_broad"]
        assert len(f) == 1
        assert f[0].severity == "medium"
        assert f[0].evidence["host_count"] == 25
    finally:
        store.close()


def test_b8_dnr_few_hosts_no_finding(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["declarativeNetRequest"],
                            host_permissions=["https://github.com/*"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "decl_net_request_broad"]
    finally:
        store.close()


# ---- detector: misc ---- #


def test_detector_empty_extension_list(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store)
        assert list(BrowserExtensionPermsDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_ignores_non_extensions_artifact(tmp_path):
    """An artifact whose subject doesn't include 'extensions' is
    skipped (could be cookies / history / etc)."""
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="browser.chrome",
            category="browser",
            subject="chrome:cookies:default",
            data={"entries": [_ext("aaa",
                                   permissions=["nativeMessaging"])]},
        ))
        assert list(BrowserExtensionPermsDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        assert list(BrowserExtensionPermsDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_multiple_findings_per_extension(tmp_path):
    """One extension can trip multiple layers (B1 + B4 + B5)."""
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed(store, _ext("aaa",
                            permissions=["nativeMessaging",
                                         "proxy", "debugger"]))
        findings = list(BrowserExtensionPermsDetector().detect(store))
        kinds = {f.evidence.get("kind") for f in findings}
        assert "native_messaging" in kinds
        assert "proxy_permission" in kinds
        assert "debugger_permission" in kinds
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "browser_ext_perms" in names


def test_detector_sigma_template_has_extension_tags():
    det = BrowserExtensionPermsDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-browser-ext-perms-template"
    assert "attack.t1176" in tpl["tags"]
    assert tpl["logsource"]["category"] == "browser"
