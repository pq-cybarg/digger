"""ADAttackDetector — Kerberoast, AS-REP roast, BloodHound, DCSync,
AdminSDHolder, DCShadow."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.ad_attacks import ADAttackDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, exe=None, cmdline=None, username="user"):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}",
        data={"pid": pid, "ppid": 1, "name": name,
              "exe": exe or f"C:\\Windows\\System32\\{name}",
              "cmdline": cm, "username": username},
    ))


def _evt(store, raw):
    store.add_artifact(Artifact(
        collector="windows.event_logs", category="logs",
        subject="security", data={"raw": raw}))


# ---- A3 BloodHound family ---- #


def test_sharphound_process_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "SharpHound.exe",
          exe="C:\\Users\\victim\\Downloads\\SharpHound.exe",
          cmdline=["SharpHound.exe", "-c", "All"])
    findings = list(ADAttackDetector().detect(store))
    bh = [f for f in findings if f.evidence.get("kind") == "bloodhound_family"]
    assert bh, [f.title for f in findings]
    assert bh[0].severity == "high"
    assert bh[0].mitre == "T1087.002"
    store.close()


def test_azurehound_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "azurehound", exe="/usr/local/bin/azurehound",
          cmdline=["azurehound", "list", "users"])
    findings = list(ADAttackDetector().detect(store))
    assert [f for f in findings if "azurehound" in f.title.lower()]
    store.close()


# ---- A4 DCSync via cmdline ---- #


def test_mimikatz_dcsync_cmdline(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "powershell.exe",
          cmdline=["powershell.exe", "-c",
                   "Invoke-Mimikatz -Command 'lsadump::dcsync /user:krbtgt'"])
    findings = list(ADAttackDetector().detect(store))
    dcs = [f for f in findings if "dcsync" in f.title.lower()
           or "DCSync" in str(f.evidence.get("pattern", ""))]
    assert dcs
    assert any(f.severity == "critical" for f in dcs)
    store.close()


def test_secretsdump_just_dc_cmdline(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "python3",
          cmdline=["python3", "secretsdump.py", "-just-dc",
                   "domain/user:pass@10.0.0.1"])
    findings = list(ADAttackDetector().detect(store))
    sd = [f for f in findings if "-just-dc" in (f.evidence.get("pattern") or "")
          or "secretsdump" in f.title.lower()]
    assert sd
    store.close()


# ---- A1 Kerberoasting in event 4769 ---- #


def test_kerberoast_4769_rc4_flagged(tmp_path):
    store = _store(tmp_path)
    evt = (
        "EventID: 4769 A Kerberos service ticket was requested. "
        "TargetUserName: alice@DOMAIN.LOCAL "
        "ServiceName: MSSQLSvc/sql01.domain.local:1433 "
        "TicketEncryptionType: 0x17 "
        "FailureCode: 0x0"
    )
    _evt(store, evt)
    findings = list(ADAttackDetector().detect(store))
    kr = [f for f in findings if "Kerberoast" in f.title]
    assert kr, [f.title for f in findings]
    assert kr[0].severity == "critical"
    assert kr[0].mitre == "T1558.003"
    store.close()


def test_kerberoast_4769_krbtgt_not_flagged(tmp_path):
    store = _store(tmp_path)
    evt = (
        "EventID: 4769 ServiceName: krbtgt/DOMAIN "
        "TicketEncryptionType: 0x17"
    )
    _evt(store, evt)
    findings = list(ADAttackDetector().detect(store))
    assert [f for f in findings if "Kerberoast" in f.title] == []
    store.close()


# ---- A2 AS-REP roasting ---- #


def test_asrep_roast_flagged(tmp_path):
    store = _store(tmp_path)
    evt = (
        "EventID: 4768 A Kerberos authentication ticket (TGT) was requested. "
        "TargetUserName: legacyaccount PreAuthType: 0 "
        "ServiceName: krbtgt"
    )
    _evt(store, evt)
    findings = list(ADAttackDetector().detect(store))
    ar = [f for f in findings if "AS-REP" in f.title]
    assert ar
    assert ar[0].severity == "high"
    assert ar[0].mitre == "T1558.004"
    store.close()


def test_machine_account_4768_not_flagged(tmp_path):
    store = _store(tmp_path)
    evt = (
        "EventID: 4768 TargetUserName: WORKSTATION01$ PreAuthType: 0"
    )
    _evt(store, evt)
    findings = list(ADAttackDetector().detect(store))
    assert [f for f in findings if "AS-REP" in f.title] == []
    store.close()


# ---- A4 DCSync via event 4662 ---- #


def test_dcsync_4662_replication_guid_flagged(tmp_path):
    store = _store(tmp_path)
    evt = (
        "EventID: 4662 An operation was performed on an object. "
        "Properties: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 "
        "AccessMask: 0x100"
    )
    _evt(store, evt)
    findings = list(ADAttackDetector().detect(store))
    dcs = [f for f in findings if "DCSync" in f.title and "4662" in f.title]
    assert dcs
    assert dcs[0].severity == "critical"
    store.close()


# ---- A5 AdminSDHolder ---- #


def test_adminsdholder_5136_flagged(tmp_path):
    store = _store(tmp_path)
    evt = (
        "EventID: 5136 A directory service object was modified. "
        "ObjectDN: CN=AdminSDHolder,CN=System,DC=domain,DC=local "
        "AttributeLDAPDisplayName: nTSecurityDescriptor"
    )
    _evt(store, evt)
    findings = list(ADAttackDetector().detect(store))
    asd = [f for f in findings if "AdminSDHolder" in f.title]
    assert asd
    assert asd[0].severity == "critical"
    assert asd[0].mitre == "T1484.001"
    store.close()


# ---- Sigma generation ---- #


def test_kerberoast_sigma(tmp_path):
    store = _store(tmp_path)
    _evt(store, "EventID: 4769 ServiceName: HTTP/web01 TicketEncryptionType: 0x17")
    f = next(ADAttackDetector().detect(store))
    fdict = {"detector": f.detector, "title": f.title, "summary": f.summary,
             "severity": f.severity, "evidence": f.evidence,
             "finding_uuid": "ad-1"}
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert "attack.t1558.003" in rule["tags"]
    store.close()


def test_dcsync_sigma(tmp_path):
    store = _store(tmp_path)
    _evt(store, "EventID: 4662 Properties: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
    f = next(ADAttackDetector().detect(store))
    fdict = {"detector": f.detector, "title": f.title, "summary": f.summary,
             "severity": f.severity, "evidence": f.evidence,
             "finding_uuid": "ad-2"}
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert "attack.t1003.006" in rule["tags"]
    store.close()
