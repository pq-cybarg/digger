"""AttackerToolingDetector — running & installed attacker tools with
self-attribution for dev contexts."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.attacker_tooling import AttackerToolingDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, exe=None, cmdline=None):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}",
        data={"pid": pid, "ppid": 1, "name": name,
              "exe": exe or f"/usr/bin/{name}",
              "cmdline": cm, "username": "user",
              "connections": [], "open_files": []},
    ))


def _inv(store, subj, raw):
    store.add_artifact(Artifact(
        collector="installed_software", category="inventory",
        subject=subj,
        data={"raw": raw},
    ))


# ---- T1 running tools ---- #


def test_running_msfconsole_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "msfconsole", exe="/usr/local/bin/msfconsole")
    findings = list(AttackerToolingDetector().detect(store))
    msf = [f for f in findings if "metasploit" in f.title]
    assert msf, [f.title for f in findings]
    assert msf[0].severity == "critical"
    assert msf[0].evidence["dev_context"] is False
    store.close()


def test_running_sliver_client_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "sliver-client", exe="/opt/sliver/sliver-client")
    findings = list(AttackerToolingDetector().detect(store))
    s = [f for f in findings if "sliver-client" in f.title]
    assert s
    assert s[0].severity == "critical"
    store.close()


def test_responder_is_mitm(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "responder", exe="/usr/local/bin/responder")
    findings = list(AttackerToolingDetector().detect(store))
    r = [f for f in findings if "responder" in f.title and "high" in f.severity]
    assert r
    store.close()


def test_impacket_script_via_python_cmdline(tmp_path):
    """python <secretsdump.py> should match via cmdline-token scan."""
    store = _store(tmp_path)
    _proc(store, 100, "python3", exe="/usr/bin/python3",
          cmdline=["python3", "/opt/impacket/secretsdump.py",
                   "domain/user:p@10.0.0.1"])
    findings = list(AttackerToolingDetector().detect(store))
    sd = [f for f in findings if "secretsdump" in f.title.lower()]
    assert sd
    store.close()


def test_hashcat_is_low_severity(tmp_path):
    """Crackers are presence-only signals (low sev)."""
    store = _store(tmp_path)
    _proc(store, 100, "hashcat", exe="/opt/homebrew/bin/hashcat")
    findings = list(AttackerToolingDetector().detect(store))
    hc = [f for f in findings if "hashcat" in f.title]
    assert hc
    assert hc[0].severity == "low"
    store.close()


# ---- Self-attribution ---- #


def test_dev_clone_downgrades_severity(tmp_path):
    """When the tool runs from a dev-clone path, severity is downgraded
    but the finding is still emitted (audit-visible)."""
    store = _store(tmp_path)
    _proc(store, 100, "responder",
          exe="/Users/dev/Desktop/priv/digger/.venv/bin/responder")
    findings = list(AttackerToolingDetector().detect(store))
    r = [f for f in findings if "responder" in f.title]
    assert r, [f.title for f in findings]
    assert r[0].evidence["dev_context"] is True
    assert r[0].severity == "medium"   # downgraded from "high"
    assert "dev-context" in r[0].title
    store.close()


def test_node_modules_dev_path_downgraded(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "msfconsole",
          exe="/Users/dev/repos/digger/node_modules/.bin/msfconsole")
    findings = list(AttackerToolingDetector().detect(store))
    m = [f for f in findings if "metasploit" in f.title]
    assert m
    assert m[0].evidence["dev_context"] is True
    assert m[0].severity == "medium"   # downgraded from "critical"
    store.close()


# ---- T2 installed tools via inventory ---- #


def test_brew_inventory_lists_responder(tmp_path):
    store = _store(tmp_path)
    _inv(store, "brew",
         "==> Listing installed formulae:\nresponder 3.1.4.0\nwget 1.21.4\n")
    findings = list(AttackerToolingDetector().detect(store))
    inst = [f for f in findings if f.evidence.get("kind") == "installed_attacker_tool"]
    assert inst
    assert "responder" in inst[0].title.lower()
    store.close()


def test_dpkg_inventory_lists_nmap(tmp_path):
    store = _store(tmp_path)
    _inv(store, "dpkg",
         "ii  nmap  7.94+dfsg-1  amd64  The Network Mapper\nii  curl 8.4.0 ...\n")
    findings = list(AttackerToolingDetector().detect(store))
    inst = [f for f in findings if f.evidence.get("tool") == "nmap"]
    assert inst
    assert inst[0].severity == "medium"  # recon category
    store.close()


def test_inventory_dedup_between_calls(tmp_path):
    """A second mention of the same tool in another inventory blob should
    not fire a second finding."""
    store = _store(tmp_path)
    _inv(store, "brew", "responder 3.1\n")
    _inv(store, "dpkg", "ii  responder 3.1  amd64  ...\n")
    findings = list(AttackerToolingDetector().detect(store))
    inst = [f for f in findings if f.evidence.get("tool") == "responder"
            and f.evidence.get("kind") == "installed_attacker_tool"]
    assert len(inst) == 1, [f.title for f in inst]
    store.close()


# ---- Sigma ---- #


def test_sigma_emitted_for_running_tool(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "responder", exe="/usr/local/bin/responder")
    f = next(AttackerToolingDetector().detect(store))
    fdict = {"detector": f.detector, "title": f.title, "summary": f.summary,
             "severity": f.severity, "evidence": f.evidence,
             "finding_uuid": "at-1"}
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert "attack.t1588.002" in rule["tags"]
    store.close()
