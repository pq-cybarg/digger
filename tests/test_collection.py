"""CollectionDetector — 13th detector, closes the Collection-tactic gap."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.collection import CollectionDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, cmdline, exe=None, username="user"):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}",
        data={"pid": pid, "ppid": 1, "name": name,
              "exe": exe or f"/usr/bin/{name}",
              "cmdline": cm, "username": username,
              "connections": [], "open_files": []},
    ))


# ---- C1 keyloggers ---- #


@pytest.mark.parametrize("cmd,mitre,sev", [
    (["xinput", "test", "12"], "T1056.001", "critical"),
    (["logkeys", "--start", "-o", "/tmp/k.log"], "T1056.001", "critical"),
    # raw evdev read is high — can be legitimate driver/test code
    (["bash", "-c", "cat /dev/input/event4 > /tmp/keys"], "T1056.001", "high"),
    (["python", "-c",
      "import x; SetWindowsHookEx(WH_KEYBOARD_LL, cb, h, 0)"],
     "T1056.001", "critical"),
])
def test_keylogger_primitives_flagged(tmp_path, cmd, mitre, sev):
    store = _store(tmp_path)
    _proc(store, 100, cmd[0], cmd)
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits, [f.title for f in findings]
    assert hits[0].mitre == mitre
    assert hits[0].severity == sev
    store.close()


# ---- C2 screen capture ---- #


@pytest.mark.parametrize("cmd,mitre,sev", [
    (["scrot", "/tmp/screen.png"], "T1113", "medium"),
    (["screencapture", "-x", "/tmp/s.png"], "T1113", "high"),
    (["gnome-screenshot", "--file=/tmp/s.png"], "T1113", "medium"),
    (["ffmpeg", "-f", "x11grab", "-i", ":0", "/tmp/x.mp4"], "T1113", "high"),
    (["ffmpeg", "-f", "avfoundation", "-i", "1", "/tmp/x.mp4"], "T1113", "high"),
])
def test_screen_capture_flagged(tmp_path, cmd, mitre, sev):
    store = _store(tmp_path)
    _proc(store, 200, cmd[0], cmd)
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits, [f.title for f in findings]
    assert hits[0].mitre == mitre
    assert hits[0].severity == sev
    store.close()


# ---- C3 clipboard polling ---- #


def test_xclip_polling_loop_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 300, "bash",
          ["bash", "-c", "while true; do xclip -o; sleep 1; done"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"
            and "clipboard" in (f.evidence.get("pattern") or "")]
    assert hits
    assert hits[0].mitre == "T1115"
    assert hits[0].severity == "high"
    store.close()


def test_pbpaste_polling_powershell_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 301, "powershell.exe",
          ["powershell.exe", "-c",
           "while($true){ Get-Clipboard; Start-Sleep -s 1 }"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"
            and "clipboard" in (f.evidence.get("pattern") or "")]
    assert hits
    store.close()


def test_oneshot_pbpaste_not_flagged(tmp_path):
    """A user reading the clipboard once is not data collection."""
    store = _store(tmp_path)
    _proc(store, 302, "pbpaste", ["pbpaste"])
    findings = list(CollectionDetector().detect(store))
    assert not [f for f in findings if "clipboard" in (f.evidence.get("pattern") or "")]
    store.close()


# ---- C4 audio capture ---- #


def test_arecord_to_wav_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 400, "arecord", ["arecord", "-D", "default", "/tmp/c.wav"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].mitre == "T1123"
    store.close()


def test_ffmpeg_alsa_to_mp3_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 401, "ffmpeg",
          ["ffmpeg", "-f", "alsa", "-i", "default", "/tmp/a.mp3"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].mitre == "T1123"
    store.close()


# ---- C5 video / camera capture ---- #


def test_ffmpeg_v4l2_webcam_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 500, "ffmpeg",
          ["ffmpeg", "-f", "v4l2", "-i", "/dev/video0", "/tmp/cam.mp4"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1125"
    store.close()


def test_imagesnap_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 501, "imagesnap", ["imagesnap", "-w", "1", "/tmp/c.jpg"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].mitre == "T1125"
    store.close()


def test_avcapturesession_python_swift_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 502, "python",
          ["python", "-c", "AVCaptureSession().addInput(camera)"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    store.close()


# ---- C6 email theft ---- #


def test_pst_extractor_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 600, "pffexport",
          ["pffexport", "/home/user/Outlook.pst", "/tmp/out/"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1114.001"
    store.close()


def test_readpst_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 601, "readpst",
          ["readpst", "/home/user/Outlook.pst"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].mitre == "T1114.001"
    store.close()


def test_cat_pst_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 602, "bash",
          ["bash", "-c", "cat /home/u/Mail.pst > /tmp/m.pst"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].severity == "high"
    store.close()


# ---- C7 AitM tooling ---- #


@pytest.mark.parametrize("cmd,mitre", [
    (["mitmproxy", "-T", "--mode", "transparent"], "T1557"),
    (["bettercap", "-iface", "eth0"], "T1557"),
    (["ettercap", "-T", "-q", "-M", "arp:remote", "/1.1.1.1//"], "T1557.002"),
    (["python", "Responder.py", "-I", "eth0"], "T1557.001"),
    (["evilginx2", "-p", "/etc/phishlets/"], "T1557"),
    (["sslsplit", "-l", "/tmp/log", "-c", "ca.pem", "ssl"], "T1557.002"),
])
def test_aitm_tools_critical(tmp_path, cmd, mitre):
    store = _store(tmp_path)
    _proc(store, 700, cmd[0], cmd)
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits, [f.title for f in findings]
    assert hits[0].mitre == mitre
    assert hits[0].severity == "critical"
    store.close()


# ---- C8 info-repo / cloud-storage scraping ---- #


def test_kubectl_get_all_secrets_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 800, "kubectl",
          ["kubectl", "get", "secrets", "--all-namespaces", "-o", "yaml"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].mitre == "T1552.007"
    store.close()


def test_aws_secretsmanager_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 801, "aws",
          ["aws", "secretsmanager", "get-secret-value",
           "--secret-id", "production/db"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].mitre == "T1530"
    store.close()


def test_vault_kv_get_medium(tmp_path):
    store = _store(tmp_path)
    _proc(store, 802, "vault", ["vault", "kv", "get", "secret/db"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].mitre == "T1213"
    store.close()


def test_gh_secret_list_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 803, "gh", ["gh", "secret", "list"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].mitre == "T1213.003"
    store.close()


def test_ssm_get_parameters_with_decryption_high(tmp_path):
    store = _store(tmp_path)
    _proc(store, 804, "aws",
          ["aws", "ssm", "get-parameters", "--names", "/prod/db",
           "--with-decryption"])
    findings = list(CollectionDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "collection_cmdline"]
    assert hits
    assert hits[0].mitre == "T1530"
    store.close()


# ---- Clean negatives ---- #


def test_user_running_ffmpeg_to_transcode_video_not_flagged(tmp_path):
    """ffmpeg invocation with input file, not capture device, is benign."""
    store = _store(tmp_path)
    _proc(store, 900, "ffmpeg",
          ["ffmpeg", "-i", "/home/u/in.mp4", "/home/u/out.mp4"])
    findings = list(CollectionDetector().detect(store))
    assert not findings
    store.close()


def test_single_kubectl_get_pods_not_flagged(tmp_path):
    """Routine kubectl introspection is not Collection."""
    store = _store(tmp_path)
    _proc(store, 901, "kubectl", ["kubectl", "get", "pods", "-n", "default"])
    findings = list(CollectionDetector().detect(store))
    assert not findings
    store.close()


# ---- Sigma ---- #


def test_sigma_for_keylog_finding(tmp_path):
    store = _store(tmp_path)
    _proc(store, 1, "xinput", ["xinput", "test", "12"])
    f = next(iter(CollectionDetector().detect(store)))
    rule = finding_to_sigma({
        "detector": f.detector, "title": f.title, "summary": f.summary,
        "severity": f.severity, "evidence": f.evidence,
        "finding_uuid": "col-1", "mitre": f.mitre,
    }, case_id="t")
    assert rule is not None
    assert rule["logsource"]["category"] == "process_creation"
    assert "attack.collection" in rule["tags"]


def test_sigma_template_present():
    tpl = CollectionDetector().to_sigma_template()
    assert tpl is not None
    assert "attack.collection" in tpl["tags"]
    for tag in ("attack.t1056.001", "attack.t1113", "attack.t1115",
                "attack.t1123", "attack.t1125", "attack.t1114",
                "attack.t1557", "attack.t1530"):
        assert tag in tpl["tags"]
    sels = [k for k in tpl["detection"] if k.startswith("selection_")]
    assert len(sels) >= 7


# ---- Registry hookup ---- #


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "collection" in [d.name for d in all_detectors()]


def test_heatmap_collection_tactic_now_covered():
    """The closing milestone — Collection went from 0 to N techniques."""
    from digger.genrule.heatmap import build_coverage
    cov = build_coverage()
    col = cov["tactics"]["collection"]
    assert col["technique_ids"], "Collection tactic should now have ≥1 covering technique"
    covering = set()
    for tid in col["technique_ids"]:
        covering.update(cov["techniques"][tid]["detectors"])
    assert "collection" in covering
    # The heatmap should now reach 14/14 tactic coverage
    assert cov["summary"]["tactics_covered"] == 14
