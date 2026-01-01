"""Loki / signature-base integration."""

from __future__ import annotations

from pathlib import Path

from digger.core import Artifact, EvidenceStore
from digger.loki import LokiStyleDetector
from digger.loki.signature_base import SignatureBase, load_signature_base


def _make_sig_base(tmp_path: Path) -> Path:
    root = tmp_path / "signature-base"
    iocs = root / "iocs"
    iocs.mkdir(parents=True)
    (iocs / "hash-iocs.txt").write_text(
        "# digger test hashes\n"
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;Test SHA-256 sample;90\n",
        encoding="utf-8",
    )
    (iocs / "filename-iocs.txt").write_text(
        "# digger test filename iocs\n"
        ".*[/\\\\]tmp[/\\\\][a-z]{4}\\.exe$;Tmp short-name executable;60;digger\n",
        encoding="utf-8",
    )
    (iocs / "c2-iocs.txt").write_text(
        "# digger test c2\n"
        "evil.example.com;Test C2 domain;80\n"
        "1.2.3.4;Test C2 IP;80\n",
        encoding="utf-8",
    )
    (iocs / "falsepositive-iocs.txt").write_text("", encoding="utf-8")
    return root


def test_signature_base_parses_canonical_format(tmp_path: Path):
    root = _make_sig_base(tmp_path)
    sb = load_signature_base(root)
    counts = sb.summary()
    assert counts["hash_iocs"] == 1
    assert counts["filename_iocs"] == 1
    assert counts["c2_iocs"] == 2
    assert sb.hash_iocs[0].kind == "sha256"
    assert sb.c2_iocs[0].kind == "domain"
    assert sb.c2_iocs[1].kind == "ipv4"


def test_loki_detector_hash_match(tmp_path: Path):
    root = _make_sig_base(tmp_path)
    sb = load_signature_base(root)
    store = EvidenceStore(tmp_path / "case")
    store.add_artifact(Artifact(
        collector="processes", category="process", subject="pid=123",
        data={"pid": 123, "name": "demo",
              "exe": "/tmp/demo",
              "exe_sha256": "deadbeef" * 8},
    ))
    n = LokiStyleDetector(sb=sb).run(store)
    assert n >= 1
    findings = list(store.iter_findings())
    assert any("LOKI SHA256" in f["title"] for f in findings)
    store.close()


def test_loki_detector_filename_match(tmp_path: Path):
    root = _make_sig_base(tmp_path)
    sb = load_signature_base(root)
    store = EvidenceStore(tmp_path / "case")
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem", subject="recent:/tmp",
        data={"entries": [{"path": "/tmp/abcd.exe", "size": 1, "executable": True}]},
    ))
    LokiStyleDetector(sb=sb).run(store)
    findings = list(store.iter_findings())
    assert any("filename IOC" in f["title"] for f in findings), findings
    store.close()


def test_loki_detector_c2_ip_match(tmp_path: Path):
    root = _make_sig_base(tmp_path)
    sb = load_signature_base(root)
    store = EvidenceStore(tmp_path / "case")
    store.add_artifact(Artifact(
        collector="network", category="network", subject="raddr=1.2.3.4:80",
        data={"raddr": ["1.2.3.4", 80], "laddr": ["10.0.0.1", 49152], "status": "ESTABLISHED"},
    ))
    LokiStyleDetector(sb=sb).run(store)
    findings = list(store.iter_findings())
    assert any("C2 IOC" in f["title"] and "1.2.3.4" in f["title"] for f in findings)
    store.close()


def test_loki_detector_double_extension_anomaly(tmp_path: Path):
    sb = SignatureBase(root=tmp_path)   # no IOCs, should still flag anomalies
    store = EvidenceStore(tmp_path / "case")
    store.add_artifact(Artifact(
        collector="recent_files", category="filesystem", subject="recent:/Users",
        data={"entries": [{"path": "/Users/x/Downloads/invoice.pdf.exe",
                            "size": 1024, "executable": True}]},
    ))
    # When sb is empty (.is_loaded == False), detector logs and returns.
    # Re-prime sb so is_loaded returns True (yara_rule_paths can be anything)
    sb.yara_rule_paths = [tmp_path / "dummy.yar"]
    LokiStyleDetector(sb=sb).run(store)
    findings = list(store.iter_findings())
    assert any("Double-extension" in f["title"] for f in findings)
    store.close()


def test_loki_detector_no_signature_base_is_quiet(tmp_path: Path):
    sb = SignatureBase(root=tmp_path / "missing")
    store = EvidenceStore(tmp_path / "case")
    store.add_artifact(Artifact(
        collector="processes", category="process", subject="pid=1",
        data={"pid": 1, "name": "init"},
    ))
    n = LokiStyleDetector(sb=sb).run(store)
    assert n == 0
    store.close()
