"""SigmaHQ live-feed pipeline + SigmaLoader integration."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from digger.exchange.sigma import SigmaLoader, _default_rule_dirs
from digger.intel import feeds as feeds_mod
from digger.intel.sources import sigma_corpus


def _point_intel_dir(monkeypatch, root):
    """Make digger.intel.feeds.intel_dir() return ``root``."""
    monkeypatch.setattr(feeds_mod, "intel_dir", lambda: root)


# ---- registry ---- #


def test_sigmahq_feed_registered():
    f = [x for x in feeds_mod.FEEDS if x.name == "sigmahq_corpus"]
    assert len(f) == 1
    assert f[0].fetch_fn is not None
    # Polite cadence
    assert f[0].interval >= 3600


# ---- parser ---- #


def test_parse_feed_payload_roundtrip():
    payload = {
        "source": "sigmahq/sigma",
        "fetched_at": 12345.0,
        "rule_count": 7,
        "total_seen": 100,
        "categories": ["rules/windows/process_creation"],
    }
    raw = json.dumps(payload).encode("utf-8")
    parsed = sigma_corpus.parse_feed_payload(raw)
    assert parsed == payload


# ---- keep-rule predicate ---- #


def test_keep_rule_accepts_c2_path():
    assert sigma_corpus._keep_rule(
        "rules/windows/command_and_control/some_rule.yml")


def test_keep_rule_accepts_credential_access():
    assert sigma_corpus._keep_rule(
        "rules/linux/credential_access/foo.yml")


def test_keep_rule_rejects_unrelated_category():
    assert not sigma_corpus._keep_rule(
        "rules/windows/discovery/random.yml")


def test_keep_rule_rejects_non_yaml():
    assert not sigma_corpus._keep_rule(
        "rules/windows/command_and_control/README.md")


# ---- fetch_fn end-to-end with mocked HTTP ---- #


def _fake_tarball(rules: dict[str, bytes]) -> bytes:
    """Build a tar.gz containing the given (relative-path, body) rules
    under a ``sigma-master/`` top dir, the way GitHub's codeload ships them."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel, body in rules.items():
            info = tarfile.TarInfo(name=f"sigma-master/{rel}")
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def test_fetch_extracts_only_kept_categories(tmp_path, monkeypatch):
    _point_intel_dir(monkeypatch, tmp_path)
    monkeypatch.setenv("DIGGER_INTEL_DIR", str(tmp_path))

    rules = {
        "rules/windows/command_and_control/win_c2_test.yml":
            b"title: c2 rule\ndetection:\n  selection:\n    Image: x\n  condition: selection\n",
        "rules/linux/credential_access/lin_cred_test.yml":
            b"title: cred rule\ndetection:\n  selection:\n    Image: y\n  condition: selection\n",
        "rules/windows/discovery/dis_test.yml":
            b"title: discovery (should be skipped)\n",
        "README.md": b"this is the readme",
    }
    fake_tar = _fake_tarball(rules)

    class _FakeResponse:
        def __init__(self, content):
            self.content = content
            self.status_code = 200
        def raise_for_status(self): pass

    import digger.intel.sources.sigma_corpus as sc
    monkeypatch.setattr(sc.requests, "get",
                        lambda *a, **k: _FakeResponse(fake_tar))

    raw = sc.fetch_as_feed_bytes()
    parsed = sc.parse_feed_payload(raw)
    assert parsed["rule_count"] == 2
    assert parsed["total_seen"] == 4

    cache = sc.cache_dir()
    files = sorted(p.name for p in cache.rglob("*.yml"))
    assert "win_c2_test.yml" in files
    assert "lin_cred_test.yml" in files
    assert "dis_test.yml" not in files


def test_sigma_loader_picks_up_live_cache(tmp_path, monkeypatch):
    """When live SigmaHQ rules exist, SigmaLoader includes them."""
    _point_intel_dir(monkeypatch, tmp_path)
    monkeypatch.setenv("DIGGER_INTEL_DIR", str(tmp_path))

    # Plant a single valid Sigma rule in the cache
    cache = sigma_corpus.cache_dir()
    (cache / "rules" / "windows" / "command_and_control").mkdir(
        parents=True, exist_ok=True)
    rule_text = (
        "title: live-cached test rule\n"
        "id: 00000000-0000-0000-0000-000000000001\n"
        "logsource: {category: process_creation}\n"
        "detection:\n  selection:\n    Image|endswith: '/badthing.exe'\n"
        "  condition: selection\n"
        "level: critical\n"
        "tags: [attack.command_and_control]\n"
    )
    (cache / "rules" / "windows" / "command_and_control" / "fake.yml"
     ).write_text(rule_text)

    dirs = _default_rule_dirs()
    assert any(str(d).endswith("sigma-corpus") for d in dirs), dirs

    loaded = SigmaLoader(dirs).load()
    matched = [r for r in loaded if "live-cached test rule" in r.title]
    assert matched, [r.title for r in loaded]
