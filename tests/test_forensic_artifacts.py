"""ForensicArtifacts knowledge-base ingestion."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from digger.core.evidence import EvidenceStore
from digger.forensic_artifacts.loader import (
    Artifact,
    ArtifactSource,
    cache_dir,
    data_root,
    load_artifacts,
)
from digger.forensic_artifacts.resolver import ArtifactResolver
from digger.forensic_artifacts.runner import run_artifact


# ---- Artifact dataclass ---- #


def test_artifact_supports_os_agnostic():
    a = Artifact(name="x")  # no supported_os
    assert a.supports("linux")
    assert a.supports("darwin")
    assert a.supports("windows")


def test_artifact_supports_strict_match():
    a = Artifact(name="x", supported_os=["Linux"])
    assert a.supports("linux")
    assert not a.supports("windows")


def test_artifact_supports_macos_translation():
    a = Artifact(name="x", supported_os=["Darwin"])
    assert a.supports("darwin")
    assert a.supports("macos")    # alias translation
    assert a.supports("mac")
    assert a.supports("osx")


def test_artifact_matches_tags_empty_passes():
    a = Artifact(name="x", labels=["persistence"])
    assert a.matches_tags([])    # empty tag list = no filter


def test_artifact_matches_tags_label_hit():
    a = Artifact(name="x", labels=["Persistence", "Linux"])
    assert a.matches_tags(["persistence"])    # case-insensitive
    assert not a.matches_tags(["nonexistent"])


def test_artifact_matches_tags_name_hit():
    a = Artifact(name="BashShellHistoryFile")
    assert a.matches_tags(["bashshellhistoryfile"])


# ---- Loader ---- #


def test_load_artifacts_missing_dir_returns_empty(tmp_path):
    assert load_artifacts(root=tmp_path / "does-not-exist") == []


def test_load_artifacts_parses_yaml_fixture(tmp_path):
    yaml = pytest.importorskip("yaml")
    data = tmp_path / "artifacts" / "data"
    data.mkdir(parents=True)
    (data / "linux.yaml").write_text(yaml.safe_dump_all([
        {
            "name": "BashShellHistoryFile",
            "doc": "User's bash shell history.",
            "sources": [{
                "type": "FILE",
                "attributes": {
                    "paths": ["%%users.homedir%%/.bash_history"],
                },
            }],
            "supported_os": ["Darwin", "Linux"],
            "labels": ["Users", "History"],
        },
        {
            "name": "RootBash",
            "doc": "/root/.bash_history",
            "sources": [{
                "type": "FILE",
                "attributes": {"paths": ["/root/.bash_history"]},
            }],
            "supported_os": ["Linux"],
        },
    ]))
    arts = load_artifacts(root=tmp_path)
    assert len(arts) == 2
    by_name = {a.name: a for a in arts}
    assert "BashShellHistoryFile" in by_name
    assert by_name["BashShellHistoryFile"].supports("linux")
    assert by_name["BashShellHistoryFile"].sources[0].type == "FILE"
    assert "Users" in by_name["BashShellHistoryFile"].labels


def test_load_artifacts_skips_malformed_docs(tmp_path):
    yaml = pytest.importorskip("yaml")
    data = tmp_path / "artifacts" / "data"
    data.mkdir(parents=True)
    (data / "x.yaml").write_text(yaml.safe_dump_all([
        {"name": "Good", "sources": []},
        {"no_name": True},     # skipped (no name)
        "just a string",       # skipped (not a dict)
        None,                  # skipped
    ]))
    arts = load_artifacts(root=tmp_path)
    assert len(arts) == 1
    assert arts[0].name == "Good"


def test_data_root_resolution_prefers_artifacts_data(tmp_path):
    (tmp_path / "artifacts" / "data").mkdir(parents=True)
    assert data_root(tmp_path).name == "data"
    assert data_root(tmp_path).parent.name == "artifacts"


def test_data_root_falls_back_to_direct_data_dir(tmp_path):
    (tmp_path / "data").mkdir()
    assert data_root(tmp_path) == tmp_path / "data"


def test_cache_dir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("DIGGER_FA_DIR", str(tmp_path / "custom"))
    assert cache_dir() == tmp_path / "custom"


# ---- Resolver ---- #


def test_resolver_no_placeholder_returns_template_verbatim():
    r = ArtifactResolver()
    assert r.expand("/etc/passwd") == ["/etc/passwd"]


def test_resolver_users_homedir_expands_to_real_home():
    """Smoke: at least the current user's home should be in there."""
    r = ArtifactResolver()
    expanded = r.expand("%%users.homedir%%/.bash_history")
    home = os.path.expanduser("~")
    assert any(p == f"{home}/.bash_history" for p in expanded)


def test_resolver_unknown_placeholder_returns_empty():
    r = ArtifactResolver()
    # users.something-that-doesnt-exist should yield nothing
    assert r.expand("%%nonsense_placeholder%%/x") == []


def test_resolver_multiple_placeholders_cartesian():
    """Two placeholders → product expansion."""
    r = ArtifactResolver()
    # Stub mapping with two small lists for deterministic behavior
    r._mapping["users.homedir"] = ["/h/alice", "/h/bob"]
    r._mapping["users.username"] = ["alice", "bob"]
    out = r.expand("%%users.homedir%% — %%users.username%%")
    # 2 × 2 = 4 combinations
    assert len(out) == 4
    assert "/h/alice — alice" in out
    assert "/h/bob — bob" in out


def test_resolver_repeated_placeholder_uses_same_value():
    r = ArtifactResolver()
    r._mapping["users.homedir"] = ["/h/alice", "/h/bob"]
    out = r.expand("%%users.homedir%%/x/%%users.homedir%%/y")
    # Two homedirs × (each placeholder uses same value within a combo)
    assert "/h/alice/x/%%users.homedir%%/y" not in out  # no leftover placeholder
    # Should produce 2 outputs (cartesian on same placeholder still
    # produces 2 outputs because product([h])([h]) yields 2)
    assert all("%%" not in o for o in out)


def test_resolver_expand_many_dedups():
    r = ArtifactResolver()
    r._mapping["users.homedir"] = ["/h/alice"]
    out = r.expand_many([
        "/etc/passwd",
        "/etc/passwd",   # duplicate
        "%%users.homedir%%/.bashrc",
    ])
    assert out.count("/etc/passwd") == 1
    assert "/h/alice/.bashrc" in out


# ---- Runner ---- #


def test_runner_file_source_emits_artifact(tmp_path):
    """FILE source should emit one digger Artifact per resolved path
    that exists."""
    store = EvidenceStore(tmp_path)
    sample = tmp_path / "sample.txt"
    sample.write_text("hello world")

    resolver = ArtifactResolver()
    # Direct path, no placeholder
    art = Artifact(
        name="SamplePathFile",
        sources=[ArtifactSource(
            type="FILE",
            attributes={"paths": [str(sample)]},
        )],
    )
    n = run_artifact(art, store, resolver=resolver)
    assert n == 1
    # The emitted artifact should show up in the store
    rows = list(store.iter_artifacts(collector="forensic_artifacts"))
    assert len(rows) == 1
    data = rows[0]["data"]
    assert data["path"] == str(sample)
    assert data["kind"] == "file"
    assert data["size"] == len("hello world")
    assert data["fa_artifact"] == "SamplePathFile"
    assert "hello world" in data.get("content_snippet", "")
    store.close()


def test_runner_file_source_skips_missing_paths(tmp_path):
    store = EvidenceStore(tmp_path)
    resolver = ArtifactResolver()
    art = Artifact(
        name="MissingFile",
        sources=[ArtifactSource(
            type="FILE",
            attributes={"paths": ["/definitely/does/not/exist/xyz"]},
        )],
    )
    n = run_artifact(art, store, resolver=resolver)
    assert n == 0
    store.close()


def test_runner_directory_source_lists_entries(tmp_path):
    store = EvidenceStore(tmp_path)
    d = tmp_path / "stuff"
    d.mkdir()
    (d / "a.txt").write_text("a")
    (d / "b.txt").write_text("b")
    resolver = ArtifactResolver()
    art = Artifact(
        name="DirX",
        sources=[ArtifactSource(
            type="DIRECTORY",
            attributes={"paths": [str(d)]},
        )],
    )
    n = run_artifact(art, store, resolver=resolver)
    assert n == 1
    rows = list(store.iter_artifacts(collector="forensic_artifacts"))
    data = rows[0]["data"]
    assert data["kind"] == "directory"
    assert data["entry_count"] == 2
    names = {e["name"] for e in data["entries"]}
    assert names == {"a.txt", "b.txt"}
    store.close()


def test_runner_command_source_skipped_without_opt_in(monkeypatch, tmp_path):
    monkeypatch.delenv("DIGGER_FA_RUN_COMMANDS", raising=False)
    store = EvidenceStore(tmp_path)
    art = Artifact(
        name="EchoTest",
        sources=[ArtifactSource(
            type="COMMAND",
            attributes={"cmd": "echo", "args": ["hi"]},
        )],
    )
    n = run_artifact(art, store, resolver=ArtifactResolver())
    assert n == 1
    rows = list(store.iter_artifacts(collector="forensic_artifacts"))
    data = rows[0]["data"]
    assert "DIGGER_FA_RUN_COMMANDS=1" in data.get("skipped_reason", "")
    # No stdout — execution skipped
    assert "stdout" not in data
    store.close()


def test_runner_command_source_runs_with_opt_in(monkeypatch, tmp_path):
    monkeypatch.setenv("DIGGER_FA_RUN_COMMANDS", "1")
    store = EvidenceStore(tmp_path)
    art = Artifact(
        name="EchoTest",
        sources=[ArtifactSource(
            type="COMMAND",
            attributes={"cmd": "echo", "args": ["digger-fa-test"]},
        )],
    )
    n = run_artifact(art, store, resolver=ArtifactResolver())
    assert n == 1
    rows = list(store.iter_artifacts(collector="forensic_artifacts"))
    data = rows[0]["data"]
    assert data["returncode"] == 0
    assert "digger-fa-test" in data["stdout"]
    store.close()


def test_runner_unsupported_source_records_stub(tmp_path):
    """REGISTRY_KEY on macOS → unsupported stub, not an error."""
    store = EvidenceStore(tmp_path)
    art = Artifact(
        name="RegPlaceholder",
        sources=[ArtifactSource(
            type="REGISTRY_KEY",
            attributes={"keys": ["HKLM\\SOFTWARE\\Microsoft\\Windows"]},
        )],
    )
    n = run_artifact(art, store, resolver=ArtifactResolver())
    assert n == 1
    rows = list(store.iter_artifacts(collector="forensic_artifacts"))
    data = rows[0]["data"]
    assert data["fa_source_type"] == "REGISTRY_KEY"
    assert "not implemented" in data["note"]
    store.close()


def test_runner_artifact_group_recurses(tmp_path):
    """An ARTIFACT_GROUP source should run every named child artifact."""
    store = EvidenceStore(tmp_path)
    sample = tmp_path / "x.txt"
    sample.write_text("x")
    child = Artifact(
        name="Child",
        sources=[ArtifactSource(
            type="FILE",
            attributes={"paths": [str(sample)]},
        )],
    )
    parent = Artifact(
        name="Parent",
        sources=[ArtifactSource(
            type="ARTIFACT_GROUP",
            attributes={"names": ["Child"]},
        )],
    )
    n = run_artifact(
        parent, store,
        all_artifacts_by_name={"Child": child, "Parent": parent},
    )
    assert n == 1   # child's one FILE-source emission
    store.close()


def test_runner_skips_when_os_not_supported(tmp_path, monkeypatch):
    """When the artifact's supported_os doesn't include the current
    OS, run_artifact should return 0 without emitting."""
    from digger.core import platform as _platform
    monkeypatch.setattr(_platform, "current_os",
                        lambda: _platform.OS.WINDOWS)
    store = EvidenceStore(tmp_path)
    art = Artifact(
        name="LinuxOnly",
        sources=[ArtifactSource(
            type="FILE",
            attributes={"paths": ["/etc/passwd"]},
        )],
        supported_os=["Linux"],
    )
    n = run_artifact(art, store, resolver=ArtifactResolver())
    assert n == 0
    store.close()


# ---- CLI smoke ---- #


def test_cli_fa_list_without_corpus_errors():
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "fa", "list"],
        capture_output=True, text=True, timeout=15,
        env={**os.environ,
             "DIGGER_FA_DIR": "/nonexistent/path/zzz"},
    )
    assert r.returncode == 1
    assert "fa update" in r.stderr


def test_cli_fa_run_requires_name_or_tags():
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "fa", "run", "--case-dir", "/tmp/nope"],
        capture_output=True, text=True, timeout=15,
        env={**os.environ,
             "DIGGER_FA_DIR": "/nonexistent/path/zzz"},
    )
    assert r.returncode != 0


def test_cli_fa_list_with_fixture_corpus(tmp_path):
    """Build a tiny FA-shaped corpus on disk + point `fa list` at it."""
    yaml = pytest.importorskip("yaml")
    data = tmp_path / "artifacts" / "data"
    data.mkdir(parents=True)
    (data / "linux.yaml").write_text(yaml.safe_dump_all([
        {"name": "BashHistoryFile",
         "sources": [{"type": "FILE",
                      "attributes": {"paths": ["/x"]}}],
         "supported_os": ["Linux"],
         "labels": ["Users", "History"]},
    ]))
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "fa", "list", "--os", "linux"],
        capture_output=True, text=True, timeout=15,
        env={**os.environ, "DIGGER_FA_DIR": str(tmp_path)},
    )
    assert r.returncode == 0, r.stderr
    assert "BashHistoryFile" in r.stdout
