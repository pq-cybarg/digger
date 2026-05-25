"""ART atomic-test loader + coverage matrix + sandbox-gated runner.

See ``digger.art.__init__`` for the public-API summary. This module
intentionally has zero hard dependencies on the ART repo being
present; ``load_atomics()`` returns an empty list when the cache
directory doesn't exist, so the coverage report degrades gracefully
to "no ART data available — run `digger art update` to clone the
corpus" rather than crashing.
"""

# live-first-ok: The ART corpus is fetched live from the upstream
# repo via `digger art update` (analogous to `digger loki update`).
# There's no bundled fallback — without the cache, coverage is empty
# but the module still loads.

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---- ART corpus location ---- #


def cache_dir() -> Path:
    """``$DIGGER_ART_DIR`` or ``~/.cache/digger/atomic-red-team``."""
    env = os.environ.get("DIGGER_ART_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".cache" / "digger" / "atomic-red-team"


def atomics_root() -> Path:
    """Where the ``atomics/T####/T####.yaml`` tree lives."""
    return cache_dir() / "atomics"


# ---- Data model ---- #


@dataclass
class AtomicTest:
    """One atomic test, normalized across ART's heterogeneous YAML shape.

    ART's per-technique YAML carries N test definitions (``atomic_tests``
    list), each with name + description + supported_platforms +
    executor (shell command_line) + input_arguments. We flatten to
    one AtomicTest per (technique, test-index) pair so the coverage
    matrix and runner can address each independently."""
    technique_id: str          # T1059 / T1059.001
    index: int                 # 0-based index within atomic_tests list
    name: str
    description: str
    supported_platforms: list[str]  # ["linux", "macos", "windows"]
    executor_name: str         # "bash" / "command_prompt" / "powershell" / "sh" / "manual"
    command: str               # raw command_line, with ART {{input_arg}} placeholders
    input_arguments: dict[str, dict[str, Any]] = field(default_factory=dict)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    elevation_required: bool = False
    auto_generated_guid: str = ""  # ART's per-test stable UUID

    @property
    def display_id(self) -> str:
        return f"{self.technique_id}#{self.index}"

    @property
    def is_destructive(self) -> bool:
        """Heuristic: command writes/deletes outside the user's tmp dir,
        modifies the registry on Windows, modifies services / drivers,
        or clears logs. Used to gate the runner from any 'never run
        this on a real host' test."""
        cmd = (self.command or "").lower()
        destructive_markers = (
            "rm -rf /", "rm -rf ~", "rm -rf $home",
            "del /q ", "del /f ", "rmdir /s",
            "format ", "diskpart", "mkfs.",
            "shutdown ", "halt", "reboot",
            "vssadmin delete", "wbadmin delete", "bcdedit /set",
            "wevtutil cl ", "clear-eventlog",
            "shred -u", "sdelete ",
            "set-mppreference -disablerealtime",
            "stop-service windefend", "net stop windefend",
            "registry::hklm\\sam", "lsadump",
            "ntdsutil", "dcsync",
            "scrcpy", "screencapture -x",
        )
        return any(m in cmd for m in destructive_markers)


# ---- ART YAML loader ---- #


def load_atomics(root: Path | None = None) -> list[AtomicTest]:
    """Load every ART atomic test from the cache.

    Returns an empty list (without error) when the cache is missing —
    callers should treat empty as "ART corpus not installed; run
    ``digger art update``."."""
    root = root or atomics_root()
    if not root.is_dir():
        return []
    try:
        import yaml  # type: ignore
    except ImportError:
        return []
    out: list[AtomicTest] = []
    for tdir in sorted(root.glob("T*")):
        if not tdir.is_dir():
            continue
        # ART stores both T1059 and T1059.001 as separate top-level
        # directories. Their main YAML file mirrors the dir name.
        yaml_path = tdir / f"{tdir.name}.yaml"
        if not yaml_path.is_file():
            continue
        try:
            with yaml_path.open("r", encoding="utf-8") as f:
                doc = yaml.safe_load(f) or {}
        except Exception:
            continue
        technique_id = doc.get("attack_technique") or tdir.name
        tests = doc.get("atomic_tests") or []
        for idx, t in enumerate(tests):
            if not isinstance(t, dict):
                continue
            executor = t.get("executor") or {}
            out.append(AtomicTest(
                technique_id=technique_id,
                index=idx,
                name=str(t.get("name") or "")[:120],
                description=str(t.get("description") or "")[:600],
                supported_platforms=[
                    str(p).lower() for p in
                    (t.get("supported_platforms") or [])
                ],
                executor_name=str(executor.get("name") or "").lower(),
                command=str(executor.get("command") or ""),
                input_arguments=dict(t.get("input_arguments") or {}),
                dependencies=list(t.get("dependencies") or []),
                elevation_required=bool(executor.get("elevation_required")),
                auto_generated_guid=str(t.get("auto_generated_guid") or ""),
            ))
    return out


# ---- Coverage matrix ---- #


def _normalize_technique(tid: str) -> str:
    """``T1059.001`` and ``T1059`` are both valid keys. Strip the
    sub-technique suffix for matching against parent-level detectors."""
    return (tid or "").upper().strip()


def _parent_technique(tid: str) -> str:
    return _normalize_technique(tid).split(".", 1)[0]


def build_coverage_matrix(
    atomics: list[AtomicTest] | None = None,
    digger_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Cross-reference ART tests with digger detector coverage.

    Returns::

        {
          "summary": {
              "art_techniques_total": int,
              "art_techniques_covered": int,
              "art_techniques_uncovered": int,
              "art_tests_total": int,
              "art_tests_destructive": int,
              "digger_techniques_total": int,
              "digger_techniques_not_in_art": int,
          },
          "per_technique": {
              "T1059": {
                  "test_count": int,
                  "destructive_count": int,
                  "covered_by_detectors": [...],     # may be empty
                  "covered": bool,
                  "supported_platforms": [...union over all tests...],
              },
              ...
          },
          "art_only": [...],     # ART has tests, digger has no coverage
          "digger_only": [...],  # digger detects, ART has no test
        }
    """
    if atomics is None:
        atomics = load_atomics()
    if digger_coverage is None:
        from digger.genrule.heatmap import build_coverage
        digger_coverage = build_coverage()

    art_techniques: dict[str, dict[str, Any]] = {}
    for t in atomics:
        tid = _normalize_technique(t.technique_id)
        if not tid:
            continue
        entry = art_techniques.setdefault(tid, {
            "test_count": 0,
            "destructive_count": 0,
            "supported_platforms": set(),
        })
        entry["test_count"] += 1
        if t.is_destructive:
            entry["destructive_count"] += 1
        entry["supported_platforms"].update(t.supported_platforms)

    digger_techniques = digger_coverage.get("techniques") or {}

    per_technique: dict[str, dict[str, Any]] = {}
    for tid, entry in art_techniques.items():
        # Try exact match first; fall back to parent technique.
        det_entry = (
            digger_techniques.get(tid)
            or digger_techniques.get(_parent_technique(tid))
        )
        detectors = sorted((det_entry or {}).get("detectors") or [])
        per_technique[tid] = {
            "test_count": entry["test_count"],
            "destructive_count": entry["destructive_count"],
            "supported_platforms": sorted(entry["supported_platforms"]),
            "covered_by_detectors": detectors,
            "covered": bool(detectors),
        }

    art_set = set(art_techniques.keys())
    art_parent_set = {_parent_technique(t) for t in art_set}
    digger_set = set(digger_techniques.keys())

    art_only = sorted(
        tid for tid in art_set
        if not per_technique[tid]["covered"]
    )
    digger_only = sorted(
        tid for tid in digger_set
        if tid not in art_set and _parent_technique(tid) not in art_parent_set
    )

    return {
        "summary": {
            "art_techniques_total": len(art_set),
            "art_techniques_covered": sum(
                1 for t in per_technique.values() if t["covered"]
            ),
            "art_techniques_uncovered": len(art_only),
            "art_tests_total": sum(e["test_count"] for e in art_techniques.values()),
            "art_tests_destructive": sum(
                e["destructive_count"] for e in art_techniques.values()
            ),
            "digger_techniques_total": len(digger_set),
            "digger_techniques_not_in_art": len(digger_only),
        },
        "per_technique": per_technique,
        "art_only": art_only,
        "digger_only": digger_only,
    }


# ---- Renderers ---- #


def coverage_report_json(matrix: dict[str, Any]) -> str:
    return json.dumps(matrix, indent=2, sort_keys=True, default=list)


def coverage_report_text(matrix: dict[str, Any], *, width: int = 100) -> str:
    s = matrix["summary"]
    if s["art_techniques_total"] == 0:
        return (
            "ART coverage report — no atomic tests loaded.\n"
            f"Looked in: {atomics_root()}\n"
            "Run `digger art update` to fetch the upstream ART corpus.\n"
        )

    lines = [
        "Atomic Red Team coverage — ART techniques × digger detectors",
        "=" * min(width, 80),
        f"ART techniques tested:        {s['art_techniques_total']}",
        f"  covered by ≥1 digger det:  {s['art_techniques_covered']}",
        f"  UNCOVERED (gaps):          {s['art_techniques_uncovered']}",
        f"ART atomic tests total:       {s['art_tests_total']}",
        f"  destructive (sandbox-only): {s['art_tests_destructive']}",
        f"digger-detected, no ART test: {s['digger_techniques_not_in_art']}",
        "-" * min(width, 80),
    ]

    # Top 20 covered techniques sorted by test count
    by_count = sorted(
        matrix["per_technique"].items(),
        key=lambda kv: (-kv[1]["test_count"], kv[0]),
    )[:20]
    lines.append("Top techniques by ART test count:")
    for tid, info in by_count:
        det = ",".join(info["covered_by_detectors"]) or "(uncovered)"
        marker = " " if info["covered"] else "!"
        lines.append(
            f"  {marker} {tid:<10} {info['test_count']:>3} tests "
            f"({info['destructive_count']} destructive) → {det}"
        )

    if matrix["art_only"]:
        lines.append("")
        lines.append(
            f"ART-only (we should consider detectors for these "
            f"{len(matrix['art_only'])} techniques):"
        )
        # Show first 25
        for tid in matrix["art_only"][:25]:
            info = matrix["per_technique"][tid]
            lines.append(
                f"  {tid:<10} {info['test_count']:>3} tests "
                f"({','.join(info['supported_platforms']) or '?'})"
            )
        if len(matrix["art_only"]) > 25:
            lines.append(f"  …and {len(matrix['art_only']) - 25} more")

    return "\n".join(lines) + "\n"


# ---- Sandbox check ---- #


SANDBOX_MARKER = Path("/tmp/digger-art-sandbox.ok")
SANDBOX_ENV = "DIGGER_ART_SANDBOX_OK"


def sandbox_check() -> tuple[bool, str]:
    """Two-gate sandbox check for the runner.

    Returns ``(ok, reason)``. Runner refuses to execute unless BOTH:
      * env var ``DIGGER_ART_SANDBOX_OK=1`` is set
      * file ``/tmp/digger-art-sandbox.ok`` exists and is owned by
        the current user

    The two-gate design forces the operator to (a) explicitly opt in
    per-session via env var AND (b) physically touch a file on disk
    that any reasonable VM-or-disposable-host audit would catch. A
    bare ``--force`` flag would be too easy to type by accident."""
    if os.environ.get(SANDBOX_ENV) != "1":
        return False, (
            f"environment variable {SANDBOX_ENV}=1 is not set — "
            "the ART runner executes real attack primitives and must "
            "only run in a sandbox or throwaway VM. Set this env var "
            "AND touch the marker file to opt in."
        )
    if not SANDBOX_MARKER.is_file():
        return False, (
            f"marker file {SANDBOX_MARKER} does not exist. Touch it "
            "as an explicit 'this is a sandbox' acknowledgement "
            "(``touch /tmp/digger-art-sandbox.ok``). Refuse on a "
            "production host."
        )
    try:
        st = SANDBOX_MARKER.stat()
        if st.st_uid != os.getuid():
            return False, (
                f"marker file {SANDBOX_MARKER} is not owned by the "
                f"current user (uid {os.getuid()}). Refusing — only "
                "the operator who explicitly opted in may run tests."
            )
    except OSError as exc:
        return False, f"could not stat marker file: {exc}"
    return True, "sandbox confirmed via env var + marker file"


# ---- Test runner (stub — wired into CLI separately) ---- #


def run_test(
    test: AtomicTest, *,
    cwd: Path | None = None,
    timeout_s: int = 30,
) -> dict[str, Any]:
    """Run a single ART atomic test. Refuses unless sandbox_check() OK.

    Destructive tests additionally require the explicit env var
    ``DIGGER_ART_ALLOW_DESTRUCTIVE=1`` on top of the sandbox gate.

    Returns a dict with stdout/stderr/returncode/elapsed_s for the
    caller to correlate against detector findings. The runner itself
    never reads digger's EvidenceStore — that's the caller's job."""
    ok, reason = sandbox_check()
    if not ok:
        return {
            "executed": False,
            "refusal_reason": reason,
            "test": test.display_id,
        }
    if test.is_destructive and (
        os.environ.get("DIGGER_ART_ALLOW_DESTRUCTIVE") != "1"
    ):
        return {
            "executed": False,
            "refusal_reason": (
                f"test {test.display_id} contains destructive primitives "
                "(rm -rf / / format / vssadmin delete / etc.). Set "
                "DIGGER_ART_ALLOW_DESTRUCTIVE=1 to override on a VM "
                "you can roll back."
            ),
            "test": test.display_id,
        }

    import shlex
    import subprocess

    started = time.time()
    cmd = test.command
    # Heuristic: map ART executor name to a shell command vector.
    if test.executor_name in ("sh", "bash"):
        args = ["/bin/bash", "-c", cmd]
    elif test.executor_name in ("powershell", "pwsh"):
        args = ["pwsh", "-NoProfile", "-Command", cmd]
    elif test.executor_name == "command_prompt":
        args = ["cmd.exe", "/c", cmd]
    else:
        # Best-effort: split as-is
        args = shlex.split(cmd) if cmd else []

    try:
        r = subprocess.run(
            args, cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, timeout=timeout_s,
        )
        return {
            "executed": True,
            "test": test.display_id,
            "command": cmd,
            "returncode": r.returncode,
            "stdout": r.stdout[-4000:],
            "stderr": r.stderr[-4000:],
            "elapsed_s": time.time() - started,
            "started_ts": started,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "executed": True,
            "test": test.display_id,
            "command": cmd,
            "returncode": None,
            "timeout": True,
            "elapsed_s": time.time() - started,
            "started_ts": started,
            "stderr": str(exc)[:1000],
        }


# ---- Detection verification ---- #


def verify_detection(
    store, technique_id: str, *, after_ts: float, window_s: int = 60,
) -> dict[str, Any]:
    """Check the EvidenceStore for a finding whose MITRE tag matches
    the given technique, emitted after ``after_ts`` and within
    ``window_s`` seconds.

    Returns ``{detected: bool, matching_findings: [...], ...}``."""
    norm = _normalize_technique(technique_id)
    parent = _parent_technique(norm)
    matches: list[dict[str, Any]] = []
    for f in store.iter_findings():
        if f.get("ts", 0) < after_ts:
            continue
        if f.get("ts", 0) > after_ts + window_s:
            continue
        mitre = _normalize_technique(f.get("mitre") or "")
        if not mitre:
            continue
        if mitre == norm or _parent_technique(mitre) == parent:
            matches.append({
                "finding_uuid": f.get("finding_uuid"),
                "detector": f.get("detector"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "mitre": mitre,
                "ts": f.get("ts"),
            })
    return {
        "detected": bool(matches),
        "technique_id": norm,
        "after_ts": after_ts,
        "window_s": window_s,
        "matching_findings": matches,
    }


# ---- ART update (git clone / fast-forward) ---- #


_ART_REPO = "https://github.com/redcanaryco/atomic-red-team.git"


def update_corpus(dest: Path | None = None) -> dict[str, Any]:
    """Clone or fast-forward the ART repo into the cache.

    Network-gated: this respects ``digger.opsec.airgap.assert_network_
    allowed`` so air-gapped operators don't accidentally fetch."""
    from digger.opsec.airgap import assert_network_allowed
    assert_network_allowed("art-corpus:atomic-red-team")

    import subprocess
    dest = dest or cache_dir()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if (dest / ".git").is_dir():
        r = subprocess.run(
            ["git", "-C", str(dest), "pull", "--ff-only"],
            capture_output=True, text=True, timeout=120,
        )
    else:
        r = subprocess.run(
            ["git", "clone", "--depth", "1", _ART_REPO, str(dest)],
            capture_output=True, text=True, timeout=300,
        )
    return {
        "dest": str(dest),
        "returncode": r.returncode,
        "stdout": r.stdout[-1000:],
        "stderr": r.stderr[-1000:],
    }
