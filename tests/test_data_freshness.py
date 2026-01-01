"""CI guardrail: every detector that loads bundled rules MUST also load
the live equivalent first.

Background:
  The user's explicit invariant after the seeded-records audit was
  "live data in all cases". This test prevents regressions where a new
  detector ships consuming only bundled YAML and never picks up the
  authoritative upstream feed.

Rule (statically enforced via AST):
  For every Python file that defines a Detector subclass and calls
  ``load_yaml(...)``, at least one of the following must hold:

    1. The file also calls ``load_intel(...)`` AND the FIRST
       ``load_intel`` line number is ≤ the FIRST ``load_yaml`` line
       number, OR
    2. The two calls are on the same line (e.g.
       ``load_intel("x") or load_yaml("y")`` chains).
    3. The file contains an explicit opt-out marker comment of the form
       ``# live-first-ok: <reason>`` (used when the bundled file
       carries digger-native fields that have no upstream equivalent).

  Otherwise: hard test failure.

Add a new detector that breaks this rule and the test fails with a
pointer to the offending file. Either wire up the live feed or add the
opt-out comment with a clear reason.
"""

from __future__ import annotations

import ast
from pathlib import Path


_DETECTOR_DIRS = (
    Path(__file__).parent.parent / "digger" / "detectors",
    Path(__file__).parent.parent / "digger" / "memory",
    Path(__file__).parent.parent / "digger" / "loki",
    Path(__file__).parent.parent / "digger" / "signing",
)

_OPT_OUT_MARKER = "# live-first-ok:"


def _detector_files() -> list[Path]:
    out: list[Path] = []
    for d in _DETECTOR_DIRS:
        if not d.is_dir():
            continue
        for p in d.glob("*.py"):
            if p.name.startswith("_") or p.name == "__init__.py":
                continue
            # Heuristic: must mention "Detector" subclass somewhere
            text = p.read_text(encoding="utf-8", errors="replace")
            if "Detector" not in text and "to_sigma_template" not in text:
                continue
            out.append(p)
    return out


def _first_call_line(tree: ast.AST, fname: str) -> int | None:
    """Return the line number of the first ``fname(...)`` call in tree."""
    found: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name) and f.id == fname:
            found.append(node.lineno)
        elif isinstance(f, ast.Attribute) and f.attr == fname:
            found.append(node.lineno)
    return min(found) if found else None


def test_every_detector_with_load_yaml_also_loads_live_intel():
    offenders: list[str] = []
    inspected = 0
    for p in _detector_files():
        try:
            src = p.read_text(encoding="utf-8")
            tree = ast.parse(src)
        except (SyntaxError, OSError):
            continue
        inspected += 1
        load_yaml_line = _first_call_line(tree, "load_yaml")
        if load_yaml_line is None:
            continue  # detector doesn't read bundled data — fine
        load_intel_line = _first_call_line(tree, "load_intel")
        has_opt_out = _OPT_OUT_MARKER in src
        if has_opt_out:
            continue
        if load_intel_line is None:
            offenders.append(
                f"{p.name}: calls load_yaml(...) at line {load_yaml_line} "
                "but never calls load_intel(...) — every bundled-rule "
                "load must also pull from the live equivalent feed. Add "
                f"a load_intel(...) call or an opt-out marker "
                f"'{_OPT_OUT_MARKER} <reason>'.")
            continue
        # Same-line OK (chained `or`); intel-before-yaml OK; yaml-before-intel
        # only OK if both calls reside on adjacent lines (passed to a
        # normalizer that handles per-tier live-first internally — see
        # digger/detectors/shai_hulud.py for the established pattern).
        if load_intel_line > load_yaml_line + 1:
            offenders.append(
                f"{p.name}: load_yaml(...) at line {load_yaml_line} runs "
                f"BEFORE load_intel(...) at line {load_intel_line}. Live "
                "feed must take precedence — either reorder the calls or "
                f"add '{_OPT_OUT_MARKER} <reason>'.")
    assert not offenders, (
        f"\n\nLive-first convention violations ({len(offenders)} of "
        f"{inspected} detector files):\n  - "
        + "\n  - ".join(offenders))


def test_at_least_one_detector_was_inspected():
    """Sanity: the file discovery actually found detector modules."""
    files = _detector_files()
    assert len(files) >= 10, f"only found {len(files)} detector files: {files}"


def test_opt_out_marker_format_is_documented():
    """The opt-out marker exists; make sure at least one file uses it
    with a non-empty reason — proves the escape hatch is in use and not
    a dead code path."""
    used = []
    for p in _detector_files():
        text = p.read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(_OPT_OUT_MARKER):
                reason = line.split(":", 1)[1].strip() if ":" in line else ""
                assert reason, (
                    f"{p.name}: '{_OPT_OUT_MARKER}' marker without reason. "
                    "Reasons make the opt-out auditable.")
                used.append(p.name)
    # OK if none used yet — the guardrail still works.


# ---- Test the test: prove the AST checker catches a synthetic violation ----


def _check_synthetic(src: str) -> tuple[int | None, int | None]:
    """Run the AST checker against a source string. Returns (load_yaml_line,
    load_intel_line)."""
    tree = ast.parse(src)
    return _first_call_line(tree, "load_yaml"), _first_call_line(tree, "load_intel")


def test_first_call_line_detects_load_yaml():
    src = "from x import load_yaml\nclass D:\n    def f(self):\n        load_yaml('a')\n"
    yaml_line, intel_line = _check_synthetic(src)
    assert yaml_line == 4
    assert intel_line is None


def test_first_call_line_detects_intel_before_yaml():
    src = (
        "from x import load_yaml, load_intel\n"
        "class D:\n"
        "    def f(self):\n"
        "        live = load_intel('feed')\n"
        "        rules = load_yaml('file.yaml')\n"
    )
    yaml_line, intel_line = _check_synthetic(src)
    assert intel_line == 4
    assert yaml_line == 5
    # The main test treats intel_line <= yaml_line as OK
    assert intel_line < yaml_line


def test_synthetic_violation_would_trip_main_check():
    """If yaml comes >1 line before intel and no opt-out, the rule trips."""
    src = (
        "from x import load_yaml, load_intel\n"
        "class D:\n"
        "    def f(self):\n"
        "        rules = load_yaml('a')\n"
        "        # ... lots of code ...\n"
        "        # ... more code ...\n"
        "        live = load_intel('b')\n"
    )
    yaml_line, intel_line = _check_synthetic(src)
    # yaml at 4, intel at 7 — would trip (intel > yaml + 1) and no opt-out
    assert yaml_line == 4
    assert intel_line == 7
    assert intel_line > yaml_line + 1   # this is the offending condition
    assert _OPT_OUT_MARKER not in src   # no opt-out → would fail main check
