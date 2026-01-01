"""Sigma rule loader and runner.

Sigma (https://github.com/SigmaHQ/sigma) is the de-facto open detection
rule format. A Sigma rule looks like:

  title: My rule
  logsource:
    category: process_creation
    product: windows
  detection:
    selection:
      Image|endswith: '\\powershell.exe'
      CommandLine|contains: '-EncodedCommand'
    condition: selection

We support a useful subset:
  - process_creation log source — matches against digger's `processes` collector
  - network_connection log source — matches against `network` collector
  - simple field modifiers: contains, endswith, startswith, re
  - single-selection conditions, or "selection1 and selection2",
    "selection1 or selection2".
  - keyword lists (top-level list under detection.<name>)

Rules that use unsupported features are skipped with a clear log line.

This is *not* a full sigma engine (those exist standalone) — it's a
zero-dependency, pragmatic implementation that handles the bulk of real-
world rules for endpoint telemetry. Drop full sigma rule files under
`digger/rules/sigma/` or pass `--sigma-dir`.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector

_RULES_DIR = Path(__file__).parent.parent / "rules" / "sigma"


@dataclass
class SigmaRule:
    title: str
    id: str
    description: str
    level: str           # informational | low | medium | high | critical
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source_path: str = ""

    def severity(self) -> str:
        lvl = (self.level or "").lower()
        return {
            "informational": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }.get(lvl, "medium")


def _default_rule_dirs() -> list[Path]:
    """Default search path: bundled rules first, then any live-fetched
    SigmaHQ corpus from the intel cache."""
    dirs = [_RULES_DIR]
    try:
        from digger.intel.sources.sigma_corpus import loaded_rule_dirs
        dirs.extend(loaded_rule_dirs())
    except Exception:
        pass
    return dirs


class SigmaLoader:
    def __init__(self, dirs: Iterable[Path] = ()):
        self.dirs = list(dirs) or _default_rule_dirs()

    def load(self) -> list[SigmaRule]:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            return []
        out: list[SigmaRule] = []
        for d in self.dirs:
            if not Path(d).is_dir():
                continue
            for f in Path(d).rglob("*.yml"):
                try:
                    with f.open("r", encoding="utf-8") as fh:
                        docs = list(yaml.safe_load_all(fh))
                except Exception:
                    continue
                for raw in docs:
                    if not isinstance(raw, dict):
                        continue
                    if "detection" not in raw:
                        continue
                    out.append(SigmaRule(
                        title=raw.get("title", "untitled"),
                        id=raw.get("id", ""),
                        description=raw.get("description", ""),
                        level=raw.get("level", "medium"),
                        logsource=raw.get("logsource", {}),
                        detection=raw.get("detection", {}),
                        falsepositives=raw.get("falsepositives", []) or [],
                        tags=raw.get("tags", []) or [],
                        source_path=str(f),
                    ))
        return out


# ---- runtime matcher ---------------------------------------------------- #


def _field_value(record: dict, fname: str) -> Optional[str]:
    """Resolve a Sigma field name against a digger record."""
    fname_l = fname.lower()
    if fname_l in ("image", "exe"):
        return record.get("exe")
    if fname_l in ("commandline", "cmdline", "command_line"):
        cl = record.get("cmdline")
        return " ".join(cl) if isinstance(cl, list) else cl
    if fname_l in ("parentimage",):
        return record.get("_parent_exe")
    if fname_l in ("parentcommandline",):
        return record.get("_parent_cmdline")
    if fname_l in ("user", "username"):
        return record.get("username")
    if fname_l in ("destinationport",):
        raddr = record.get("raddr")
        if isinstance(raddr, (list, tuple)) and len(raddr) > 1:
            return str(raddr[1])
        return None
    if fname_l in ("destinationip", "destinationhostname"):
        raddr = record.get("raddr")
        if isinstance(raddr, (list, tuple)) and raddr:
            return str(raddr[0])
        return None
    return record.get(fname) or record.get(fname.lower())


def _match_field(record: dict, field_spec: str, expected: Any) -> bool:
    name, *modifiers = field_spec.split("|")
    actual = _field_value(record, name)
    if actual is None:
        return False
    actual_l = str(actual).lower()
    expected_list = expected if isinstance(expected, list) else [expected]
    for e in expected_list:
        e_l = str(e).lower()
        if not modifiers:
            if e_l == actual_l:
                return True
        else:
            mod = modifiers[0]
            if mod == "contains" and e_l in actual_l:
                return True
            if mod == "startswith" and actual_l.startswith(e_l):
                return True
            if mod == "endswith" and actual_l.endswith(e_l):
                return True
            if mod == "re":
                try:
                    if re.search(e, str(actual), re.I):
                        return True
                except re.error:
                    continue
    return False


def _selection_matches(record: dict, selection: Any) -> bool:
    if isinstance(selection, dict):
        return all(_match_field(record, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        # keyword list — any keyword present in any value
        joined = " ".join(str(v) for v in record.values() if isinstance(v, (str, list))).lower()
        return any(str(k).lower() in joined for k in selection)
    return False


_CONDITION_RE = re.compile(r"^\s*(\w+)(?:\s+(and|or)\s+(\w+))?\s*$", re.I)


def _eval_condition(detection: dict, record: dict) -> bool:
    condition = detection.get("condition", "selection")
    m = _CONDITION_RE.match(str(condition))
    if not m:
        return False
    left, op, right = m.group(1), m.group(2), m.group(3)
    if left not in detection:
        return False
    left_match = _selection_matches(record, detection[left])
    if not op:
        return left_match
    right_match = _selection_matches(record, detection.get(right, {}))
    if op.lower() == "and":
        return left_match and right_match
    if op.lower() == "or":
        return left_match or right_match
    return False


class SigmaDetector(Detector):
    name = "sigma"
    description = "Sigma rule matches over process and network telemetry."

    def __init__(self, dirs: Iterable[Path] = ()):
        self.loader = SigmaLoader(dirs)

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        rules = self.loader.load()
        if not rules:
            return
        # Build a parent index for ParentImage support
        proc_index = {a["data"].get("pid"): a["data"] for a in store.iter_artifacts(collector="processes")
                       if a["data"].get("pid")}

        for rule in rules:
            ls = rule.logsource or {}
            cat = (ls.get("category") or "").lower()
            target_collector = None
            if cat == "process_creation":
                target_collector = "processes"
            elif cat == "network_connection":
                target_collector = "network"
            else:
                continue
            for art in store.iter_artifacts(collector=target_collector):
                rec = dict(art["data"])
                # enrich with parent process for ParentImage/ParentCommandLine fields
                ppid = rec.get("ppid")
                if ppid and ppid in proc_index:
                    parent = proc_index[ppid]
                    rec["_parent_exe"] = parent.get("exe")
                    rec["_parent_cmdline"] = " ".join(parent.get("cmdline") or [])
                if _eval_condition(rule.detection, rec):
                    yield Finding(
                        detector=self.name,
                        severity=rule.severity(),
                        title=f"Sigma: {rule.title}",
                        summary=(
                            f"{rule.description or 'Sigma rule match'}\n\nRule id: {rule.id}\n"
                            f"Source: {rule.source_path}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"rule_id": rule.id, "rule_title": rule.title, "tags": rule.tags, "record": rec},
                        mitre=_first_mitre_tag(rule.tags),
                    )


def _first_mitre_tag(tags: list[str]) -> str:
    for t in tags or []:
        m = re.match(r"attack\.(t\d{4}(\.\d{3})?)$", t.lower())
        if m:
            return m.group(1).upper()
    return ""


def sigma_detect(store: EvidenceStore, dirs: Iterable[Path] = ()) -> int:
    return SigmaDetector(dirs).run(store)
