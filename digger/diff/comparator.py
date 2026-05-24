"""Compare two evidence stores and emit a structured diff.

The point: forensic investigators repeatedly ask "what's new on this host
since the last collection?" digger can answer that directly by comparing
two case directories, identifying artifacts that appeared, disappeared,
or changed, and surfacing findings that newly fired or got resolved.

Identity model
--------------
Two artifacts from different cases are "the same artifact" iff their
``identity()`` is equal. The identity is a stable tuple of fields chosen
per-collector — volatile fields (pid, ephemeral ports, current timestamp)
are deliberately excluded. See ``IDENTITY_FIELDS`` for the per-collector
key list. Collectors not in the map fall back to ``(collector, subject)``.

Per-collector diff modes
------------------------
Some collectors (``recent_files``, ``browsers``, ``macos.unified_logs``)
generate high-churn output that drowns the diff in noise if compared
field-by-field. ``DIFF_MODES`` lets each collector opt in to:

  - "track"     full diff (new / removed / modified)
  - "summarize" only emit counts (artifact count delta)
  - "ignore"    skipped entirely

Findings identity
-----------------
Findings are matched by ``(detector, title)``. A finding present in
case A but not B is "resolved". A finding present in B but not A is
"new". Findings present in both with different evidence are "modified".
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from digger.core.evidence import EvidenceStore


# Fields that change between runs without representing a real change
# to the underlying entity. Stripped from the content signature before
# "modified?" comparison so a re-spawned process with a new pid doesn't
# show up as modified.
VOLATILE_FIELDS: dict[str, set[str]] = {
    "processes": {
        "pid", "ppid", "create_time", "num_threads", "nice",
        "status", "terminal", "connections", "open_files",
        "env_sample", "exe_sha256",
    },
    "network":    {"pid", "fd", "laddr"},
    "system":     {"uptime_seconds", "boot_time"},
    "users":      {"started", "pid"},
    "dns":        {"raw"},
}


# Per-collector identity fields. Volatile attributes (pid, ephemeral
# laddr port, create_time, ts) are deliberately excluded.
IDENTITY_FIELDS: dict[str, tuple[str, ...]] = {
    # cross-platform
    "processes":            ("name", "exe", "cmdline", "username"),
    "network":              ("raddr", "status", "type"),
    "users":                ("user", "uid", "gid"),
    "ssh_keys":             ("path", "name"),
    "env":                  ("subject",),
    "dns":                  ("subject",),
    "recent_files":         ("location",),
    "installed_software":   ("subject",),
    "python_packages":      ("interpreter",),
    "npm_packages":         ("project",),
    "github_workflows":     ("path",),
    "system":               ("subject",),
    # windows
    "windows.registry_persistence": ("hive", "subkey"),
    "windows.scheduled_tasks":      ("subject",),
    "windows.services":             ("name",),
    "windows.event_logs":           ("subject",),
    "windows.defender":             ("subject",),
    "windows.firewall":             ("subject",),
    "windows.wmi_persistence":      ("subject",),
    "windows.startup_folders":      ("path",),
    # macos
    "macos.launchd":           ("path",),
    "macos.login_items":       ("subject",),
    "macos.tcc":               ("path",),
    "macos.quarantine":        ("subject",),
    "macos.unified_logs":      ("subject",),
    "macos.kext":              ("subject",),
    "macos.profiles":          ("subject",),
    "macos.security_posture":  ("subject",),
    # linux
    "linux.systemd":  ("subject",),
    "linux.cron":     ("path", "name"),
    "linux.auth_logs":("subject",),
    "linux.audit":    ("subject",),
    "linux.kmod":     ("subject",),
    "linux.sudoers":  ("path",),
}


# How aggressively each collector should be diffed.
DIFF_MODES: dict[str, str] = {
    # full diff — meaningful churn
    "processes":           "track",
    "network":             "track",
    "users":               "track",
    "ssh_keys":            "track",
    "env":                 "track",
    "dns":                 "track",
    "installed_software":  "track",
    "python_packages":     "track",
    "npm_packages":        "track",
    "github_workflows":    "track",
    "windows.registry_persistence": "track",
    "windows.scheduled_tasks":      "track",
    "windows.services":             "track",
    "windows.defender":             "track",
    "windows.firewall":             "track",
    "windows.wmi_persistence":      "track",
    "windows.startup_folders":      "track",
    "macos.launchd":           "track",
    "macos.login_items":       "track",
    "macos.tcc":               "track",
    "macos.kext":              "track",
    "macos.profiles":          "track",
    "macos.security_posture":  "track",
    "linux.systemd":  "track",
    "linux.cron":     "track",
    "linux.kmod":     "track",
    "linux.sudoers":  "track",
    # summarize only — too noisy for full diff
    "recent_files":        "summarize",
    "browsers":            "summarize",
    "system":              "summarize",
    "macos.quarantine":    "summarize",
    "linux.auth_logs":     "summarize",
    "linux.audit":         "summarize",
    # ignore — always different by nature
    "windows.event_logs":  "ignore",
    "macos.unified_logs":  "ignore",
}


def _identity(art: dict[str, Any]) -> str:
    """Stable identity tuple → string. Differs between artifacts that
    represent semantically distinct entities; matches between two
    artifacts that represent the same entity across runs."""
    fields = IDENTITY_FIELDS.get(art["collector"])
    parts: list[str] = [art["collector"]]
    if fields:
        for f in fields:
            if f == "subject":
                parts.append(str(art.get("subject") or ""))
            else:
                parts.append(json.dumps(art["data"].get(f), sort_keys=True, default=str))
    else:
        parts.append(str(art.get("subject") or ""))
    return "|".join(parts)


def _content_signature(art: dict[str, Any]) -> str:
    """Canonical signature of the artifact's content for change detection.

    ``subject`` is intentionally excluded — it is a display string that
    often embeds volatile values (e.g. ``pid=…``). Identity matching
    already pairs the right artifacts; this signature decides whether
    the paired pair's *content* differs. Volatile fields are stripped
    from the data dict for the same reason.
    """
    volatile = VOLATILE_FIELDS.get(art["collector"], set())
    data = {k: v for k, v in art["data"].items() if k not in volatile}
    return json.dumps({
        "collector": art["collector"],
        "category":  art["category"],
        "data":      data,
    }, sort_keys=True, default=str)


def _content_signature_finding(f: dict[str, Any]) -> str:
    return json.dumps({
        "detector":  f["detector"],
        "severity":  f["severity"],
        "title":     f["title"],
        "summary":   f["summary"],
        "evidence":  f.get("evidence") or {},
        "mitre":     f.get("mitre") or "",
    }, sort_keys=True, default=str)


def _changed_fields(collector: str, old: dict, new: dict) -> list[str]:
    volatile = VOLATILE_FIELDS.get(collector, set())
    keys = (set(old.keys()) | set(new.keys())) - volatile
    return sorted(k for k in keys if old.get(k) != new.get(k))


# ---- result types ----------------------------------------------------- #


@dataclass
class ArtifactDiff:
    """Per-collector artifact diff."""
    collector: str
    mode: str
    base_count: int
    new_count: int
    added: list[dict] = field(default_factory=list)      # in new, not base
    removed: list[dict] = field(default_factory=list)    # in base, not new
    modified: list[dict] = field(default_factory=list)   # changed_fields populated


@dataclass
class FindingDiff:
    """Finding-level diff across the whole case."""
    new: list[dict] = field(default_factory=list)        # appeared in B
    resolved: list[dict] = field(default_factory=list)   # disappeared from B
    persisted: list[dict] = field(default_factory=list)  # in both, unchanged
    modified: list[dict] = field(default_factory=list)   # in both, content differs


@dataclass
class DiffResult:
    base_case_id: str
    new_case_id: str
    base_host: dict
    new_host: dict
    same_host: bool
    base_collected: Optional[float]
    new_collected: Optional[float]
    # Full chain_tip dict from each case:
    #   {"artifacts": {"sha256": "...", "sha3_256": "..."},
    #    "findings":  {"sha256": "...", "sha3_256": "..."},
    #    "case_id": "...", "algorithms": ["SHA-256", "SHA3-256"]}
    base_chain_tip: dict = field(default_factory=dict)
    new_chain_tip:  dict = field(default_factory=dict)
    artifact_diffs: list[ArtifactDiff] = field(default_factory=list)
    findings: FindingDiff = field(default_factory=FindingDiff)

    def summary(self) -> dict[str, int]:
        added   = sum(len(d.added)    for d in self.artifact_diffs)
        removed = sum(len(d.removed)  for d in self.artifact_diffs)
        modified= sum(len(d.modified) for d in self.artifact_diffs)
        return {
            "artifact_added":   added,
            "artifact_removed": removed,
            "artifact_modified":modified,
            "finding_new":      len(self.findings.new),
            "finding_resolved": len(self.findings.resolved),
            "finding_modified": len(self.findings.modified),
            "finding_persisted":len(self.findings.persisted),
        }


# ---- engine ----------------------------------------------------------- #


class DiffEngine:
    """Compare two evidence stores."""

    def __init__(self, base: EvidenceStore, new: EvidenceStore):
        self.base = base
        self.new = new

    def _index_artifacts(self, store: EvidenceStore) -> dict[str, dict[str, dict]]:
        """By collector → identity → artifact."""
        out: dict[str, dict[str, dict]] = {}
        for art in store.iter_artifacts():
            ident = _identity(art)
            out.setdefault(art["collector"], {})[ident] = art
        return out

    def _index_findings(self, store: EvidenceStore) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for f in store.iter_findings():
            key = f"{f['detector']}|{f['title']}"
            out[key] = f
        return out

    def run(self) -> DiffResult:
        base_arts = self._index_artifacts(self.base)
        new_arts  = self._index_artifacts(self.new)

        base_host = self.base.get_meta("host") or {}
        new_host  = self.new.get_meta("host") or {}

        result = DiffResult(
            base_case_id=str(self.base.get_meta("case_id", "")),
            new_case_id=str(self.new.get_meta("case_id", "")),
            base_host=base_host,
            new_host=new_host,
            same_host=(base_host.get("node") == new_host.get("node")
                       and base_host.get("machine") == new_host.get("machine")),
            base_collected=self.base.get_meta("collection_finished"),
            new_collected=self.new.get_meta("collection_finished"),
            base_chain_tip=self.base.chain_tip(),
            new_chain_tip=self.new.chain_tip(),
        )

        all_collectors = sorted(set(base_arts) | set(new_arts))
        for c in all_collectors:
            mode = DIFF_MODES.get(c, "track")
            if mode == "ignore":
                continue
            bmap = base_arts.get(c, {})
            nmap = new_arts.get(c, {})
            d = ArtifactDiff(
                collector=c,
                mode=mode,
                base_count=len(bmap),
                new_count=len(nmap),
            )
            if mode == "summarize":
                # Skip per-row diff for noisy collectors
                result.artifact_diffs.append(d)
                continue
            # mode == "track"
            for ident, art in nmap.items():
                if ident not in bmap:
                    d.added.append(art)
            for ident, art in bmap.items():
                if ident not in nmap:
                    d.removed.append(art)
            for ident in set(bmap) & set(nmap):
                b_sig = _content_signature(bmap[ident])
                n_sig = _content_signature(nmap[ident])
                if b_sig != n_sig:
                    changed = _changed_fields(c, bmap[ident]["data"], nmap[ident]["data"])
                    d.modified.append({
                        "identity": ident,
                        "base": bmap[ident],
                        "new": nmap[ident],
                        "changed_fields": changed,
                    })
            result.artifact_diffs.append(d)

        # Findings
        base_f = self._index_findings(self.base)
        new_f  = self._index_findings(self.new)
        for key, f in new_f.items():
            if key not in base_f:
                result.findings.new.append(f)
            else:
                b_sig = _content_signature_finding(base_f[key])
                n_sig = _content_signature_finding(f)
                if b_sig == n_sig:
                    result.findings.persisted.append(f)
                else:
                    result.findings.modified.append({
                        "key": key,
                        "base": base_f[key],
                        "new": f,
                    })
        for key, f in base_f.items():
            if key not in new_f:
                result.findings.resolved.append(f)

        return result


def compute_diff(base_dir: str | Path, new_dir: str | Path) -> DiffResult:
    base = EvidenceStore(base_dir)
    new = EvidenceStore(new_dir)
    try:
        return DiffEngine(base, new).run()
    finally:
        base.close()
        new.close()
