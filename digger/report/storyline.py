"""Aftermath-style storyline reconstruction.

Walks the finding graph of a digger case and clusters related findings
into "event chains" — narrative blocks that turn a flat list of 80
findings into 4-6 ordered storylines analysts can actually read.

Inspired by Jamf Aftermath's macOS triage approach: rather than asking
the analyst to manually correlate findings by shared pid / path /
timestamp / host, do it once at report-build time and emit a
"Likely event chain" block at the top of the report.

Clustering signals (any one creates an edge between two findings)
-----------------------------------------------------------------
  * shared ``pid`` in ``evidence``  (same process)
  * shared parent ``pid``           (parent → child execution)
  * shared file ``path`` / ``basename`` (file referenced by both)
  * shared C2 ``domain`` / ``host`` / ``remote_ip``
  * shared SHA-256 ``hash``
  * shared ``campaign`` value       (Mini Shai-Hulud, TrapDoor, etc.)
  * temporal proximity              (findings within ``WINDOW_S`` seconds)
  * shared ``artifact_uuid``        (both findings reference the same
                                     source artifact)

The result is a union-find over findings: every connected component
becomes one storyline. Each storyline gets ranked by:

  rank = (sum of severity weights) × (kill-chain coverage breadth)

  severity weight:  info=1, low=2, medium=4, high=8, critical=16
  kill-chain breadth: count of distinct MITRE tactics covered

A 2-finding storyline of critical + critical that spans Initial Access
+ Execution + Persistence outranks a 20-finding storyline of low /
info findings concentrated in Defense Evasion.

Output formats
--------------
  build_storylines(store) → list[Storyline]
  render_storyline_text(storylines) → str
  render_storyline_html(storylines) → str (snippet for html_report.py)
  render_storyline_markdown(storylines) → str
"""

from __future__ import annotations

import html
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable


# ---- tunables ---- #

# Findings within this many seconds of each other share a "time
# proximity" edge. Conservative default (10 minutes) — wide enough
# to catch shell session → child process timing, narrow enough that
# unrelated hours-apart events don't accidentally merge.
WINDOW_S = 600

_SEVERITY_WEIGHTS = {
    "info":      1,
    "low":       2,
    "medium":    4,
    "high":      8,
    "critical": 16,
}

# Sigma-convention tag → MITRE tactic slug. Re-uses the same canonical
# mapping the heatmap module uses.
_TACTIC_OF_TECHNIQUE_LAZY: dict[str, list[str]] | None = None


def _tactic_map() -> dict[str, list[str]]:
    global _TACTIC_OF_TECHNIQUE_LAZY
    if _TACTIC_OF_TECHNIQUE_LAZY is None:
        from digger.genrule.heatmap import _load_tactic_map
        _TACTIC_OF_TECHNIQUE_LAZY = _load_tactic_map()
    return _TACTIC_OF_TECHNIQUE_LAZY


def _tactics_for_mitre(mitre: str | None) -> list[str]:
    if not mitre:
        return []
    return _tactic_map().get(mitre.strip().upper(), [])


# ---- Data model ---- #


@dataclass
class Storyline:
    """One connected cluster of findings, ranked + summarized."""
    finding_uuids: list[str]
    findings: list[dict[str, Any]]   # full finding dicts, time-sorted
    tactics: list[str]               # distinct tactic slugs covered
    detectors: list[str]             # distinct detectors that fired
    severity_max: str                # highest severity in the chain
    rank: float                      # the ranking number
    span_s: float                    # time span first → last finding
    label: str                       # human title for the chain
    primary_actors: list[str]        # pids/paths/domains/campaign names
                                     # this storyline revolves around
    suspected_campaign: str = ""     # populated if all findings agree

    @property
    def severity_weights_sum(self) -> int:
        return sum(_SEVERITY_WEIGHTS.get((f.get("severity") or "info"), 1)
                   for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "rank": self.rank,
            "severity_max": self.severity_max,
            "tactics": self.tactics,
            "detectors": self.detectors,
            "finding_count": len(self.findings),
            "span_s": self.span_s,
            "primary_actors": self.primary_actors,
            "suspected_campaign": self.suspected_campaign,
            "finding_uuids": self.finding_uuids,
        }


# ---- Union-find ---- #


class _UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def add(self, x: str) -> None:
        self.parent.setdefault(x, x)

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def components(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = defaultdict(list)
        for x in self.parent:
            out[self.find(x)].append(x)
        return out


# ---- Edge extraction ---- #


def _extract_keys(f: dict[str, Any]) -> dict[str, set[str]]:
    """Pull the per-finding "join keys" used to detect edges.

    Returns a dict of ``key_type → values`` so the edge-building loop
    can compare each key type independently.
    """
    ev = f.get("evidence") or {}
    keys: dict[str, set[str]] = defaultdict(set)

    # PID + parent PID
    for k in ("pid", "ppid"):
        v = ev.get(k)
        if isinstance(v, (int, str)) and str(v).strip():
            keys["pid"].add(str(v))

    # File paths + basenames
    for k in ("path", "exe", "file", "target_path"):
        v = ev.get(k)
        if isinstance(v, str) and v.strip():
            keys["path"].add(v.strip())
            if "/" in v or "\\" in v:
                bn = re.split(r"[\\/]", v.rstrip("/\\"))[-1].lower()
                if bn:
                    keys["basename"].add(bn)

    # Pull paths out of "paths" / "matching_paths" arrays
    for k in ("paths", "matching_paths", "files"):
        v = ev.get(k)
        if isinstance(v, list):
            for entry in v:
                if isinstance(entry, str) and entry.strip():
                    keys["path"].add(entry.strip())

    # Network: domain, host, IP
    for k in ("domain", "host", "remote_ip", "ip", "host_observed"):
        v = ev.get(k)
        if isinstance(v, str) and v.strip():
            keys["host"].add(v.strip().lower())

    # Hash IOCs
    for k in ("hash", "sha256", "sha1", "md5"):
        v = ev.get(k)
        if isinstance(v, str) and v.strip():
            keys["hash"].add(v.strip().lower())

    # Campaign tag (Mini Shai-Hulud, TrapDoor, Nightmare-Eclipse, etc.)
    camp = ev.get("campaign")
    if isinstance(camp, str) and camp.strip():
        keys["campaign"].add(camp.strip())

    # Artifact UUIDs the finding cites
    for ref in (f.get("artifact_refs") or []):
        if isinstance(ref, str) and ref.strip():
            keys["artifact_uuid"].add(ref.strip())

    return keys


def _share_edge(
    a: dict[str, set[str]],
    b: dict[str, set[str]],
    ts_a: float,
    ts_b: float,
) -> bool:
    """Two findings share an edge if any join-key set overlaps OR
    they fall within the temporal window."""
    if abs(ts_a - ts_b) <= WINDOW_S:
        return True
    for key_type in ("pid", "path", "basename", "host", "hash",
                     "campaign", "artifact_uuid"):
        if a.get(key_type) and (a[key_type] & b.get(key_type, set())):
            return True
    return False


# ---- Storyline construction ---- #


def _component_label(findings: list[dict[str, Any]], primary: list[str]) -> str:
    """Compose a short human-readable title for a chain."""
    detectors = sorted({(f.get("detector") or "?") for f in findings})
    # Special-case the well-known campaign clusters for clearer text.
    campaign = next(
        ((f.get("evidence") or {}).get("campaign") for f in findings
         if (f.get("evidence") or {}).get("campaign")),
        None,
    )
    if campaign:
        return f"{campaign} campaign chain ({len(findings)} findings)"
    if len(detectors) == 1:
        return f"{detectors[0]} sequence ({len(findings)} findings)"
    head_actor = primary[0] if primary else "(no anchor)"
    return f"Chain anchored on {head_actor} ({len(findings)} findings)"


def _primary_actors(findings: list[dict[str, Any]]) -> list[str]:
    """Pick the 3 most-distinguishing anchor strings for the label."""
    counter: dict[str, int] = defaultdict(int)
    for f in findings:
        ev = f.get("evidence") or {}
        for k in ("campaign", "host", "domain", "remote_ip",
                  "exploit", "pattern", "exe", "path", "name"):
            v = ev.get(k)
            if isinstance(v, str) and v.strip():
                counter[v.strip()] += 1
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and item.strip():
                        counter[item.strip()] += 1
    # Return top 3 by occurrence, ties broken alphabetically
    return [k for k, _ in sorted(counter.items(),
                                 key=lambda kv: (-kv[1], kv[0]))][:3]


def _rank(findings: list[dict[str, Any]], tactics: list[str]) -> float:
    sev_sum = sum(
        _SEVERITY_WEIGHTS.get((f.get("severity") or "info"), 1)
        for f in findings
    )
    return sev_sum * max(1, len(tactics))


def _severity_max(findings: list[dict[str, Any]]) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    seen = {(f.get("severity") or "info") for f in findings}
    for s in reversed(order):
        if s in seen:
            return s
    return "info"


def build_storylines(
    findings: Iterable[dict[str, Any]] | None = None,
    store=None,
) -> list[Storyline]:
    """Build storylines from a list of finding dicts or an EvidenceStore.

    Pass either ``findings`` (already-loaded list of dicts) or
    ``store`` (an open EvidenceStore — we'll iterate it). When both
    are passed, ``findings`` wins."""
    if findings is None and store is not None:
        findings = list(store.iter_findings())
    findings = list(findings or [])
    if not findings:
        return []

    # Sort by timestamp so we can do an O(n) sweep within the temporal
    # window instead of O(n²) all-pairs.
    findings.sort(key=lambda f: f.get("ts", 0))
    uf = _UnionFind()
    keys_by_uuid: dict[str, dict[str, set[str]]] = {}
    ts_by_uuid: dict[str, float] = {}
    finding_by_uuid: dict[str, dict[str, Any]] = {}

    for f in findings:
        uid = f.get("finding_uuid") or f"_idx{id(f)}"
        f["finding_uuid"] = uid
        uf.add(uid)
        keys_by_uuid[uid] = _extract_keys(f)
        ts_by_uuid[uid] = float(f.get("ts", 0))
        finding_by_uuid[uid] = f

    # All-pairs within the time window (and across the whole list for
    # join-key overlap). For typical case sizes (≤ 1000 findings)
    # this is fine; if it gets big we can index by host/path/hash.
    n = len(findings)
    for i in range(n):
        u_i = findings[i]["finding_uuid"]
        for j in range(i + 1, n):
            u_j = findings[j]["finding_uuid"]
            # If we're outside the temporal window AND there's no
            # join-key overlap, no edge.
            if _share_edge(keys_by_uuid[u_i], keys_by_uuid[u_j],
                           ts_by_uuid[u_i], ts_by_uuid[u_j]):
                uf.union(u_i, u_j)

    # Build Storyline objects per component
    storylines: list[Storyline] = []
    for comp_uuids in uf.components().values():
        comp_findings = sorted(
            [finding_by_uuid[u] for u in comp_uuids],
            key=lambda f: f.get("ts", 0),
        )
        tactics_set: set[str] = set()
        for f in comp_findings:
            for t in _tactics_for_mitre(f.get("mitre")):
                tactics_set.add(t)
        tactics = sorted(tactics_set)
        detectors = sorted({(f.get("detector") or "?") for f in comp_findings})
        actors = _primary_actors(comp_findings)
        ts_first = comp_findings[0].get("ts", 0)
        ts_last = comp_findings[-1].get("ts", 0)
        # Suspected campaign: only set if every finding in the chain
        # agrees on a campaign value
        camps = {((f.get("evidence") or {}).get("campaign") or "")
                 for f in comp_findings if (f.get("evidence") or {}).get("campaign")}
        suspected = next(iter(camps)) if len(camps) == 1 else ""
        storylines.append(Storyline(
            finding_uuids=[f.get("finding_uuid") for f in comp_findings],
            findings=comp_findings,
            tactics=tactics,
            detectors=detectors,
            severity_max=_severity_max(comp_findings),
            rank=_rank(comp_findings, tactics),
            span_s=float(ts_last) - float(ts_first),
            label=_component_label(comp_findings, actors),
            primary_actors=actors,
            suspected_campaign=suspected,
        ))

    storylines.sort(key=lambda s: -s.rank)
    return storylines


# ---- Renderers ---- #


def render_storyline_text(storylines: list[Storyline], *, top_n: int = 10) -> str:
    if not storylines:
        return "No storylines synthesized (no findings, or all findings stand alone).\n"
    out: list[str] = []
    out.append("Likely event chains (ranked by severity × kill-chain breadth)")
    out.append("=" * 80)
    for i, s in enumerate(storylines[:top_n], 1):
        out.append(
            f"\n{i}. [{s.severity_max.upper()}] {s.label} · rank={s.rank:.0f} · "
            f"{len(s.findings)} findings · "
            f"{len(s.tactics)} tactic{'s' if len(s.tactics) != 1 else ''} "
            f"({', '.join(s.tactics) or 'unmapped'}) · span={s.span_s:.0f}s"
        )
        if s.suspected_campaign:
            out.append(f"   campaign: {s.suspected_campaign}")
        if s.primary_actors:
            out.append(f"   anchors: {', '.join(s.primary_actors)}")
        out.append(f"   detectors: {', '.join(s.detectors)}")
        out.append("   sequence:")
        for f in s.findings[:8]:
            mitre = f.get("mitre") or "—"
            out.append(
                f"     · [{f.get('severity', '?'):>8}] {f.get('detector', '?'):<22} "
                f"{mitre:<10} {(f.get('title') or '')[:90]}"
            )
        if len(s.findings) > 8:
            out.append(f"     · …and {len(s.findings) - 8} more")
    if len(storylines) > top_n:
        out.append(f"\n…and {len(storylines) - top_n} more storylines.")
    return "\n".join(out) + "\n"


def render_storyline_markdown(storylines: list[Storyline], *, top_n: int = 10) -> str:
    if not storylines:
        return "_No storylines synthesized._\n"
    out: list[str] = []
    out.append("## Likely event chains")
    out.append("")
    out.append("_Ranked by severity × kill-chain breadth._\n")
    for i, s in enumerate(storylines[:top_n], 1):
        out.append(
            f"### {i}. {s.label}  "
            f"`{s.severity_max.upper()}` · rank {s.rank:.0f}"
        )
        if s.suspected_campaign:
            out.append(f"**Campaign:** `{s.suspected_campaign}`")
        out.append(
            f"**Tactics covered:** {', '.join(s.tactics) or '(unmapped)'}  "
            f"**Span:** {s.span_s:.0f}s  "
            f"**Detectors:** `{', '.join(s.detectors)}`"
        )
        if s.primary_actors:
            out.append(f"**Anchors:** {', '.join(f'`{a}`' for a in s.primary_actors)}")
        out.append("")
        out.append("| ts | severity | detector | mitre | title |")
        out.append("|---|---|---|---|---|")
        for f in s.findings[:12]:
            safe_title = (f.get("title") or "").replace("|", "\\|")
            out.append(
                f"| {int(f.get('ts', 0))} "
                f"| {f.get('severity', '?')} "
                f"| `{f.get('detector', '?')}` "
                f"| {f.get('mitre') or '—'} "
                f"| {safe_title} |"
            )
        if len(s.findings) > 12:
            out.append(f"| … | … | … | … | _…and {len(s.findings) - 12} more_ |")
        out.append("")
    return "\n".join(out) + "\n"


def render_storyline_html(storylines: list[Storyline], *, top_n: int = 10) -> str:
    """HTML snippet — designed to slot into the existing html_report.py
    above the per-finding table."""
    if not storylines:
        return "<section class='storylines empty'><h2>Storylines</h2><p>No storylines synthesized.</p></section>"
    parts: list[str] = []
    parts.append(
        "<section class='storylines'><h2>Likely event chains</h2>"
        "<p class='subtitle'>Findings grouped by shared "
        "pid / path / host / hash / campaign / timestamp window. "
        "Ranked by severity × kill-chain breadth.</p>"
    )
    for i, s in enumerate(storylines[:top_n], 1):
        sev_class = f"sev-{s.severity_max}"
        parts.append(f"<article class='storyline {sev_class}'>")
        parts.append(
            f"<h3>#{i}. {html.escape(s.label)} "
            f"<span class='rank'>rank {int(s.rank)}</span></h3>"
        )
        meta = [
            f"<span class='sev'>{html.escape(s.severity_max)}</span>",
            f"<span>tactics: {html.escape(', '.join(s.tactics) or '(unmapped)')}</span>",
            f"<span>detectors: {html.escape(', '.join(s.detectors))}</span>",
            f"<span>span: {int(s.span_s)}s</span>",
            f"<span>{len(s.findings)} findings</span>",
        ]
        if s.suspected_campaign:
            meta.insert(0, f"<span class='campaign'>campaign: {html.escape(s.suspected_campaign)}</span>")
        parts.append("<div class='meta'>" + " · ".join(meta) + "</div>")
        parts.append("<table class='sequence'><thead><tr>"
                      "<th>ts</th><th>sev</th><th>detector</th>"
                      "<th>mitre</th><th>title</th></tr></thead><tbody>")
        for f in s.findings[:12]:
            parts.append(
                "<tr>"
                f"<td>{int(f.get('ts', 0))}</td>"
                f"<td>{html.escape(f.get('severity', '?'))}</td>"
                f"<td><code>{html.escape(f.get('detector', '?'))}</code></td>"
                f"<td>{html.escape(f.get('mitre') or '—')}</td>"
                f"<td>{html.escape((f.get('title') or '')[:140])}</td>"
                "</tr>"
            )
        if len(s.findings) > 12:
            parts.append(f"<tr><td colspan='5'>…and {len(s.findings) - 12} more</td></tr>")
        parts.append("</tbody></table></article>")
    parts.append("</section>")
    return "\n".join(parts)


# ---- JSON ---- #


def storylines_to_json(storylines: list[Storyline]) -> list[dict[str, Any]]:
    return [s.to_dict() for s in storylines]
