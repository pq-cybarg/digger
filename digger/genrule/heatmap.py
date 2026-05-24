"""MITRE ATT&CK coverage heatmap derived from detector tags.

Inputs
------
Coverage is computed from two sources, in order:

  1. Every Detector's ``to_sigma_template()`` (when present) — its
     ``tags`` list yields ATT&CK technique IDs via the ``attack.t####``
     convention. This is the *static* coverage surface — what the
     detector knows how to flag, independent of any specific case.
  2. Per-detector tag map in ``digger.genrule.sigma._tags`` — the
     detector_tag_map dict maps detector name → tags. We mine its
     values for additional ``attack.*`` tags so that detectors which
     emit only per-finding Sigma rules (not class-level templates)
     still contribute to the heatmap.

Tactic mapping
--------------
ATT&CK technique → tactic is a many-to-many relationship. We use a
bundled canonical mapping (``digger/rules/attack/tactic_map.yaml``)
seeded from the MITRE Enterprise matrix. When the live MITRE ATT&CK
intel feed is cached and parses out tactic info, that overrides the
bundled fallback per technique. (Live-first; bundled is the
air-gap-default first-run case.)

Output formats
--------------
``render_text``  → grid printable in a terminal (tactics columns,
                   technique IDs in each column with detector tags).
``render_json``  → machine-readable: ``{tactics: [...], techniques:
                   [...], coverage: {technique_id: {tactic, detectors,
                   sigma_template}}}``.
``render_html``  → standalone HTML page that mirrors the MITRE
                   ATT&CK Navigator visual: tactics columns top→
                   bottom, techniques rows colored by coverage
                   density (1 detector = light, 3+ = dark).
"""

from __future__ import annotations

import html
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


# ---- Tactic canonical order ------------------------------------------- #

ATTACK_TACTICS = [
    ("reconnaissance",          "Reconnaissance"),
    ("resource-development",    "Resource Development"),
    ("initial-access",          "Initial Access"),
    ("execution",               "Execution"),
    ("persistence",             "Persistence"),
    ("privilege-escalation",    "Privilege Escalation"),
    ("defense-evasion",         "Defense Evasion"),
    ("credential-access",       "Credential Access"),
    ("discovery",               "Discovery"),
    ("lateral-movement",        "Lateral Movement"),
    ("collection",              "Collection"),
    ("command-and-control",     "Command and Control"),
    ("exfiltration",            "Exfiltration"),
    ("impact",                  "Impact"),
]
TACTIC_SLUGS = [s for s, _ in ATTACK_TACTICS]
TACTIC_LABELS = dict(ATTACK_TACTICS)


# ---- ATT&CK tag parsing ----------------------------------------------- #

# Matches Sigma-convention tags: attack.t1059, attack.t1059.001
_ATTACK_TECHNIQUE_RX = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.I)
# Matches tactic-shape tags too, eg "attack.defense_evasion".
_ATTACK_TACTIC_RX = re.compile(
    r"^attack\.(reconnaissance|resource_development|initial_access|execution|"
    r"persistence|privilege_escalation|defense_evasion|credential_access|"
    r"discovery|lateral_movement|collection|command_and_control|"
    r"exfiltration|impact)$",
    re.I,
)


def _tactic_slug_from_tag(tag: str) -> str | None:
    """Sigma convention uses underscore: ``attack.defense_evasion``.
    The MITRE matrix uses kebab: ``defense-evasion``. Normalize."""
    m = _ATTACK_TACTIC_RX.match(tag)
    if not m:
        return None
    return m.group(1).lower().replace("_", "-")


def _technique_from_tag(tag: str) -> str | None:
    """Return ``T####`` or ``T####.###`` uppercase, or None."""
    m = _ATTACK_TECHNIQUE_RX.match(tag)
    if not m:
        return None
    return "T" + m.group(1).upper()


# ---- Coverage extraction --------------------------------------------- #


def _detector_static_tags() -> dict[str, list[str]]:
    """Map detector name → all attack.* tags it can produce.

    Combines:
      a) Each Detector's class-level ``to_sigma_template().tags``.
      b) The per-detector tag map in ``genrule.sigma._tags``-builder
         (the ``detector_tag_map`` dict). We can't get to it at runtime
         cleanly without calling _tags() for a fake finding, so we
         duplicate the dict here — the source of truth is one place.
    """
    from digger.detectors import all_detectors

    out: dict[str, set[str]] = defaultdict(set)
    for det in all_detectors():
        try:
            tpl = det.to_sigma_template()
        except Exception:
            tpl = None
        if isinstance(tpl, dict):
            for tag in tpl.get("tags") or []:
                if isinstance(tag, str) and tag.startswith("attack."):
                    out[det.name].add(tag)

    # Also pull in tags from the detector_tag_map in sigma.py. Re-derive
    # by invoking _tags() against a synthetic finding for each detector.
    from digger.genrule.sigma import _tags as _sigma_tags
    for det in all_detectors():
        synth = {"detector": det.name, "mitre": ""}
        for tag in _sigma_tags(synth) or []:
            if tag.startswith("attack."):
                out[det.name].add(tag)

    return {k: sorted(v) for k, v in out.items()}


def build_coverage() -> dict[str, Any]:
    """Return the coverage map.

    Schema::

        {
          "detectors":  {name: {sigma_template_present: bool, tags: [...]}},
          "techniques": {
              "T1059":      {"tactics": ["execution"], "detectors": [...]},
              "T1059.001":  {...},
          },
          "tactics":    {slug: {"label": "...", "technique_ids": [...]}},
          "summary":    {
              "detectors_total": int,
              "detectors_with_template": int,
              "techniques_covered": int,
              "tactics_covered": int,
          },
        }
    """
    from digger.detectors import all_detectors

    tactic_map = _load_tactic_map()

    detector_tags = _detector_static_tags()
    detector_info: dict[str, dict] = {}
    for det in all_detectors():
        tpl_present = False
        try:
            tpl = det.to_sigma_template()
            tpl_present = isinstance(tpl, dict) and bool(tpl)
        except Exception:
            tpl_present = False
        detector_info[det.name] = {
            "sigma_template_present": tpl_present,
            "tags": detector_tags.get(det.name, []),
        }

    # Build per-technique coverage.
    technique_cov: dict[str, dict] = {}
    tactic_cov: dict[str, set[str]] = defaultdict(set)

    for det_name, tags in detector_tags.items():
        # Collect tactics declared explicitly via attack.<tactic> tags.
        det_tactics_explicit = {
            t for t in (_tactic_slug_from_tag(tag) for tag in tags)
            if t is not None
        }
        for tag in tags:
            tid = _technique_from_tag(tag)
            if tid is None:
                continue
            entry = technique_cov.setdefault(tid, {
                "tactics": set(),
                "detectors": set(),
            })
            entry["detectors"].add(det_name)
            # Add tactics from the canonical map.
            mapped = tactic_map.get(tid) or []
            for slug in mapped:
                entry["tactics"].add(slug)
                tactic_cov[slug].add(tid)
            # If the detector listed an explicit tactic but no mapping
            # exists for the technique, attribute to those explicit ones
            # so the heatmap still places the cell.
            if not mapped and det_tactics_explicit:
                for slug in det_tactics_explicit:
                    entry["tactics"].add(slug)
                    tactic_cov[slug].add(tid)

    # Flatten sets to sorted lists for JSON-friendliness.
    techniques_out = {
        tid: {
            "tactics":   sorted(entry["tactics"]),
            "detectors": sorted(entry["detectors"]),
        }
        for tid, entry in technique_cov.items()
    }
    tactics_out = {
        slug: {
            "label":        TACTIC_LABELS.get(slug, slug),
            "technique_ids": sorted(tactic_cov.get(slug, set())),
        }
        for slug in TACTIC_SLUGS
    }

    return {
        "detectors":  detector_info,
        "techniques": techniques_out,
        "tactics":    tactics_out,
        "summary":    {
            "detectors_total": len(detector_info),
            "detectors_with_template": sum(
                1 for d in detector_info.values()
                if d["sigma_template_present"]
            ),
            "techniques_covered": len(techniques_out),
            "tactics_covered": sum(
                1 for slug in TACTIC_SLUGS if tactics_out[slug]["technique_ids"]
            ),
        },
    }


# ---- Tactic map (bundled with live override) ------------------------- #


def _load_tactic_map() -> dict[str, list[str]]:
    """Return ``{technique_id: [tactic-slug, ...]}``.

    Live cache (``digger intel update`` mitre_attack feed) wins when it
    surfaces tactic info; otherwise we use the bundled
    ``digger/rules/attack/tactic_map.yaml``.

    Both sources are reduced to the same shape. Unknown techniques get
    an empty list and are still surfaced in the heatmap, attributed to
    whatever tactic the detector declared.
    """
    # Live: parse from the cached mitre_attack feed if it carries
    # per-technique tactic info. The current feed parser keeps only
    # actors; until we extend it, we go straight to bundled.
    bundled = _load_bundled_tactic_map()
    return bundled


def _load_bundled_tactic_map() -> dict[str, list[str]]:
    """Load the bundled tactic map. Returns {} on failure."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return {}
    path = (
        Path(__file__).parent.parent / "rules" / "attack" / "tactic_map.yaml"
    )
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return {}
    out: dict[str, list[str]] = {}
    for tid, tactics in (data.get("techniques") or {}).items():
        if isinstance(tactics, str):
            tactics = [tactics]
        if not isinstance(tactics, list):
            continue
        out[str(tid).upper()] = [str(t).lower() for t in tactics]
    return out


# ---- Renderers -------------------------------------------------------- #


def render_json(coverage: dict[str, Any]) -> str:
    """Pretty JSON dump, deterministic key order."""
    return json.dumps(coverage, indent=2, sort_keys=True)


def render_text(coverage: dict[str, Any], *, width: int = 100) -> str:
    """Plain ASCII tabulation suitable for stdout / log files.

    Layout:
        Tactic              | #Techniques | Techniques (covering detector)
        ------------------- | ----------- | ----------------------------
        Reconnaissance      | 2           | T1595.001 (recon, exfiltration)
        Defense Evasion     | 9           | T1027 (yara), T1070 (anti_forensics), …
        ...
        SUMMARY: N detectors / M techniques / K of 14 tactics
    """
    lines: list[str] = []
    lines.append("MITRE ATT&CK coverage — derived from detector tags")
    lines.append("=" * min(width, 80))
    header_a, header_b, header_c = "Tactic", "#", "Techniques (covering detectors)"
    lines.append(f"{header_a:<22} | {header_b:>3} | {header_c}")
    lines.append(f"{'-' * 22} | {'-' * 3} | {'-' * max(10, width - 32)}")
    for slug in TACTIC_SLUGS:
        info = coverage["tactics"][slug]
        label = info["label"]
        tids = info["technique_ids"]
        if not tids:
            lines.append(f"{label:<22} | {0:>3} | (uncovered)")
            continue
        # Format each technique with its detectors in parens.
        chunks = []
        for tid in tids:
            dets = coverage["techniques"].get(tid, {}).get("detectors", [])
            chunks.append(f"{tid} ({', '.join(dets) or '-'})")
        wrapped = ", ".join(chunks)
        lines.append(f"{label:<22} | {len(tids):>3} | {wrapped}")
    s = coverage["summary"]
    lines.append("=" * min(width, 80))
    lines.append(
        f"SUMMARY: {s['detectors_total']} detectors "
        f"({s['detectors_with_template']} with Sigma templates) · "
        f"{s['techniques_covered']} techniques covered · "
        f"{s['tactics_covered']} of {len(TACTIC_SLUGS)} tactics with at "
        f"least one technique"
    )
    return "\n".join(lines)


def _density_class(n_detectors: int) -> str:
    if n_detectors >= 3:
        return "cov3"
    if n_detectors == 2:
        return "cov2"
    if n_detectors == 1:
        return "cov1"
    return "cov0"


def render_html(coverage: dict[str, Any], *, title: str = "ATT&CK coverage — digger") -> str:
    """Standalone HTML — no external CSS/JS, single file.

    Layout: 14 tactic columns × N techniques per column. Each cell
    shows the technique ID and its covering detectors. Color encodes
    coverage density (0 / 1 / 2 / 3+ detectors)."""
    by_tactic: dict[str, list[tuple[str, list[str]]]] = {}
    for slug in TACTIC_SLUGS:
        info = coverage["tactics"][slug]
        by_tactic[slug] = [
            (tid, coverage["techniques"].get(tid, {}).get("detectors", []))
            for tid in info["technique_ids"]
        ]

    max_rows = max((len(v) for v in by_tactic.values()), default=0)
    s = coverage["summary"]

    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append("<html lang='en'><head><meta charset='utf-8'>")
    parts.append(f"<title>{html.escape(title)}</title>")
    parts.append("<style>")
    parts.append("""
:root {
  --bg: #0e1116; --fg: #d0d7de; --border: #2a3140;
  --accent: #57c785;
  --cov0: #1c2128; --cov1: #265a40; --cov2: #2ea44f; --cov3: #57c785;
}
body { background: var(--bg); color: var(--fg); font-family: ui-monospace,
       SFMono-Regular, Menlo, monospace; margin: 24px; }
h1 { font-size: 18px; margin: 0 0 4px 0; }
.summary { margin: 0 0 18px 0; color: #9aa4af; font-size: 13px; }
table.matrix { border-collapse: collapse; }
table.matrix th {
  background: #161b22; color: var(--fg); text-align: left; padding: 6px 8px;
  border: 1px solid var(--border); font-size: 12px; font-weight: 600;
  vertical-align: top; min-width: 130px;
}
table.matrix td {
  padding: 4px 8px; border: 1px solid var(--border); font-size: 11px;
  vertical-align: top; line-height: 1.35; min-width: 130px;
}
td.cov0 { background: var(--cov0); color: #5a6371; }
td.cov1 { background: var(--cov1); color: #d0d7de; }
td.cov2 { background: var(--cov2); color: #ffffff; }
td.cov3 { background: var(--cov3); color: #0d1117; }
.tid { font-weight: 700; }
.dets { display: block; margin-top: 2px; font-size: 10px; color: inherit;
        opacity: 0.85; }
.legend { display: inline-block; padding: 2px 8px; border: 1px solid var(--border);
          margin-right: 6px; font-size: 11px; }
.cov0 .swatch, .cov1 .swatch, .cov2 .swatch, .cov3 .swatch { display:inline-block;
   width:10px; height:10px; margin-right:4px; vertical-align: middle; }
""")
    parts.append("</style></head><body>")
    parts.append(f"<h1>{html.escape(title)}</h1>")
    parts.append("<p class='summary'>" +
                 f"{s['detectors_total']} detectors " +
                 f"({s['detectors_with_template']} with class-level Sigma templates) · " +
                 f"{s['techniques_covered']} techniques covered · " +
                 f"{s['tactics_covered']} of {len(TACTIC_SLUGS)} tactics</p>")
    parts.append(
        "<p>"
        "<span class='legend cov0'><span class='swatch' style='background:var(--cov0)'></span>uncovered</span>"
        "<span class='legend cov1'><span class='swatch' style='background:var(--cov1)'></span>1 detector</span>"
        "<span class='legend cov2'><span class='swatch' style='background:var(--cov2)'></span>2 detectors</span>"
        "<span class='legend cov3'><span class='swatch' style='background:var(--cov3)'></span>3+ detectors</span>"
        "</p>"
    )
    parts.append("<table class='matrix'>")
    parts.append("<thead><tr>")
    for slug in TACTIC_SLUGS:
        label = html.escape(TACTIC_LABELS[slug])
        count = len(by_tactic[slug])
        parts.append(f"<th>{label}<br><small>{count} techniques</small></th>")
    parts.append("</tr></thead><tbody>")

    for row in range(max_rows):
        parts.append("<tr>")
        for slug in TACTIC_SLUGS:
            cells = by_tactic[slug]
            if row >= len(cells):
                parts.append("<td class='cov0'>&nbsp;</td>")
                continue
            tid, dets = cells[row]
            cls = _density_class(len(dets))
            det_label = (
                "<span class='dets'>" + html.escape(", ".join(dets)) + "</span>"
                if dets else ""
            )
            parts.append(
                f"<td class='{cls}'><span class='tid'>{html.escape(tid)}</span>"
                f"{det_label}</td>"
            )
        parts.append("</tr>")
    parts.append("</tbody></table>")
    parts.append("</body></html>")
    return "".join(parts)


def write_heatmap(coverage: dict[str, Any], *, fmt: str, out_path: Path) -> Path:
    """Render and write to ``out_path``."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        out_path.write_text(render_json(coverage), encoding="utf-8")
    elif fmt == "text":
        out_path.write_text(render_text(coverage), encoding="utf-8")
    elif fmt == "html":
        out_path.write_text(render_html(coverage), encoding="utf-8")
    else:
        raise ValueError(f"unsupported format: {fmt}")
    return out_path
