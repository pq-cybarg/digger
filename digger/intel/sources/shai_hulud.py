"""Shai-Hulud npm-worm IOC feed parser.

Pulls the community-maintained Aikido `shai-hulud-iocs` corpus (or a
mirror set via ``$DIGGER_SHAI_HULUD_URL``) and normalizes it into the
schema that :class:`digger.detectors.shai_hulud.ShaiHuludDetector`
consumes:

  - compromised_packages    list[str]   "pkg@ver" or "pkg@*"
  - worm_unambiguous_markers list[str]  strings that are dispositive on a single hit
  - worm_suggestive_markers  list[str]  strings that need co-occurrence
  - worm_webhook_patterns    list[str]  regex patterns for exfil URLs
  - worm_workflow_filename   str        literal workflow filename the worm creates
  - worm_artifact_repos      list[str]  repo names the worm publishes

The Aikido upstream JSON uses a few field-name variants over time; we
accept all of them. Anything we don't recognize is preserved under
``raw`` so future schema changes don't lose data.
"""

from __future__ import annotations

import json


# Aikido field-name candidates for each tier we care about. Tried in order.
_PACKAGE_FIELDS = (
    "compromised_packages", "compromised", "packages",
    "malicious_packages",
)
_UNAMBIGUOUS_FIELDS = (
    "worm_unambiguous_markers",
    "unambiguous_markers",
    "worm_strong_markers",
    "bundle_marker_strings",
)
_SUGGESTIVE_FIELDS = (
    "worm_suggestive_markers",
    "suggestive_markers",
    "weak_markers",
)
_WEBHOOK_FIELDS = (
    "worm_webhook_patterns",
    "webhook_endpoints",
    "webhook_patterns",
    "exfil_urls",
)
_WORKFLOW_FILENAME_FIELDS = (
    "worm_workflow_filename",
    "worm_workflow_filenames",
    "workflow_filename",
)
_REPO_FIELDS = (
    "worm_artifact_repos",
    "self_replicating_repo_names",
    "artifact_repos",
)


def _first_list(d: dict, fields: tuple[str, ...]) -> list:
    """First key in `fields` whose value is a non-empty list (or [])."""
    for f in fields:
        v = d.get(f)
        if isinstance(v, list):
            return v
        # Aikido sometimes nests inside "data" / "iocs"
    return []


def _first_str(d: dict, fields: tuple[str, ...]) -> str | None:
    for f in fields:
        v = d.get(f)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, list) and v and isinstance(v[0], str):
            return v[0].strip()
    return None


def _normalize_package(entry) -> str | None:
    """Each entry may be 'pkg@ver', or {name, version}, or {package, version}."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        name = entry.get("name") or entry.get("package")
        ver = entry.get("version")
        if not name:
            return None
        return f"{name}@{ver}" if ver else f"{name}@*"
    return None


def parse_iocs(raw_json: bytes | str) -> dict:
    """Parse a fetched IOCs JSON blob → normalized dict."""
    if isinstance(raw_json, (bytes, bytearray)):
        data = json.loads(raw_json)
    elif isinstance(raw_json, str):
        data = json.loads(raw_json)
    else:
        data = raw_json or {}

    # Accept several top-level shapes
    if isinstance(data, list):
        data = {"compromised_packages": data}
    elif not isinstance(data, dict):
        data = {}

    # Some hosts wrap under "iocs" or "data"
    for nest in ("iocs", "data"):
        if isinstance(data.get(nest), dict):
            inner = data[nest]
            # promote inner keys (without overwriting existing top-level)
            for k, v in inner.items():
                data.setdefault(k, v)

    packages = [
        _normalize_package(e)
        for e in _first_list(data, _PACKAGE_FIELDS)
    ]
    packages = [p for p in packages if p]

    return {
        "source": "aikido-shai-hulud",
        "raw": data,   # preserved for future fields we don't yet parse
        # Normalized shape the detector reads:
        "compromised_packages": packages,
        "worm_unambiguous_markers": [
            m for m in _first_list(data, _UNAMBIGUOUS_FIELDS) if isinstance(m, str)
        ],
        "worm_suggestive_markers": [
            m for m in _first_list(data, _SUGGESTIVE_FIELDS) if isinstance(m, str)
        ],
        "worm_webhook_patterns": [
            m for m in _first_list(data, _WEBHOOK_FIELDS) if isinstance(m, str)
        ],
        "worm_workflow_filename": _first_str(data, _WORKFLOW_FILENAME_FIELDS),
        "worm_artifact_repos": [
            m for m in _first_list(data, _REPO_FIELDS) if isinstance(m, str)
        ],
    }
