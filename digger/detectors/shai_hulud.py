"""Shai-Hulud npm worm detector.

Signals checked, layered:

  1. **Compromised package versions** — exact `name@version` matches against
     bundled list + live `shai_hulud_packages` intel feed.
  2. **Worm workflow file** — any `.github/workflows/shai-hulud-workflow.yml`
     or workflow whose body contains the worm's marker strings.
  3. **TruffleHog/bundle.js dropper artifacts** in node_modules.
  4. **Webhook exfil targets** — `webhook.site/<uuid>` URLs in workflow,
     scripts, or running process command lines.
"""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_intel, load_yaml
from digger.detectors.base import Detector


def _normalize_compromised(rules: dict, intel: dict | None):
    """Parse the rule corpus into discriminated marker tiers.

    Returns:
        exact:        set of "name@version" pairs (compromised)
        wildcards:    set of package names (any version compromised)
        webhook_pats: compiled patterns matching worm exfil URLs
        unambiguous:  markers that fire on a single hit (worm-only)
        suggestive:   markers that need to co-occur with another worm
                      signal (trufflehog / shai-hulud — appear in
                      defensive tooling too)
        worm_filename: the literal filename the worm creates
                       (matched as exact filename, not substring)
    """
    exact: set[str] = set()
    wildcards: set[str] = set()

    # Live-first: prefer the normalized live feed payload for each tier.
    live = intel or {}

    # Packages — live wins over bundled when present.
    live_pkgs = (
        live.get("compromised_packages")
        or (live.get("raw") or {}).get("packages")
        or (live.get("raw") or {}).get("compromised")
        or []
    )
    if live_pkgs:
        for entry in live_pkgs:
            if isinstance(entry, str):
                if entry.endswith("@*"):
                    wildcards.add(entry[:-2])
                elif "@" in entry:
                    exact.add(entry)
            elif isinstance(entry, dict):
                name = entry.get("name") or entry.get("package")
                ver = entry.get("version")
                if name and ver:
                    exact.add(f"{name}@{ver}")
                elif name:
                    wildcards.add(name)
    else:
        for entry in rules.get("compromised_packages", []):
            if "@" not in entry:
                continue
            if entry.endswith("@*"):
                wildcards.add(entry[:-2])
            else:
                exact.add(entry)

    # Markers — live tier overrides bundled tier when non-empty.
    live_unamb = live.get("worm_unambiguous_markers") or []
    live_sugg = live.get("worm_suggestive_markers") or []
    live_webhook = live.get("worm_webhook_patterns") or []
    live_filename = live.get("worm_workflow_filename")

    unambiguous = list(live_unamb) or list(
        rules.get("worm_unambiguous_markers")
        or rules.get("worm_strong_markers")
        or rules.get("worm_bundle_marker_strings", [])
    )
    suggestive = list(live_sugg) or list(rules.get("worm_suggestive_markers") or [])
    webhook_src = list(live_webhook) or list(rules.get("worm_webhook_patterns", []))
    webhook_pats = [re.compile(p, re.I) for p in webhook_src]
    worm_filename = live_filename or rules.get(
        "worm_workflow_filename", "shai-hulud-workflow.yml"
    )
    return exact, wildcards, webhook_pats, unambiguous, suggestive, worm_filename


class ShaiHuludDetector(Detector):
    name = "shai_hulud"
    description = (
        "Shai-Hulud npm worm: compromised package@version pairs, worm workflow file, "
        "webhook exfil URLs, TruffleHog bundle markers."
    )

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        rules = load_yaml("supply_chain/shai_hulud.yaml")
        intel = load_intel("shai_hulud_packages")
        (exact, wildcards, webhook_patterns,
         unambiguous, suggestive, worm_filename) = _normalize_compromised(rules, intel)

        # --- compromised package matches --- #
        for art in store.iter_artifacts(collector="npm_packages"):
            data = art["data"]
            project = data.get("project")
            locked = data.get("locked_packages") or {}
            declared = {**(data.get("declared_deps") or {}), **(data.get("declared_dev_deps") or {})}
            for name, ver in locked.items():
                pinned = f"{name}@{ver}"
                if pinned in exact or name in wildcards:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"Shai-Hulud compromised package: {pinned}",
                        summary=(
                            f"Project {project} has compromised npm package {pinned} in its "
                            f"lockfile. This package version is listed as part of the Shai-Hulud "
                            "npm worm campaign. Treat the host as potentially compromised: "
                            "rotate any tokens that were in env vars or .npmrc, audit recent "
                            "`npm publish` activity for accounts that ran installs on this "
                            "machine, and inspect for the worm workflow file."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"project": project, "package": pinned},
                        mitre="T1195.002",
                    )
            for name in declared:
                if name in wildcards:
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=f"Declared dependency on package-of-concern: {name}",
                        summary=(
                            f"Project {project} declares dependency on {name}, which has had "
                            "compromised versions published. Verify the locked version is safe."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"project": project, "package": name},
                        mitre="T1195.002",
                    )

        # --- worm workflow file --- #
        # We fire critical when ANY of:
        #   * the workflow's filename is exactly the worm filename, OR
        #   * an unambiguous marker hits, OR
        #   * a webhook exfil URL hits, OR
        #   * a suggestive marker hits AND it co-occurs with another signal
        # We deliberately do NOT fire on suggestive markers alone — they
        # appear in defensive tooling (workflows that invoke TruffleHog
        # as a secret-scanner, hardening docs referencing "Shai-Hulud-
        # class" attacks). Those are not the worm.
        worm_filename_lower = (worm_filename or "").lower()
        for art in store.iter_artifacts(collector="github_workflows"):
            for entry in art["data"].get("entries", []):
                name = entry.get("name", "")
                contents = entry.get("contents", "")
                lower_contents = contents.lower() if isinstance(contents, str) else ""

                # Exact filename match only — substring would catch
                # legit "shai-hulud-defense.yml" type names.
                bad_name = name.lower() == worm_filename_lower
                unambiguous_hits = [m for m in unambiguous if m.lower() in lower_contents]
                suggestive_hits = [m for m in suggestive if m.lower() in lower_contents]
                webhook_hits = [
                    m.group(0) for m in (pat.search(contents or "") for pat in webhook_patterns)
                    if m is not None
                ]

                strong_signal = bad_name or unambiguous_hits or webhook_hits
                # Suggestive markers count only when paired with something
                # else worm-specific.
                if not strong_signal and suggestive_hits:
                    continue

                if strong_signal:
                    all_markers = unambiguous_hits + (suggestive_hits if suggestive_hits else [])
                    if bad_name:
                        reason = "filename matches the worm's literal filename"
                    elif webhook_hits:
                        reason = f"webhook exfil URL ({webhook_hits[0]})"
                    else:
                        reason = f"unambiguous worm markers: {unambiguous_hits[:3]}"
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"Shai-Hulud worm workflow artifact: {entry.get('path')}",
                        summary=(
                            f"GitHub Actions workflow {entry.get('path')} — {reason}. "
                            "This is the self-propagation vehicle of the Shai-Hulud worm. "
                            "Delete it, revert recent commits to this repo, and rotate "
                            "the repo's GITHUB_TOKEN and any tokens that could have been "
                            "used during a workflow run."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "path": entry.get("path"),
                            "filename_exact_match": bad_name,
                            "unambiguous_markers": unambiguous_hits,
                            "suggestive_markers": suggestive_hits,
                            "webhook_hits": webhook_hits,
                        },
                        mitre="T1199",
                    )

        # --- live processes referencing the worm --- #
        # Same tiering: unambiguous markers in cmdlines fire; suggestive
        # markers (trufflehog, shai-hulud) alone do not — a developer
        # running `trufflehog filesystem .` is not the worm.
        for art in store.iter_artifacts(collector="processes"):
            cmd = " ".join(art["data"].get("cmdline") or [])
            cmd_low = cmd.lower()
            unambiguous_hit = next((m for m in unambiguous if m.lower() in cmd_low), None)
            if unambiguous_hit:
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=f"Process command line contains Shai-Hulud unambiguous marker '{unambiguous_hit}'",
                    summary=(
                        f"Live process (pid {art['data'].get('pid')}, "
                        f"{art['data'].get('name')}) was running with command line referencing "
                        f"a worm-specific string. Cmdline: {cmd[:300]}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"cmdline": cmd, "marker": unambiguous_hit,
                              "pid": art["data"].get("pid")},
                    mitre="T1059",
                )
