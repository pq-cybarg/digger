"""Supply-chain detector: malicious packages and KEV-affected installed software."""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_intel, load_yaml
from digger.detectors.base import Detector


def _expand_pinned(entries: list[str]) -> tuple[set[str], set[str]]:
    exact: set[str] = set()
    wildcards: set[str] = set()
    for entry in entries or []:
        if "@" not in entry:
            wildcards.add(entry)
            continue
        if entry.endswith("@*"):
            wildcards.add(entry[:-2])
        else:
            exact.add(entry)
    return exact, wildcards


# Reverse-DNS prefix patterns for known publishers. Used by the KEV
# matcher to verify the installed app actually comes from the same
# vendor the KEV entry names. This is the strongest signal we have —
# bundle IDs are issued by the publisher's own development cert and
# faking them requires signing-cert compromise.
_VENDOR_BUNDLE_PREFIXES: dict[str, tuple[str, ...]] = {
    "microsoft":   ("com.microsoft.",),
    "apple":       ("com.apple.",),
    "google":      ("com.google.", "com.google.chrome", "com.google.chromeremotedesktop"),
    "mozilla":     ("org.mozilla.",),
    "apache":      ("org.apache.",),
    "the apache software foundation": ("org.apache.",),
    "oracle":      ("com.oracle.", "com.oracle.virtualbox", "com.sun."),
    "adobe":       ("com.adobe.",),
    "atlassian":   ("com.atlassian.",),
    "jetbrains":   ("com.jetbrains.",),
    "ledger":      ("com.ledgerwallet.", "com.ledger."),
    "ivanti":      ("com.ivanti.", "com.pulsesecure."),
    "palo alto":   ("com.paloaltonetworks.",),
    "cisco":       ("com.cisco.",),
    "vmware":      ("com.vmware.",),
}


def _word_boundary_match(needle: str, haystack: str) -> bool:
    """True iff `needle` appears as a whole word inside `haystack`,
    case-insensitive. ``"office"`` matches ``"Microsoft Office"`` but
    NOT ``"OpenOffice.app"`` — they're a single concatenated word."""
    if not needle or not haystack:
        return False
    return re.search(r"\b" + re.escape(needle) + r"\b", haystack, re.I) is not None


def _kev_matches_installed(kev_entry: dict, inst: dict) -> bool:
    """The hardened KEV matcher.

    Tightens the v1 matcher in two ways:

      1. If the installed app has a bundle_id, the KEV vendor must
         match the reverse-DNS prefix corresponding to that vendor.
         e.g. KEV vendor='Microsoft' requires bundle_id 'com.microsoft.*'.
         An Apache OpenOffice bundle (org.apache.openoffice.*) does
         NOT match a Microsoft Office CVE — even though "Office" is a
         substring of "OpenOffice".

      2. If no bundle_id, fall back to requiring BOTH the KEV vendor
         token AND the KEV product token to word-boundary-match the
         installed display name. The product token "Office" no longer
         matches "OpenOffice" because OpenOffice is a single word.
    """
    product = (kev_entry.get("product") or "").strip()
    vendor  = (kev_entry.get("vendor") or "").strip()
    if not product or product == "*":
        return False

    bundle_id = (inst.get("bundle_id") or "").lower()

    # Step 1: bundle_id is authoritative when present.
    if bundle_id:
        prefixes = _VENDOR_BUNDLE_PREFIXES.get(vendor.lower())
        if prefixes is None:
            # We don't know this vendor's bundle convention; fall through
            # to name-based matching rather than blanket-accept.
            pass
        else:
            if not any(bundle_id.startswith(p) for p in prefixes):
                return False
            # vendor matched; now check product also makes sense in the
            # installed name (or bundle_id).
            name = inst.get("name") or ""
            return (_word_boundary_match(product, name)
                    or _word_boundary_match(product, bundle_id))

    # Step 2: no bundle_id — require both tokens, both word-boundary.
    name = inst.get("name") or ""
    if not _word_boundary_match(product, name):
        return False
    # Vendor token — if KEV vendor is multi-word, require any token to match.
    vendor_tokens = [t for t in re.split(r"\s+", vendor) if t]
    if vendor_tokens and not any(_word_boundary_match(t, name) for t in vendor_tokens):
        return False
    return True


class SupplyChainDetector(Detector):
    name = "supply_chain"
    description = (
        "Malicious package detection (npm/pypi/gems) plus CISA KEV matching against "
        "installed software inventory."
    )

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # Live OpenSSF malicious-packages feed is authoritative (OSV format,
        # covers npm/pypi/RubyGems/Maven/etc., refreshed every few hours).
        # Bundled snapshot is a *fallback only* — it carries a small curated
        # seed for the air-gap-default first-run case before the user has
        # done their first `digger intel update`.
        npm_exact: set[str] = set()
        npm_wild: set[str] = set()
        pypi_exact: set[str] = set()
        pypi_wild: set[str] = set()

        openssf = load_intel("openssf_malicious_packages") or {}
        live_entries = (openssf.get("raw") or {}).get("entries", []) or []
        for adv in live_entries:
            try:
                affected = adv.get("affected", [])
                for a in affected:
                    pkg = a.get("package") or {}
                    eco = (pkg.get("ecosystem") or "").lower()
                    name = pkg.get("name") or ""
                    versions = a.get("versions") or []
                    for v in versions:
                        spec = f"{name}@{v}"
                        if eco == "npm":
                            npm_exact.add(spec)
                        elif eco == "pypi":
                            pypi_exact.add(spec)
            except Exception:
                continue

        if not live_entries:
            # Fallback: bundled curated seed
            rules = load_yaml("supply_chain/malicious_packages.yaml") or {}
            npm_exact_b, npm_wild_b = _expand_pinned(rules.get("npm", []))
            pypi_exact_b, pypi_wild_b = _expand_pinned(rules.get("pypi", []))
            npm_exact |= npm_exact_b
            npm_wild  |= npm_wild_b
            pypi_exact |= pypi_exact_b
            pypi_wild  |= pypi_wild_b

        # npm projects
        for art in store.iter_artifacts(collector="npm_packages"):
            data = art["data"]
            locked = data.get("locked_packages") or {}
            for name, ver in locked.items():
                pinned = f"{name}@{ver}"
                if pinned in npm_exact or name in npm_wild:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"Malicious npm package present: {pinned}",
                        summary=(
                            f"Project {data.get('project')} has locked dependency {pinned} "
                            "which is on the malicious-packages list. Remove, audit history, "
                            "and rotate any credentials used during install."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"project": data.get("project"), "package": pinned},
                        mitre="T1195.001",
                    )

        # python environments
        for art in store.iter_artifacts(collector="python_packages"):
            for entry in art["data"].get("entries") or []:
                name = (entry.get("name") or "").lower()
                ver = entry.get("version") or ""
                pinned = f"{name}@{ver}"
                if pinned in pypi_exact or name in pypi_wild:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"Malicious PyPI package installed: {pinned}",
                        summary=(
                            f"Python env {art['data'].get('interpreter')} has malicious "
                            f"package {pinned} installed. Uninstall and rotate."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"package": pinned, "interpreter": art["data"].get("interpreter")},
                        mitre="T1195.001",
                    )

        # CISA KEV — match installed software against KEV entries.
        # The naive substring match in v1 turned "OpenOffice" into a hit
        # for every "Microsoft Office" CVE because "Office" is a
        # substring of both. The new matcher:
        #   1. Uses bundle_id reverse-DNS for vendor identity (the
        #      strongest available signal: org.mozilla.firefox vs
        #      org.apache.openoffice vs com.microsoft.* are bright lines).
        #   2. Falls back to requiring BOTH the KEV vendor token AND
        #      the KEV product token to word-boundary-match the
        #      installed name (substring of a longer word doesn't count).
        kev = load_intel("cisa_kev") or load_yaml("supply_chain/kev_snapshot.yaml")
        kev_entries = kev.get("entries", [])
        installed = []
        for art in store.iter_artifacts(collector="installed_software"):
            for e in art["data"].get("entries") or []:
                if isinstance(e, dict):
                    name      = e.get("DisplayName") or e.get("name") or ""
                    ver       = e.get("DisplayVersion") or e.get("version") or ""
                    bundle_id = e.get("bundle_id") or e.get("BundleIdentifier") or ""
                else:
                    name, ver, bundle_id = str(e), "", ""
                if name:
                    installed.append({
                        "name": name, "version": ver,
                        "bundle_id": bundle_id,
                        "artifact_uuid": art["artifact_uuid"],
                    })

        for kev_entry in kev_entries:
            product = (kev_entry.get("product") or "").strip()
            vendor  = (kev_entry.get("vendor") or "").strip()
            if not product or product == "*":
                continue
            for inst in installed:
                if _kev_matches_installed(kev_entry, inst):
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=f"KEV: {kev_entry.get('cve')} affects installed {inst['name']} {inst['version']}",
                        summary=(
                            f"Installed software '{inst['name']}' (version '{inst['version']}', "
                            f"bundle_id '{inst.get('bundle_id') or '—'}') matches CISA KEV entry "
                            f"{kev_entry.get('cve')} ({kev_entry.get('summary')}). "
                            "Verify whether your installed version is in the affected range; "
                            "CISA KEV entries are actively exploited."
                        ),
                        artifact_refs=[inst["artifact_uuid"]],
                        evidence={"installed": inst, "kev": kev_entry},
                        mitre="T1190",
                    )
