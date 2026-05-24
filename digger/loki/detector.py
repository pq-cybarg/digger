"""LOKI-style detector consuming Neo23x0/signature-base.

Implements the IOC matching layers LOKI is famous for, against digger's
existing artifact set:

  - Filename IOC matches against process exe paths, recent files, open
    files, and any captured filesystem path.
  - Hash IOC matches against running process exe SHA-256 hashes (we also
    compute MD5 / SHA-1 on demand to support those IOC kinds).
  - C2 IOC matches against established network connections and browser
    history.
  - File-anomaly checks (double extensions, RTL filename trickery) on
    recent_files entries.

This complements the existing `yara` and `ioc` detectors — those use
digger's bundled rules + intel-feed cache; this uses the signature-base
corpus when present. Findings cite the original signature-base entry.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector
from digger.loki.signature_base import C2IOC, FilenameIOC, HashIOC, SignatureBase, cached


def _loki_score_to_severity(score: int) -> str:
    """Map signature-base 0-100 score to a digger severity."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def _md5_of_file(path: str) -> str | None:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                buf = f.read(1 << 20)
                if not buf:
                    break
                h.update(buf)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _sha1_of_file(path: str) -> str | None:
    try:
        h = hashlib.sha1()
        with open(path, "rb") as f:
            while True:
                buf = f.read(1 << 20)
                if not buf:
                    break
                h.update(buf)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


# Double-extension and RTL-trickery patterns from LOKI's filename heuristics.
_DOUBLE_EXT = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|rtf|zip)\."
    r"(exe|scr|com|bat|cmd|pif|vbs|js|jse|wsf|hta|ps1|jar|msi|app|dmg|bin)$",
    re.I,
)
# Unicode right-to-left override character (and friends).
_RTL_TRICK = re.compile(r"[‪-‮⁦-⁩]")


class LokiStyleDetector(Detector):
    name = "loki"
    description = (
        "LOKI/THOR-style IOC matching against Neo23x0/signature-base, "
        "plus filename anomaly checks."
    )

    def __init__(self, sb: SignatureBase | None = None):
        self.sb = sb if sb is not None else cached()

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        if not self.sb.is_loaded:
            store.log(
                "info",
                "loki: signature-base not present at "
                f"{self.sb.root} — run `digger loki update` to fetch it",
            )
            return

        # Integrity check — verify the PQC signature on the corpus before
        # using its rules. Strict mode (DIGGER_LOKI_STRICT=1) refuses to
        # run when the snapshot is unsigned or fails verification; default
        # mode logs a warning and continues so existing workflows aren't
        # broken by users who haven't yet run `digger loki sign`.
        from digger.loki.integrity import verify_snapshot
        import os
        ir = verify_snapshot(self.sb.root)
        if ir.signed and ir.verified is False:
            msg = (f"loki: signature-base at {self.sb.root} has a PQC "
                   "signature but it does NOT verify — the corpus has "
                   "been modified since signing. Refusing to use it.")
            store.log("error", msg)
            yield Finding(
                detector=self.name, severity="critical",
                title="signature-base corpus integrity violation",
                summary=msg,
                artifact_refs=[],
                evidence={"corpus_root": str(self.sb.root), **ir.to_dict()},
                mitre="T1554",
            )
            return
        if not ir.signed:
            note = (f"loki: signature-base at {self.sb.root} is unsigned. "
                    "Run `digger loki sign --key <pqc-secret>` to bind a "
                    "PQC signature to the current corpus for future "
                    "integrity checks.")
            if os.environ.get("DIGGER_LOKI_STRICT", "").lower() in {"1", "true", "yes"}:
                store.log("error", note + " (strict mode — refusing to run)")
                return
            store.log("warn", note)

        # Build indexes
        hash_by_value = {h.value: h for h in self.sb.hash_iocs}
        false_positives = self.sb.false_positive_hashes

        # ---- hash matches over process executables ---- #
        for art in store.iter_artifacts(collector="processes"):
            data = art["data"]
            exe = data.get("exe")
            sha256 = (data.get("exe_sha256") or "").lower()
            if not sha256 or not re.match(r"^[a-f0-9]{64}$", sha256):
                # exe_sha256 might be a "skipped-large-file" marker
                sha256 = ""
            if sha256 and sha256 not in false_positives:
                hit = hash_by_value.get(sha256)
                if hit:
                    yield self._hash_finding(art, hit, sha256, "sha256")
                    continue
            # Try MD5 / SHA-1 if any of those are in the IOC set
            if exe:
                md5_needed = any(h.kind == "md5" for h in self.sb.hash_iocs)
                sha1_needed = any(h.kind == "sha1" for h in self.sb.hash_iocs)
                if md5_needed:
                    m = _md5_of_file(exe)
                    if m and m in hash_by_value and m not in false_positives:
                        yield self._hash_finding(art, hash_by_value[m], m, "md5")
                        continue
                if sha1_needed:
                    s = _sha1_of_file(exe)
                    if s and s in hash_by_value and s not in false_positives:
                        yield self._hash_finding(art, hash_by_value[s], s, "sha1")
                        continue

        # ---- filename IOC matches ---- #
        for art in store.iter_artifacts(collector="processes"):
            exe = art["data"].get("exe")
            if exe:
                for fioc in self.sb.filename_iocs:
                    if fioc.compiled and fioc.compiled.search(exe):
                        yield self._filename_finding(art, fioc, exe, "process_exe")
                        break
        for art in store.iter_artifacts(collector="recent_files"):
            for entry in art["data"].get("entries") or []:
                p = entry.get("path") if isinstance(entry, dict) else None
                if not p:
                    continue
                for fioc in self.sb.filename_iocs:
                    if fioc.compiled and fioc.compiled.search(p):
                        yield self._filename_finding(art, fioc, p, "recent_file")
                        break

        # ---- C2 IOC matches ---- #
        for ioc in self.sb.c2_iocs:
            if ioc.kind == "ipv4":
                for art in store.iter_artifacts(collector="network"):
                    raddr = art["data"].get("raddr")
                    if raddr and raddr[0] == ioc.value:
                        yield self._c2_finding(art, ioc, ioc.value)
                        break
            elif ioc.kind == "domain":
                # Match against browser history URLs
                for art in store.iter_artifacts(collector="browsers"):
                    found = False
                    for e in art["data"].get("entries") or []:
                        url = (e.get("url") if isinstance(e, dict) else "") or ""
                        if ioc.value in url.lower():
                            yield self._c2_finding(art, ioc, url)
                            found = True
                            break
                    if found:
                        break
            elif ioc.kind == "url":
                for art in store.iter_artifacts(collector="browsers"):
                    for e in art["data"].get("entries") or []:
                        url = (e.get("url") if isinstance(e, dict) else "") or ""
                        if ioc.value in url.lower():
                            yield self._c2_finding(art, ioc, url)
                            break

        # ---- filename anomalies (double extensions, RTL trickery) ---- #
        for art in store.iter_artifacts(collector="recent_files"):
            for entry in art["data"].get("entries") or []:
                p = entry.get("path") if isinstance(entry, dict) else None
                if not p:
                    continue
                if _DOUBLE_EXT.search(p):
                    yield Finding(
                        detector=self.name, severity="high",
                        title=f"Double-extension file: {p}",
                        summary=(
                            "File has a content-extension followed by an executable "
                            "extension (e.g. invoice.pdf.exe). Classic dropper "
                            "masquerade pattern (LOKI rule)."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"path": p, "kind": "double_extension"},
                        mitre="T1036.007",
                    )
                if _RTL_TRICK.search(p):
                    yield Finding(
                        detector=self.name, severity="high",
                        title=f"Right-to-Left override in filename: {p!r}",
                        summary=(
                            "Filename contains a U+202E (or related) Unicode "
                            "directional-override codepoint. Used to disguise "
                            "executables as documents (e.g. \"resume[U+202E]fdp.exe\" "
                            "rendered as \"resumeexe.pdf\")."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"path": p, "kind": "rtl_override"},
                        mitre="T1036.002",
                    )

    # ---- helpers ---- #

    def _hash_finding(self, art, ioc: HashIOC, value: str, kind: str) -> Finding:
        return Finding(
            detector=self.name,
            severity=_loki_score_to_severity(ioc.score),
            title=f"LOKI {kind.upper()} hash IOC: {ioc.description or value}",
            summary=(
                f"Running process executable {art['data'].get('name')} (pid "
                f"{art['data'].get('pid')}) has {kind.upper()} hash {value} which "
                f"matches signature-base entry: \"{ioc.description}\" "
                f"(LOKI score {ioc.score})."
            ),
            artifact_refs=[art["artifact_uuid"]],
            evidence={
                "ioc_kind": kind, "ioc_value": value,
                "description": ioc.description, "loki_score": ioc.score,
                "process": art["data"],
            },
            mitre="T1204.002",
        )

    def _filename_finding(self, art, ioc: FilenameIOC, path: str, where: str) -> Finding:
        return Finding(
            detector=self.name,
            severity=_loki_score_to_severity(ioc.score),
            title=f"LOKI filename IOC: {ioc.description or ioc.regex}",
            summary=(
                f"Path {path} matches signature-base filename IOC regex "
                f"`{ioc.regex}` (\"{ioc.description}\", LOKI score {ioc.score}). "
                f"Source: {where}."
            ),
            artifact_refs=[art["artifact_uuid"]],
            evidence={
                "regex": ioc.regex, "description": ioc.description,
                "loki_score": ioc.score, "path": path, "where": where,
            },
            mitre="T1036",
        )

    def _c2_finding(self, art, ioc: C2IOC, observed: str) -> Finding:
        return Finding(
            detector=self.name,
            severity=_loki_score_to_severity(ioc.score),
            title=f"LOKI C2 IOC ({ioc.kind}): {ioc.value}",
            summary=(
                f"Observed {ioc.kind} `{observed}` matches signature-base C2 "
                f"indicator \"{ioc.description}\" (LOKI score {ioc.score})."
            ),
            artifact_refs=[art["artifact_uuid"]],
            evidence={
                "ioc_kind": ioc.kind, "ioc_value": ioc.value,
                "observed": observed, "description": ioc.description,
                "loki_score": ioc.score,
            },
            mitre="T1071",
        )
