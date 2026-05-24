"""Detect provenance anomalies in running-process executables."""

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# Paths that are commonly home to legitimately ad-hoc-signed binaries —
# don't fire on these. (Apple's own first-run apps under /Applications,
# and Xcode developer-installed binaries, are normally team-signed.)
_AD_HOC_BENIGN_PREFIXES = (
    # Anything under /usr/local, /opt/homebrew is third-party; users
    # may genuinely have ad-hoc binaries there but it's worth surfacing.
)


# Apple Cryptex mount roots. Binaries living under these paths are
# Apple-signed at the cryptex layer (SIP / Boot Policy validates the
# whole cryptex image at mount time), but classic per-binary codesign
# treats them as unverifiable because the trust chain can't be walked
# the conventional way. Anything matching one of these path prefixes
# is not a real finding.
_APPLE_CRYPTEX_PREFIXES = (
    "/System/Volumes/Preboot/Cryptexes/",
    "/System/Cryptexes/",
    "/private/var/preboot/Cryptexes/",
)


def _is_apple_cryptex_path(path: str) -> bool:
    return any(path.startswith(p) for p in _APPLE_CRYPTEX_PREFIXES)


class UnsignedBinaryDetector(Detector):
    name = "unsigned_binary"
    description = (
        "Provenance anomalies in running executables: unsigned, ad-hoc-only, "
        "invalid/expired/revoked signatures, and Linux files not owned by "
        "any system package."
    )

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="code_signing"):
            d = art["data"]
            state = d.get("state") or "unknown"
            exe = d.get("exe", "")
            pids = d.get("pids") or []
            signer = d.get("signer")

            if state == "signed":
                continue
            if state == "skipped":
                continue
            if state == "package_owned":
                continue
            # Apple Cryptex-mounted system binaries (under
            # /System/Volumes/Preboot/Cryptexes/ or /System/Cryptexes/)
            # are validated via SIP / Boot Policy at mount time, not via
            # classic codesign per-binary. Running `codesign --verify
            # --deep --strict` against them returns 'invalid' because
            # codesign can't trace the signature chain back to a normal
            # trust root — but Apple's cryptex layer has already
            # validated them. Suppress so we don't alarm on system files.
            if _is_apple_cryptex_path(exe):
                continue

            severity, title, summary, mitre = _shape(state, exe, signer, d)
            yield Finding(
                detector=self.name,
                severity=severity,
                title=title,
                summary=summary,
                artifact_refs=[art["artifact_uuid"]],
                evidence={"exe": exe, "state": state, "signer": signer,
                          "team_id": d.get("team_id"), "details": d.get("details"),
                          "pids": pids[:10]},
                mitre=mitre,
            )


def _shape(state: str, exe: str, signer, d: dict) -> tuple[str, str, str, str]:
    if state == "unsigned":
        return (
            "high",
            f"Unsigned running binary: {exe}",
            (f"Process executable {exe} carries no code signature. "
             f"Modern macOS signs every binary it ships; an unsigned "
             "executable in a system process is a strong indicator of "
             "tampering or sideloaded software."),
            "T1059",
        )
    if state == "ad_hoc":
        return (
            "medium",
            f"Ad-hoc-signed running binary: {exe}",
            (f"Process executable {exe} has only an ad-hoc signature — "
             "no developer identity, no team identifier. Some legitimate "
             "tools first-run with this state, but malware almost "
             "universally is ad-hoc signed."),
            "T1553.002",
        )
    if state == "invalid":
        return (
            "high",
            f"Invalid code signature on running binary: {exe}",
            (f"codesign reports the signature on {exe} as invalid. "
             "Bytes may have been modified after signing — a hallmark of "
             "binary tampering."),
            "T1565.001",
        )
    if state == "expired":
        return (
            "medium",
            f"Expired certificate on running binary: {exe}",
            (f"The code-signing certificate for {exe} has expired. "
             "Often benign for old vendor software but should be confirmed."),
            "T1553.002",
        )
    if state == "revoked":
        return (
            "high",
            f"Revoked certificate on running binary: {exe}",
            (f"The code-signing certificate for {exe} has been revoked. "
             "The publisher considers this binary untrusted."),
            "T1553.002",
        )
    if state == "package_orphan":
        return (
            "low",
            f"Orphan binary (no package owns it): {exe}",
            (f"On a package-managed system no dpkg/rpm package claims "
             f"{exe}. May be a hand-installed tool, a build artifact, "
             "or a dropped binary — worth confirming."),
            "T1564.001",
        )
    return (
        "low",
        f"Unknown signature state ({state}) on running binary: {exe}",
        f"codesign returned a state we couldn't classify cleanly. Details: {d.get('details', '')}",
        "",
    )
