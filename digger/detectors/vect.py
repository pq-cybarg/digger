"""VECT 2.0 ransomware-by-design / wiper-by-accident detector.

Disclosed by Check Point Research in April 2026 along with a fatal
nonce-storage bug in the ChaCha20-IETF encryptor: files larger than
128 KB have 3 of 4 nonces permanently discarded, so 75% of any
non-trivial file is wiped even when the correct decryption key is
used. Effectively a wiper for every meaningful enterprise file (VM
disks, databases, documents, backups).

Cross-platform: Windows / Linux / ESXi. RaaS group partnered with
TeamPCP (the Mini Shai-Hulud operator).

Detection layers
----------------

V1  Published SHA-256 IOCs (6 binaries across the three platforms)
    matched against process exe hashes + the files table.
    Critical, T1486.

V2  Ransom-note filename ``!!!READ_ME!!!.txt`` in any recent-files
    artifact. Critical, T1486.

V3  ``.vect`` extension on any recent-files entry — mass-rename
    footprint. Single hit is critical; the impact detector's
    mass_rename heuristic will also fire when ≥50 such files
    accumulate.

V4  ESXi/Linux ransom-note paths written: /etc/motd / /etc/issue
    / /etc/profile.d/vector_notice.sh.

V5  Distinctive cmdline flags — ``--force-safemode``,
    ``--no-stealth`` (Windows), ``--no-kill-vms``, ``--spread``
    (Linux/ESXi). Single hit is critical when paired with the
    expected binary name; otherwise high.

V6  C2 contact: Tor onion ``vectordntlcrlm...``  or the Qtox
    backup ID in any cmdline / DNS / browser artifact.

Every finding ships the destructive_warning ("don't pay — files
> 128 KB are wiped regardless") in evidence.

MITRE: T1486 (Data Encrypted for Impact), T1485 (Data Destruction
— because the nonce bug makes it functionally a wiper), T1489
(Service Stop — VM and DB service kill).
"""

# live-first-ok: VECT IOCs live on Check Point's vendor blog. No
# upstream OSV/STIX feed for the per-binary list. Bundled YAML is
# authoritative; refresh when CP publishes a new variant.

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_yaml
from digger.detectors.base import Detector


def _basename(path: str) -> str:
    if not path:
        return ""
    if "/" in path:
        path = path.rsplit("/", 1)[1]
    if "\\" in path:
        path = path.rsplit("\\", 1)[1]
    return path


def _cmdline_str(cmdline) -> str:
    if isinstance(cmdline, list):
        return " ".join(str(c) for c in cmdline if c)
    return cmdline or ""


def _ext_lower(path: str) -> str:
    name = _basename(path)
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[1].lower()


class VectDetector(Detector):
    name = "vect"
    description = (
        "VECT 2.0 ransomware-by-design / wiper-by-accident. Cross-"
        "platform Win/Linux/ESXi. ChaCha20-IETF with a critical "
        "nonce-storage bug — files > 128 KB are unrecoverable even "
        "with payment. Detects via published SHA-256 IOCs, "
        "ransom-note filename, .vect extension, ESXi/Linux ransom-"
        "note drop paths, distinctive cmdline flags, and Tor C2."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "VECT 2.0 ransomware (wiper-by-accident; do-not-pay)",
            "id": "digger-vect-template",
            "description": (
                "Detects VECT 2.0 by any of: published SHA-256 hash "
                "of a VECT binary; ransom-note filename "
                "!!!READ_ME!!!.txt; .vect file extension on disk; "
                "ESXi/Linux ransom-note drop paths "
                "(/etc/motd|issue|issue.net|profile.d/"
                "vector_notice.sh); distinctive cmdline flags "
                "(--force-safemode, --no-stealth, --no-kill-vms, "
                "--spread); Tor onion "
                "vectordntlcrlm... in cmdline or DNS."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_cmdline_flags": {
                    "CommandLine|contains": [
                        "--force-safemode",
                        "--no-stealth",
                        "--no-kill-vms",
                    ],
                },
                "selection_tor_c2": {
                    "CommandLine|contains":
                        "vectordntlcrlmfkcm4alni734tbcrnd5lk44v6sp4lqal6noqrgnbyd",
                },
                "selection_ransom_note_file": {
                    "TargetFilename|endswith": "/!!!READ_ME!!!.txt",
                },
                "selection_vect_extension": {
                    "TargetFilename|endswith": ".vect",
                },
                "condition": "1 of selection_*",
            },
            "level": "critical",
            "tags": [
                "attack.t1486",
                "attack.t1485",
                "attack.t1489",
                "attack.impact",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        rules = load_yaml("exploits/vect.yaml") or {}
        if not rules:
            return

        campaign = rules.get("campaign") or "VECT 2.0"
        references = rules.get("references") or []
        destructive_warning = rules.get("destructive_warning", "")
        mitigation = rules.get("mitigation", "")

        hashes = rules.get("hashes") or []
        sha256_iocs = {h["sha256"].lower(): h for h in hashes
                       if isinstance(h, dict) and h.get("sha256")}

        ransom_notes = {n.lower() for n in
                        (rules.get("ransom_note_filenames") or [])}
        ext = (rules.get("encrypted_file_extension") or "").lower()
        drop_paths = [p.lower() for p in
                       (rules.get("linux_esxi_drop_paths") or [])]

        c2 = rules.get("c2") or {}
        tor_prefix = (c2.get("tor_onion_prefix") or "").lower()
        qtox_id = (c2.get("qtox_backup_id") or "").lower()

        flags = rules.get("cmdline_flags") or {}
        win_flags = list(flags.get("windows_distinctive") or [])
        linux_flags = list(flags.get("linux_distinctive") or [])
        all_flags = win_flags + linux_flags

        common_response = (
            "VECT 2.0 is ransomware-by-design with a fatal encryption "
            "bug making it a wiper for files > 128 KB. DO NOT PAY — "
            "the > 128 KB file population is unrecoverable regardless "
            "of key delivery. Isolate at the switch (not the host — "
            "the encryptor accelerates on connectivity loss), preserve "
            "a memory image before reboot, then restore from backups "
            f"taken before infection. Campaign: {campaign}. Disclosed "
            "by Check Point Research."
        )

        # ---- V1 hash IOCs ---- #

        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            hv = (d.get("exe_sha256") or "").lower()
            if hv and hv in sha256_iocs:
                ioc = sha256_iocs[hv]
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=(
                        f"VECT 2.0 binary running: SHA-256 match "
                        f"({ioc['platform']}) in pid {d.get('pid')}"
                    ),
                    summary=(
                        f"Process pid {d.get('pid')} ({d.get('name')}, "
                        f"exe {d.get('exe')}) matches the published "
                        f"VECT 2.0 {ioc['platform']} binary. "
                        f"{common_response}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "binary_hash",
                        "campaign": campaign,
                        "platform": ioc["platform"],
                        "sha256": hv,
                        "pid": d.get("pid"),
                        "name": d.get("name"),
                        "destructive_warning": destructive_warning,
                        "mitigation_commands": mitigation,
                        "references": references,
                    },
                    mitre="T1486",
                )

        for art in store.iter_artifacts(category="filesystem"):
            d = art["data"] or {}
            entries = d.get("entries") or ([d] if d.get("path") else [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                hv = (entry.get("sha256") or "").lower()
                if hv and hv in sha256_iocs:
                    ioc = sha256_iocs[hv]
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"VECT 2.0 binary on disk: "
                            f"{entry.get('path')} ({ioc['platform']})"
                        ),
                        summary=(
                            f"File ``{entry.get('path')}`` matches "
                            f"published VECT 2.0 {ioc['platform']} "
                            f"hash. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "binary_hash",
                            "campaign": campaign,
                            "platform": ioc["platform"],
                            "sha256": hv,
                            "path": entry.get("path"),
                            "destructive_warning": destructive_warning,
                            "mitigation_commands": mitigation,
                            "references": references,
                        },
                        mitre="T1486",
                    )

        # ---- V2 ransom-note filename + V3 .vect extension +
        #      V4 ESXi/Linux drop paths ---- #

        for art in store.iter_artifacts(collector="recent_files"):
            d = art["data"] or {}
            entries = d.get("entries") or ([d] if d.get("path") else [])
            seen_drop = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path") or ""
                if not path:
                    continue
                base = _basename(path).lower()
                low_path = path.lower()

                # V2: ransom-note filename
                if base in ransom_notes:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"VECT 2.0 ransom note: {path}",
                        summary=(
                            f"File ``{path}`` matches the VECT 2.0 "
                            f"ransom-note filename. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "ransom_note_file",
                            "campaign": campaign,
                            "path": path,
                            "destructive_warning": destructive_warning,
                            "mitigation_commands": mitigation,
                            "references": references,
                        },
                        mitre="T1486",
                    )

                # V3: .vect extension
                if ext and _ext_lower(path) == ext:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"VECT 2.0 encrypted file present: {path}",
                        summary=(
                            f"File ``{path}`` has the VECT 2.0 "
                            f"``{ext}`` extension. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "vect_extension",
                            "campaign": campaign,
                            "path": path,
                            "destructive_warning": destructive_warning,
                            "mitigation_commands": mitigation,
                            "references": references,
                        },
                        mitre="T1486",
                    )

                # V4: ESXi/Linux ransom-note drop paths
                for dp in drop_paths:
                    if low_path == dp and dp not in seen_drop:
                        seen_drop.add(dp)
                        yield Finding(
                            detector=self.name,
                            severity="critical",
                            title=(
                                f"VECT 2.0 ESXi/Linux ransom-note "
                                f"drop path written: {path}"
                            ),
                            summary=(
                                f"File ``{path}`` is one of the "
                                "VECT 2.0 ESXi/Linux ransom-note drop "
                                "paths. The encryptor writes these "
                                "files unconditionally on those "
                                f"platforms. {common_response}"
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "drop_path",
                                "campaign": campaign,
                                "path": path,
                                "destructive_warning": destructive_warning,
                                "mitigation_commands": mitigation,
                                "references": references,
                            },
                            mitre="T1486",
                        )
                        break

        # ---- V5 distinctive cmdline flags ---- #

        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            cmd = _cmdline_str(d.get("cmdline"))
            if not cmd:
                continue
            for flag in all_flags:
                if flag in cmd:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"VECT 2.0 distinctive flag '{flag}' in "
                            f"cmdline (pid {d.get('pid')})"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} "
                            f"({d.get('name')}) cmdline contains "
                            f"``{flag}`` — a distinctive VECT 2.0 "
                            f"flag. {common_response}"
                            f"\n\nCmdline: {cmd[:300]}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "cmdline_flag",
                            "campaign": campaign,
                            "flag": flag,
                            "pid": d.get("pid"),
                            "name": d.get("name"),
                            "cmdline": cmd[:400],
                            "destructive_warning": destructive_warning,
                            "mitigation_commands": mitigation,
                            "references": references,
                        },
                        mitre="T1486",
                    )
                    break   # one flag finding per process

        # ---- V6 Tor / Qtox C2 ---- #

        if tor_prefix:
            for art in store.iter_artifacts(collector="processes"):
                d = art["data"] or {}
                cmd = _cmdline_str(d.get("cmdline")).lower()
                if tor_prefix in cmd or (qtox_id and qtox_id in cmd):
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"VECT 2.0 C2 contact in cmdline "
                            f"(pid {d.get('pid')})"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} references "
                            "VECT 2.0 Tor onion or Qtox-backup "
                            f"contact ID. {common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "c2_cmdline",
                            "campaign": campaign,
                            "pid": d.get("pid"),
                            "destructive_warning": destructive_warning,
                            "mitigation_commands": mitigation,
                            "references": references,
                        },
                        mitre="T1071",
                    )

            for art in store.iter_artifacts(collector="dns"):
                d = art["data"] or {}
                host = (d.get("host") or d.get("name") or "").lower()
                if host and tor_prefix in host:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"VECT 2.0 Tor C2 resolved in DNS: {host}",
                        summary=(
                            f"DNS history shows resolution of VECT "
                            f"2.0 Tor onion ``{host}``. "
                            f"{common_response}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "c2_dns",
                            "campaign": campaign,
                            "host": host,
                            "destructive_warning": destructive_warning,
                            "mitigation_commands": mitigation,
                            "references": references,
                        },
                        mitre="T1071",
                    )
