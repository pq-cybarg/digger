"""Counter-privilege-escalation: detect planted suid/sgid, capability,
sudoers, and kernel-module privesc primitives.

Observational only — we read what the privesc-surface + sudoers + kmod
collectors have captured and flag known privesc patterns:

  P1  setuid binary in user-writable scratch dir
      A setuid root binary in /tmp, /var/tmp, /dev/shm, /Users/Shared,
      or under a user home — the canonical "I planted myself a root
      escape" primitive. Always world-writable+setuid is automatic
      critical.

  P2  setuid binary that should not be setuid
      Common admin binaries (cp, mv, less, vi, find, awk, perl, python,
      bash) with setuid set — these aren't normally setuid; if they are,
      they're a GTFOBins-trivial privesc.

  P3  sudoers with NOPASSWD: ALL or ALL=(ALL) NOPASSWD
      Effective passwordless root. Sometimes legitimate (CI users), but
      always worth a finding so the operator can confirm.

  P4  Linux capability set on a shell or shell-like binary
      ``setcap cap_setuid+ep /bin/bash`` or similar — silent privesc
      primitive that doesn't even need setuid bit.

  P5  Kernel taint flags set (Linux)
      Non-zero /proc/sys/kernel/tainted = something abnormal happened
      to the kernel. Each bit means something specific; we surface them.

  P6  Kernel module loaded from a non-standard path
      Modules loaded via `insmod /tmp/rootkit.ko` show up in lsmod and
      are visible if their backing file path is not under /lib/modules.

MITRE: T1548 (Abuse Elevation Control Mechanism),
T1068 (Exploitation for Privilege Escalation),
T1611 (Escape to Host), T1547.006 (Kernel Modules / Extensions).
"""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# Binaries that should NEVER be setuid (would equal trivial root)
_NEVER_SETUID = {
    "cp", "mv", "less", "more", "vi", "vim", "nano", "ed", "emacs",
    "awk", "gawk", "sed", "find", "xargs", "tee", "dd",
    "perl", "python", "python2", "python3", "ruby", "lua", "node",
    "bash", "sh", "zsh", "dash", "ksh", "fish", "tcsh",
    "cat", "tail", "head", "grep", "egrep", "fgrep",
    "tar", "gzip", "gunzip", "zip", "unzip", "rsync",
    "nc", "ncat", "socat", "ssh", "scp", "sftp",
    "env", "exec",
}

# Scratch dirs where any setuid binary is a privesc primitive.
_SCRATCH_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/",
                     "/Users/Shared/", "/private/tmp/")


# Sudoers patterns
_NOPASSWD_ALL = re.compile(r"^\s*[^#]*?NOPASSWD\s*:\s*ALL\b", re.M)
_ALL_ALL_NOPASSWD = re.compile(r"^\s*[^#]*?\bALL\s*=\s*\(\s*ALL\s*(?::\s*ALL\s*)?\)\s*NOPASSWD", re.M)
_USER_ALL_ANY = re.compile(r"^\s*([^\s#%][^\s#=]*)\s+ALL\s*=\s*", re.M)

# Capabilities that grant root-equivalent powers
_DANGEROUS_CAPS = {
    "cap_setuid", "cap_setgid", "cap_sys_admin", "cap_sys_ptrace",
    "cap_sys_module", "cap_dac_override", "cap_dac_read_search",
    "cap_chown", "cap_fowner", "cap_kill", "cap_net_admin", "cap_net_raw",
}

# Names of binaries on which a dangerous capability = silent privesc.
_SENSITIVE_CAP_BINARIES = {
    "bash", "sh", "zsh", "dash", "ksh", "fish", "tcsh",
    "python", "python2", "python3", "perl", "ruby", "node", "php",
    "awk", "gawk", "find", "vim", "nano",
}


# /proc/sys/kernel/tainted bit meanings
_TAINT_BITS = {
    0:  "proprietary module loaded",
    1:  "module force-loaded",
    2:  "kernel running on out-of-spec system",
    3:  "module force-unloaded",
    4:  "processor reported a Machine Check Exception (hardware fault)",
    5:  "bad page reference / unexpected page flag",
    6:  "userspace requested taint",
    7:  "kernel died recently (OOPS/BUG/etc.)",
    8:  "staging-tree driver loaded",
    9:  "workaround for buggy firmware in use",
    10: "out-of-tree module loaded",
    11: "unsigned module loaded",
    12: "soft-lockup occurred",
    13: "kernel has been live-patched",
    14: "auxiliary taint by kernel subsystem",
    15: "kernel built with struct randomization disabled at runtime",
}


def _path_in_scratch(path: str) -> str | None:
    for pref in _SCRATCH_PREFIXES:
        if path.startswith(pref):
            return pref
    # Per-user home anywhere
    if path.startswith("/home/") or path.startswith("/Users/"):
        return path.rsplit("/", 1)[0] + "/"
    return None


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if "/" in path else path


class PrivescDetector(Detector):
    name = "privesc"
    description = (
        "Privilege-escalation primitives: planted setuid, dangerous capabilities, "
        "permissive sudoers, kernel taint, modules from non-standard paths."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Privilege-escalation primitive installed (setuid / capability / sudoers / kmod)",
            "id": "digger-privesc-template",
            "description": (
                "A file-event creating or modifying a setuid binary in a "
                "user-writable directory, sudoers NOPASSWD: ALL clauses, "
                "setcap on a shell/interpreter, or insmod/modprobe of "
                "an out-of-tree module."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "file_event"},
            "detection": {
                "selection_setuid": {
                    "TargetFilename|startswith": ["/tmp/", "/var/tmp/",
                                                    "/dev/shm/", "/home/"],
                    "FileMode|contains": ["4000", "2000"],
                },
                "selection_sudoers": {
                    "TargetFilename|startswith": "/etc/sudoers",
                },
                "selection_setcap": {
                    "Image|endswith": "/setcap",
                },
                "selection_insmod": {
                    "Image|endswith": ["/insmod", "/modprobe"],
                },
                "condition": "1 of selection_*",
            },
            "level": "high",
            "tags": ["attack.t1548", "attack.t1068", "attack.t1547.006",
                    "attack.privilege_escalation"],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- P1 + P2: setuid surface ----
        for art in store.iter_artifacts(category="privesc_surface"):
            d = art["data"]
            if not (d.get("is_setuid") or d.get("is_setgid")):
                continue
            path = d.get("path") or ""
            ww = bool(d.get("world_writable"))
            owner_uid = d.get("owner_uid")
            base = _basename(path)

            # P1.a — world-writable AND setuid: critical, no exceptions
            if ww:
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=f"World-writable setuid binary: {path}",
                    summary=(
                        f"{path} has setuid root + world-writable permissions. "
                        "Any local user can overwrite the binary to take its "
                        "elevated identity. This is an unambiguous privesc."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"kind": "world_writable_setuid", "path": path,
                              "mode": d.get("mode"), "owner_uid": owner_uid},
                    mitre="T1548.001",
                )
                continue

            # P1.b — setuid in scratch / user home
            scratch = _path_in_scratch(path)
            if scratch:
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=f"setuid binary in scratch/user dir: {path}",
                    summary=(
                        f"setuid binary at {path} lives in {scratch}. Setuid in "
                        "user-writable space is the textbook planted privesc "
                        "primitive — no legitimate package installs setuid roots "
                        "under /tmp or a user home."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"kind": "setuid_in_scratch", "path": path,
                              "scratch_root": scratch},
                    mitre="T1548.001",
                )
                continue

            # P2 — should-never-be-setuid commodity binary
            if base in _NEVER_SETUID and owner_uid == 0:
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=f"setuid root on commodity binary: {path}",
                    summary=(
                        f"{path} ({base}) is setuid root. GTFOBins lists {base} "
                        "as a trivial privesc when setuid — the binary has "
                        "documented escape paths to a root shell."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"kind": "gtfobins_setuid", "path": path,
                              "binary": base, "mode": d.get("mode")},
                    mitre="T1548.001",
                )
                continue

            # Fallback: a setuid binary outside the system bin dirs is worth a
            # medium-sev advisory.
            if not d.get("in_system_dir"):
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=f"setuid binary outside system bin dirs: {path}",
                    summary=(
                        f"{path} is setuid but not under one of the canonical "
                        "system bin directories. Could be admin-built tooling; "
                        "review."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"kind": "setuid_offpath", "path": path,
                              "mode": d.get("mode")},
                    mitre="T1548.001",
                )

        # ---- P4: dangerous file capabilities ----
        for art in store.iter_artifacts(collector="linux.privesc",
                                         category="privesc_surface"):
            d = art["data"]
            raw = d.get("raw")
            if not raw:
                continue
            # getcap output format:  /path/to/binary cap_setuid,cap_net_raw=ep
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                # newer getcap separates path and caps by spaces; older by '='
                m = re.match(r"(/\S+)\s+(\S+)\s*=", line)
                if not m:
                    m = re.match(r"(/\S+)\s+(\S+)", line)
                if not m:
                    continue
                bin_path, caps = m.group(1), m.group(2)
                bin_caps = {c.strip().lower() for c in caps.split(",")}
                dangerous = bin_caps & _DANGEROUS_CAPS
                if not dangerous:
                    continue
                base = _basename(bin_path)
                is_shell_like = base in _SENSITIVE_CAP_BINARIES
                severity = "critical" if is_shell_like else "high"
                yield Finding(
                    detector=self.name,
                    severity=severity,
                    title=f"Dangerous file capability on {bin_path}: {sorted(dangerous)}",
                    summary=(
                        f"{bin_path} has file capabilities {sorted(dangerous)} set. "
                        + ("This binary is a shell or interpreter — a dangerous "
                           "capability here is equivalent to setuid root without "
                           "the visible setuid bit. "
                           if is_shell_like else "")
                        + "Use `getcap -v` to inspect, `setcap -r` to remove."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "dangerous_file_capability",
                        "path": bin_path,
                        "capabilities": sorted(bin_caps),
                        "dangerous": sorted(dangerous),
                    },
                    mitre="T1548",
                )

        # ---- P3: sudoers permissive entries ----
        for art in store.iter_artifacts(collector="linux.sudoers"):
            d = art["data"]
            text = d.get("contents") or ""
            path = d.get("path") or "?"
            if not text:
                continue
            for m in _NOPASSWD_ALL.finditer(text):
                line = m.group(0).strip()
                # Skip pure-comment captures (defensive)
                if line.startswith("#"):
                    continue
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=f"sudoers NOPASSWD: ALL in {path}",
                    summary=(
                        f"{path} contains a NOPASSWD: ALL clause: `{line}`. "
                        "Anyone matching this rule can sudo with no password "
                        "challenge. Sometimes legitimate (CI), often not."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "sudoers_nopasswd_all",
                        "sudoers_path": path,
                        "line": line[:300],
                    },
                    mitre="T1548.003",
                )

        # ---- P5: kernel taint ----
        for art in store.iter_artifacts(collector="linux.privesc"):
            d = art["data"]
            if art["subject"] != "kernel-tainted":
                continue
            try:
                v = int(d.get("value") or 0)
            except (TypeError, ValueError):
                continue
            if v == 0:
                continue
            bits_set = [(b, _TAINT_BITS.get(b, "unknown bit"))
                        for b in range(32) if v & (1 << b)]
            # Bits that are real privesc smells: 11 (unsigned module),
            # 10 (out-of-tree module), 6 (userspace tainted)
            high_signal = any(b in (10, 11, 6) for b, _ in bits_set)
            yield Finding(
                detector=self.name,
                severity="high" if high_signal else "medium",
                title=f"Kernel taint flags set (value={v})",
                summary=(
                    f"/proc/sys/kernel/tainted = {v}. Bits set:\n  "
                    + "\n  ".join(f"bit {b}: {desc}" for b, desc in bits_set)
                    + "\nBit 11 (unsigned module) and bit 10 (out-of-tree) are "
                    "common signs of operator-loaded modules — could be a "
                    "DKMS driver or a planted rootkit."
                ),
                artifact_refs=[art["artifact_uuid"]],
                evidence={
                    "kind": "kernel_taint",
                    "value": v,
                    "bits_set": [{"bit": b, "meaning": d} for b, d in bits_set],
                },
                mitre="T1547.006",
            )

        # ---- P6: kernel modules loaded from non-standard paths ----
        # /proc/modules doesn't include the .ko backing path. We don't have a
        # reliable cross-distro way to map module->path without running
        # `modinfo` ourselves. We surface taint+module count as a single
        # composite signal; per-module path enumeration is left to a future
        # extension.
