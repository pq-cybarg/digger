"""Linux systemd unit deep-audit detector.

The existing ``persistent_sessions`` detector catches one narrow
shape: an ExecStart in a user-systemd unit pointing at a user-
writable shell script. This detector covers the rest of the
malicious-unit patterns documented across Linux malware research
(Symbiote, OrBit, BPFDoor, Earth Lusca's CrossLock loader),
parallel to ``MacosLaunchdDetector`` for launchd plists.

Scope
-----
Consumes ``linux.systemd`` Artifacts with subject ``user-unit:*``
or ``system-unit:*``:
  - ``user-unit:*`` — per-user units under ``~/.config/systemd/user/``
  - ``system-unit:*`` — operator-customized + runtime-generated
    units under ``/etc/systemd/system`` and ``/run/systemd/system``

The vendor-shipped ``/usr/lib/systemd/system`` tree is intentionally
out of scope (signed-package files, would generate massive noise).

Detection layers (U1-U7)
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- regexes ---- #

_EXECSTART_RE = re.compile(
    r"^\s*(?:ExecStart|ExecStartPre|ExecStartPost|ExecStop|"
    r"ExecStopPost|ExecReload)\s*=\s*(.+?)\s*$",
    re.MULTILINE,
)
_RESTART_RE = re.compile(
    r"^\s*Restart\s*=\s*(\S+)", re.MULTILINE,
)
_USER_KEY_RE = re.compile(r"^\s*User\s*=\s*(\S+)", re.MULTILINE)
_GROUP_KEY_RE = re.compile(r"^\s*Group\s*=\s*(\S+)", re.MULTILINE)
_WANTEDBY_RE = re.compile(r"^\s*WantedBy\s*=\s*(\S.*)", re.MULTILINE)
_REQUIREDBY_RE = re.compile(r"^\s*RequiredBy\s*=\s*(\S.*)", re.MULTILINE)
_ENVFILE_RE = re.compile(
    r"^\s*EnvironmentFile\s*=\s*(\S+)", re.MULTILINE,
)
_LOADCRED_RE = re.compile(
    r"^\s*LoadCredentialEncrypted\s*=\s*\S+:(\S+)", re.MULTILINE,
)
_ON_UNIT_ACTIVE_SEC_RE = re.compile(
    r"^\s*OnUnitActiveSec\s*=\s*(\S+)", re.MULTILINE,
)
_ON_CALENDAR_RE = re.compile(
    r"^\s*OnCalendar\s*=\s*(\S.*)", re.MULTILINE,
)
_TYPE_RE = re.compile(r"^\s*Type\s*=\s*(\S+)", re.MULTILINE)

_NETWORK_FETCH_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|socat|fetch|"
    r"python[23]?\s+-c\s+['\"]import\s+(?:socket|urllib|http))",
    re.IGNORECASE,
)
_PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget|fetch)[^|]*\|\s*(?:sh|bash|zsh|/bin/sh|/bin/bash)",
    re.IGNORECASE,
)
_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_LONG_HEX_RE = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}){40,}|(?:[0-9a-fA-F]{2}\\?){80,}"
)

_INTERPRETERS_BASENAMES = (
    "sh", "bash", "zsh", "dash", "ksh",
    "python", "python3", "python2",
    "perl", "ruby", "node", "deno",
)

_USER_WRITABLE_PATH_FRAGMENTS = (
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/home/", "/root/",
    "/.cache/", "/.config/",
)


def _looks_writable(path: str) -> bool:
    if not path:
        return False
    return any(frag in path for frag in _USER_WRITABLE_PATH_FRAGMENTS)


def _exec_basename(execstart: str) -> str:
    """Return the basename of the first token in an ExecStart line.
    Handles the systemd ``+``/``-``/``@`` prefix modifiers."""
    s = execstart.lstrip().lstrip("+-@!:")
    first = s.split()[0] if s.split() else ""
    return first.rsplit("/", 1)[-1]


def _parse_timer_seconds(value: str) -> int | None:
    """Parse a systemd time string like ``30s``, ``5min``, ``2h`` to
    seconds. Returns None on parse failure."""
    if not value:
        return None
    m = re.match(r"^(\d+)\s*(s|sec|second|seconds|"
                  r"m|min|minute|minutes|"
                  r"h|hr|hour|hours|"
                  r"d|day|days)?$",
                  value.strip().lower())
    if not m:
        return None
    n = int(m.group(1))
    unit = (m.group(2) or "s")[0]
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return n * multipliers.get(unit, 1)


# ---- the detector ---- #


class SystemdAuditDetector(Detector):
    name = "systemd_audit"
    description = (
        "Linux systemd user-unit deep audit: network-fetch in "
        "ExecStart, encoded payloads, interpreter + Restart "
        "respawn loops, ExecStart from writable path + WantedBy "
        "auto-start, EnvironmentFile / LoadCredential from "
        "writable path, suspicious-cadence timers."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Suspicious systemd user unit",
            "id": "digger-systemd-audit-template",
            "description": (
                "Linux user-systemd unit matches a malware-style "
                "pattern (network-fetch ExecStart, encoded "
                "payload, interpreter+Restart loop, "
                "auto-enabled writable-path target, suspicious "
                "timer cadence)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "linux"},
            "detection": {
                "selection": {
                    "kind": [
                        "systemd_network_fetch",
                        "systemd_encoded_payload",
                        "systemd_interpreter_respawn",
                        "systemd_writable_autoenabled",
                        "systemd_writable_envfile",
                        "systemd_suspicious_timer",
                        "systemd_root_writable_exec",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1543.002", "attack.t1059.004",
                "attack.t1053.006", "attack.t1027",
                "attack.t1546",
                "attack.persistence",
                "attack.execution",
                "attack.defense_evasion",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="linux.systemd"):
            subj = art.get("subject") or ""
            if not (subj.startswith("user-unit:")
                    or subj.startswith("system-unit:")):
                continue
            yield from self._check_unit(art)

    def _check_unit(self, art) -> Iterable[Finding]:
        data = art["data"] or {}
        path = data.get("path") or "?"
        contents = data.get("contents") or ""
        owner_uid = data.get("owner_uid")
        ref = art["artifact_uuid"]
        unit_name = path.rsplit("/", 1)[-1]

        exec_lines = _EXECSTART_RE.findall(contents)
        full_exec_text = " ".join(exec_lines)
        m_user = _USER_KEY_RE.search(contents)
        unit_user = m_user.group(1) if m_user else ""
        m_restart = _RESTART_RE.search(contents)
        restart_mode = m_restart.group(1).lower() if m_restart else ""
        wanted_by = _WANTEDBY_RE.search(contents)
        required_by = _REQUIREDBY_RE.search(contents)
        auto_enabled = bool(wanted_by or required_by)
        envfile = _ENVFILE_RE.search(contents)
        loadcred = _LOADCRED_RE.search(contents)

        # ---- U1: network fetch in any Exec* ---- #
        net = _NETWORK_FETCH_RE.search(full_exec_text)
        pipe = _PIPE_TO_SHELL_RE.search(full_exec_text)
        if net or pipe:
            sev = "critical" if pipe else "high"
            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"systemd unit runs network-fetch command: "
                    f"{unit_name}"
                ),
                summary=(
                    f"Unit ``{path}`` declares an Exec line that "
                    "fetches from the network (curl/wget/nc/"
                    "socat/python-socket). A persistent unit that "
                    "issues a download on every (re)start is the "
                    "classic Linux-malware downloader stub. "
                    "Verify the destination."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "systemd_network_fetch",
                    "path": path,
                    "unit_name": unit_name,
                    "owner_uid": owner_uid,
                    "exec_snippet": full_exec_text[:400],
                    "restart_mode": restart_mode,
                    "auto_enabled": auto_enabled,
                    "pipe_to_shell": bool(pipe),
                },
                mitre="T1543.002",
            )

        # ---- U2: encoded payload in Exec lines ---- #
        if _LONG_BASE64_RE.search(full_exec_text) or \
                _LONG_HEX_RE.search(full_exec_text):
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"systemd unit contains long encoded "
                    f"payload: {unit_name}"
                ),
                summary=(
                    f"Unit ``{path}`` carries a long base64 or "
                    "escaped-hex sequence in its Exec lines. "
                    "Sometimes legitimate (encoded TLS pin, "
                    "key material), often a hidden shell / "
                    "Python payload. Decode and review."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "systemd_encoded_payload",
                    "path": path,
                    "unit_name": unit_name,
                    "exec_snippet": full_exec_text[:400],
                },
                mitre="T1027",
            )

        # ---- U3: interpreter + Restart respawn ---- #
        interpreter_in_exec = any(
            _exec_basename(line) in _INTERPRETERS_BASENAMES
            for line in exec_lines
        )
        restart_keeps_alive = restart_mode in (
            "always", "on-failure", "on-abnormal", "on-success",
        )
        if interpreter_in_exec and restart_keeps_alive:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"systemd interpreter respawn loop: "
                    f"{unit_name}"
                ),
                summary=(
                    f"Unit ``{path}`` runs an interpreter "
                    "(sh/bash/python/perl/ruby/node) with "
                    f"Restart=``{restart_mode}`` — systemd will "
                    "keep respawning it. Combined with an "
                    "interpreter vs a compiled binary, the "
                    "daemon-shaped malware fingerprint. Verify "
                    "the operator intentionally chose a script "
                    "as a service."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "systemd_interpreter_respawn",
                    "path": path,
                    "unit_name": unit_name,
                    "owner_uid": owner_uid,
                    "restart_mode": restart_mode,
                    "exec_snippet": full_exec_text[:400],
                },
                mitre="T1059.004",
            )

        # ---- U4: ExecStart from writable path + auto-enabled ---- #
        writable_execs = [
            line for line in exec_lines if _looks_writable(line)
        ]
        if writable_execs and auto_enabled:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"systemd unit Exec from writable path + "
                    f"auto-enabled: {unit_name}"
                ),
                summary=(
                    f"Unit ``{path}`` has at least one Exec "
                    "line pointing into a user-writable path "
                    f"(``{writable_execs[0][:200]}``) AND an "
                    "[Install] section that auto-enables it "
                    "(WantedBy / RequiredBy). The unit will start "
                    "on boot, run code the user (or any process "
                    "with write access to the target path) can "
                    "edit. Documented worm-persistence pattern "
                    "for Linux."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "systemd_writable_autoenabled",
                    "path": path,
                    "unit_name": unit_name,
                    "owner_uid": owner_uid,
                    "writable_execs": [w[:200] for w in writable_execs[:5]],
                    "wanted_by": wanted_by.group(1) if wanted_by else "",
                    "required_by": required_by.group(1) if required_by else "",
                },
                mitre="T1546",
            )

        # ---- U5: root user + writable Exec target ---- #
        if unit_user == "root" and writable_execs:
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"systemd unit runs as root from writable "
                    f"path: {unit_name}"
                ),
                summary=(
                    f"Unit ``{path}`` declares ``User=root`` and "
                    "points Exec at a user-writable location "
                    f"(``{writable_execs[0][:200]}``). Whoever "
                    "can write to that path gets code execution "
                    "as root every time the unit runs — the "
                    "canonical Linux setuid-via-systemd "
                    "primitive."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "systemd_root_writable_exec",
                    "path": path,
                    "unit_name": unit_name,
                    "owner_uid": owner_uid,
                    "writable_execs": [w[:200] for w in writable_execs[:5]],
                },
                mitre="T1543.002",
            )

        # ---- U6: EnvironmentFile / LoadCredential from writable path ---- #
        envfile_path = envfile.group(1) if envfile else ""
        loadcred_path = loadcred.group(1) if loadcred else ""
        if _looks_writable(envfile_path) or _looks_writable(loadcred_path):
            offending = (envfile_path if _looks_writable(envfile_path)
                          else loadcred_path)
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"systemd unit loads env / credentials from "
                    f"writable path: {unit_name}"
                ),
                summary=(
                    f"Unit ``{path}`` reads either "
                    "``EnvironmentFile=`` or "
                    "``LoadCredentialEncrypted=`` from "
                    f"``{offending}``. Anyone who can write to "
                    "that path can inject environment variables "
                    "(``LD_PRELOAD``, etc.) or substitute "
                    "credentials before the service starts."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "systemd_writable_envfile",
                    "path": path,
                    "unit_name": unit_name,
                    "envfile_path": envfile_path,
                    "loadcred_path": loadcred_path,
                },
                mitre="T1546",
            )

        # ---- U7: suspicious timer cadence ---- #
        m_active = _ON_UNIT_ACTIVE_SEC_RE.search(contents)
        if m_active:
            secs = _parse_timer_seconds(m_active.group(1))
            if secs is not None and secs < 60:
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=(
                        f"systemd timer fires faster than once "
                        f"per minute: {unit_name}"
                    ),
                    summary=(
                        f"Timer ``{path}`` declares "
                        f"``OnUnitActiveSec={m_active.group(1)}`` "
                        f"({secs}s). Legitimate timers rarely "
                        "fire sub-minute; a fast-cadence timer "
                        "is the canonical C2 / beacon poll "
                        "shape — common in low-and-slow Linux "
                        "implants."
                    ),
                    artifact_refs=[ref],
                    evidence={
                        "kind": "systemd_suspicious_timer",
                        "path": path,
                        "unit_name": unit_name,
                        "on_unit_active_sec_raw": m_active.group(1),
                        "on_unit_active_sec_s": secs,
                    },
                    mitre="T1053.006",
                )
