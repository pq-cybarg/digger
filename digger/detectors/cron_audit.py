"""Linux cron / anacron / at deep-audit detector.

The existing ``persistence_outlier`` detector catches cron entries
whose command lives in a writable path (the generic "writable
path" heuristic). This detector covers the cron-specific patterns
it misses, modeled on ``systemd_audit`` and ``macos_launchd``.

Scope
-----
Consumes Artifacts emitted by ``digger.collectors.linux.cron``:
  - ``cron:<path>`` — /etc/crontab + /etc/anacrontab (full text)
  - ``cron-dir:<path>`` — /etc/cron.{d,hourly,daily,weekly,monthly},
                          /var/spool/cron, /var/spool/cron/crontabs,
                          /var/spool/anacron, /var/spool/at
                          (entries[] each with name + contents)

Detection layers (C1-C7).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


_NETWORK_FETCH_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|socat|fetch|"
    r"python[23]?\s+-c\s+['\"]?import\s+(?:socket|urllib|http))",
    re.IGNORECASE,
)
_PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget|fetch)[^|]*\|\s*(?:sh|bash|zsh|/bin/sh|/bin/bash)",
    re.IGNORECASE,
)
_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_LONG_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}")

_REBOOT_RE = re.compile(r"^\s*@reboot\b", re.MULTILINE)

# Crontab schedule field forms we care about for cadence checks.
# Match a 5-field schedule at the line start.
_CRON_LINE_RE = re.compile(
    r"^\s*"
    r"(?P<min>\S+)\s+"
    r"(?P<hour>\S+)\s+"
    r"(?P<dom>\S+)\s+"
    r"(?P<month>\S+)\s+"
    r"(?P<dow>\S+)\s+"
    r"(?P<rest>.+)$",
    re.MULTILINE,
)
# /etc/crontab + /etc/cron.d lines have an extra ``user`` field
# BEFORE the command: minute hour dom month dow user command...
_CRON_LINE_WITH_USER_RE = re.compile(
    r"^\s*"
    r"(?P<min>\S+)\s+"
    r"(?P<hour>\S+)\s+"
    r"(?P<dom>\S+)\s+"
    r"(?P<month>\S+)\s+"
    r"(?P<dow>\S+)\s+"
    r"(?P<user>[A-Za-z_][A-Za-z0-9_-]*)\s+"
    r"(?P<command>.+)$",
    re.MULTILINE,
)

_USER_WRITABLE_PATH_FRAGMENTS = (
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/home/", "/root/",
    "/.cache/", "/.config/",
)


def _looks_writable(path: str) -> bool:
    if not path:
        return False
    if path.startswith(("./", "../", "~/")):
        return True
    return any(frag in path for frag in _USER_WRITABLE_PATH_FRAGMENTS)


def _is_system_path(path: str) -> bool:
    """Recognize canonical system / package locations."""
    return path.startswith((
        "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/",
        "/usr/local/sbin/", "/usr/local/bin/",
        "/opt/",
    ))


def _first_command_token(rest: str) -> str:
    """Strip an env-prefix (``KEY=VALUE`` pairs) and return the
    first command word."""
    parts = rest.strip().split()
    for tok in parts:
        if "=" in tok and not tok.startswith(("/", "-")):
            continue
        return tok
    return ""


def _schedule_seconds_estimate(min_field: str,
                                 hour_field: str) -> int | None:
    """Estimate the typical cadence in seconds for the given
    crontab minute+hour fields. Returns None if the cadence isn't
    something we can characterize cheaply.

    Heuristics:
      "* * ..."       → every minute   → 60s
      "*/N * ..."     → every N min    → 60*N
      "0 * ..."       → every hour     → 3600
      "0 */N * ..."   → every N hours  → 3600*N
    """
    if min_field == "*" and hour_field == "*":
        return 60
    m = re.match(r"^\*/(\d+)$", min_field)
    if m and hour_field == "*":
        return 60 * int(m.group(1))
    if hour_field == "*" and re.match(r"^\d+$", min_field):
        return 3600
    m = re.match(r"^\*/(\d+)$", hour_field)
    if m and (min_field == "0" or re.match(r"^\d+$", min_field)):
        return 3600 * int(m.group(1))
    return None


def _walk_cron_artifact(art) -> Iterable[tuple[str, str, str]]:
    """Yield (source_label, source_path, contents) tuples for every
    parseable cron-text body in the artifact."""
    subj = art.get("subject") or ""
    data = art["data"] or {}
    if subj.startswith("cron:"):
        contents = data.get("contents") or ""
        path = data.get("path") or subj[len("cron:"):]
        if contents:
            yield (path.rsplit("/", 1)[-1], path, contents)
    elif subj.startswith("cron-dir:"):
        base = data.get("path") or subj[len("cron-dir:"):]
        for entry in data.get("entries") or []:
            if not isinstance(entry, dict):
                continue
            contents = entry.get("contents") or ""
            if not contents:
                continue
            name = entry.get("name") or ""
            yield (name, f"{base}/{name}", contents)


class CronAuditDetector(Detector):
    name = "cron_audit"
    description = (
        "Linux cron / anacron / at deep audit: network-fetch in "
        "cron entry, encoded payloads, command in writable path, "
        "root-context entries running attacker-controlled paths, "
        "@reboot persistence, high-frequency beacon schedules, "
        "at-jobs."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Suspicious cron entry",
            "id": "digger-cron-audit-template",
            "description": (
                "cron/anacron/at entry matches a malware-style "
                "pattern (network-fetch, encoded payload, "
                "writable-path command, root + attacker path, "
                "@reboot persistence, high-frequency cadence)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "linux"},
            "detection": {
                "selection": {
                    "kind": [
                        "cron_network_fetch",
                        "cron_encoded_payload",
                        "cron_writable_command",
                        "cron_root_attacker_path",
                        "cron_at_reboot",
                        "cron_high_frequency",
                        "cron_at_job",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1053.003", "attack.t1053.001",
                "attack.t1059.004", "attack.t1027",
                "attack.t1546", "attack.t1037",
                "attack.persistence", "attack.execution",
                "attack.defense_evasion",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="linux.cron"):
            subj = art.get("subject") or ""
            for src_label, src_path, contents in _walk_cron_artifact(art):
                yield from self._check_body(
                    art, src_label, src_path, contents,
                    is_at_spool=("at" in subj
                                 or "/var/spool/at" in src_path),
                )

    def _check_body(
        self,
        art,
        src_label: str,
        src_path: str,
        contents: str,
        *,
        is_at_spool: bool,
    ) -> Iterable[Finding]:
        ref = art["artifact_uuid"]

        # ---- C1 network fetch in the body anywhere ---- #
        net = _NETWORK_FETCH_RE.search(contents)
        pipe = _PIPE_TO_SHELL_RE.search(contents)
        if pipe or net:
            sev = "critical" if pipe else "high"
            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"cron entry fetches from the network: "
                    f"{src_label}"
                ),
                summary=(
                    f"``{src_path}`` contains a network-fetch "
                    "command (curl/wget/nc/socat/python-socket). "
                    "A cron task that downloads on schedule is "
                    "the classic Linux-malware payload-rotation "
                    "primitive. A pipe-to-shell shape is "
                    "essentially never legitimate."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "cron_network_fetch",
                    "source": src_path,
                    "pipe_to_shell": bool(pipe),
                },
                mitre="T1053.003",
            )

        # ---- C2 encoded payload ---- #
        if _LONG_BASE64_RE.search(contents) or \
                _LONG_HEX_RE.search(contents):
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"cron entry contains encoded payload: "
                    f"{src_label}"
                ),
                summary=(
                    f"``{src_path}`` carries a long base64 or "
                    "escaped-hex sequence. Sometimes legitimate "
                    "(certificate, encoded key), often a hidden "
                    "shell / Python payload — decode and review."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "cron_encoded_payload",
                    "source": src_path,
                },
                mitre="T1027",
            )

        # ---- C5 @reboot persistence ---- #
        if _REBOOT_RE.search(contents):
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"cron entry uses @reboot: {src_label}"
                ),
                summary=(
                    f"``{src_path}`` declares an ``@reboot`` "
                    "schedule — the command runs on every boot. "
                    "Legitimate uses exist (one-shot daemon "
                    "kickoff) but @reboot is also one of the "
                    "most common persistence primitives. Verify "
                    "the body."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "cron_at_reboot",
                    "source": src_path,
                },
                mitre="T1037",
            )

        # ---- C6 at-job present ---- #
        if is_at_spool:
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"at-job present: {src_label}"
                ),
                summary=(
                    f"``{src_path}`` is an at-job (one-shot "
                    "delayed exec). Less common than cron, often "
                    "abused for delayed-execution / "
                    "anti-sandbox tradecraft (set the job to "
                    "fire 24h out so analysis machines time out "
                    "first). Worth a manual review of the body."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "cron_at_job",
                    "source": src_path,
                },
                mitre="T1053.001",
            )

        # ---- per-line: C3 writable, C4 root + attacker path,
        #                 C7 high-frequency ---- #
        # First try with-user form (/etc/crontab + /etc/cron.d);
        # then plain user-crontab form (/var/spool/cron/*).
        seen_lines: set[str] = set()
        for m in _CRON_LINE_WITH_USER_RE.finditer(contents):
            line_key = m.group(0)
            if line_key in seen_lines:
                continue
            seen_lines.add(line_key)
            yield from self._check_schedule_line(
                m.group("min"), m.group("hour"),
                user=m.group("user"),
                command=m.group("command"),
                ref=ref, src_path=src_path, src_label=src_label,
            )
        # Now check plain crontab lines, but only those that
        # weren't already matched as with-user.
        for m in _CRON_LINE_RE.finditer(contents):
            if m.group(0) in seen_lines:
                continue
            min_f, hour_f = m.group("min"), m.group("hour")
            # Skip env-variable lines and "@<keyword>" entries
            # (they don't have the 5-field schedule shape).
            if "=" in min_f or min_f.startswith("@"):
                continue
            # Per-user crontabs (no user field). Owner inferred
            # from the artifact's source path.
            yield from self._check_schedule_line(
                min_f, hour_f,
                user="", command=m.group("rest"),
                ref=ref, src_path=src_path, src_label=src_label,
            )

    def _check_schedule_line(
        self,
        min_field: str,
        hour_field: str,
        *,
        user: str,
        command: str,
        ref: str,
        src_path: str,
        src_label: str,
    ) -> Iterable[Finding]:
        cmd_tok = _first_command_token(command)

        # C3 writable command
        if _looks_writable(cmd_tok):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"cron command in writable path: "
                    f"{src_label}"
                ),
                summary=(
                    f"``{src_path}`` schedules "
                    f"``{cmd_tok[:200]}`` (user "
                    f"``{user or '<owner>'}``). The command "
                    "lives in a user-writable / scratch path — "
                    "whoever can write to that path edits what "
                    "cron runs on schedule."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "cron_writable_command",
                    "source": src_path,
                    "user": user,
                    "command": cmd_tok,
                },
                mitre="T1053.003",
            )

        # C4 root + attacker-controlled path
        if user == "root" and cmd_tok and \
                not _is_system_path(cmd_tok):
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"root cron command outside system path: "
                    f"{src_label}"
                ),
                summary=(
                    f"``{src_path}`` schedules "
                    f"``{cmd_tok[:200]}`` to run as ``root`` but "
                    "the command does not live under "
                    "/usr/sbin /usr/bin /sbin /bin /opt. "
                    "Anyone with write access to the target "
                    "binary gets root every schedule fire — "
                    "canonical Linux escalation via cron."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "cron_root_attacker_path",
                    "source": src_path,
                    "command": cmd_tok,
                },
                mitre="T1053.003",
            )

        # C7 high-frequency
        secs = _schedule_seconds_estimate(min_field, hour_field)
        if secs is not None and secs < 300:
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"cron entry fires more often than every "
                    f"5 minutes: {src_label}"
                ),
                summary=(
                    f"``{src_path}`` schedule "
                    f"``{min_field} {hour_field} * * *`` fires "
                    f"approximately every {secs} seconds. "
                    "Legitimate sub-5-minute crons are rare; "
                    "fast cadence is the canonical C2 / beacon "
                    "poll shape."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "cron_high_frequency",
                    "source": src_path,
                    "user": user,
                    "estimated_period_s": secs,
                    "min_field": min_field,
                    "hour_field": hour_field,
                    "command": cmd_tok,
                },
                mitre="T1053.003",
            )
