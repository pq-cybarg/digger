"""Counter-persistent-session: long-lived attacker holds on the host.

Observational only. Mines processes + systemd unit text for the three
canonical persistent-shell-session patterns:

  S1  Multiplexer session parented by a network-facing service
      tmux / screen / zellij / dtach process whose parent (or grandparent)
      is sshd is the normal admin pattern. The same multiplexer parented
      by nginx / apache / php-fpm / postgres / mysqld is a textbook
      attacker-stays-resident primitive — once the implant breaks out
      of the webserver context into a multiplexer, it survives every
      reload of the parent.

  S2  Detached process (nohup / setsid) with an open network socket
      A process whose session-leader is itself (setsid) AND that holds
      one or more INET sockets is an unattended listener / phone-home —
      pure presence is not malicious but a low-signal advisory.

  S3  systemd user-units pointing to a user-writable script
      ~/.config/systemd/user/*.service with ExecStart=<path> where
      <path> is under the user's home and the script's first line is
      a shell shebang (#!/bin/sh, #!/bin/bash, etc.). The user-systemd
      directory + lingering enables logout-resilient persistence with
      no root required.

MITRE: T1546 (Event-Triggered Execution) — closest fit for multiplexer
hijack and shell-as-systemd-unit; T1543.002 (Create or Modify System
Process: systemd Service); T1059 (interactive shell as persistence).
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# Network-facing-service names whose direct or transitive parentage of a
# multiplexer / interactive shell is the persistence signature.
_NETWORK_SERVICE_PARENTS = {
    "nginx", "httpd", "apache2", "php-fpm", "php-fpm8.1", "php-fpm8.2",
    "php-fpm8.3", "node", "nodejs", "java", "tomcat",
    "postgres", "postmaster", "mysqld", "mariadbd",
    "redis-server", "mongod", "memcached", "elasticsearch",
    "vsftpd", "smbd", "w3wp.exe", "iisexpress", "tomcat9.exe",
}

# Long-lived multiplexer / detacher names.
_MULTIPLEXER_NAMES = {
    "tmux", "tmux:server", "tmux:client",
    "screen", "SCREEN",
    "zellij", "dtach", "abduco",
    "nohup",  # rarely the binary name, but seen with `exec -a nohup`
}

# Shell names (re-used for the S3 ExecStart check)
_SHELL_NAMES = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh",
}

# Common scratch / home prefixes for the S3 "ExecStart in user-writable" check.
_USER_WRITABLE_PREFIXES = (
    "/home/", "/root/", "/tmp/", "/var/tmp/", "/dev/shm/", "/Users/Shared/",
)


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


def _collect_processes(store: EvidenceStore) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for art in store.iter_artifacts(collector="processes"):
        d = art["data"]
        pid = d.get("pid")
        if pid is None:
            continue
        nm = (d.get("name") or "").lower()
        out[pid] = {
            "pid": pid,
            "ppid": d.get("ppid"),
            "name": nm,
            "base": (_basename(d.get("exe") or "") or nm).lower(),
            "cmdline": _cmdline_str(d.get("cmdline")),
            "connections": d.get("connections") or [],
            "username": d.get("username"),
            "artifact_uuid": art["artifact_uuid"],
        }
    return out


def _ancestor_chain(procs: dict[int, dict], pid: int, depth: int = 6) -> list[dict]:
    chain: list[dict] = []
    cur = procs.get(pid)
    while cur and depth > 0:
        chain.append(cur)
        ppid = cur.get("ppid")
        if not ppid:
            break
        cur = procs.get(ppid)
        depth -= 1
    return chain


# ExecStart=<...> parser. Handles inline, multi-line continuation we already
# stripped at collection time, and quoted paths.
_EXECSTART = re.compile(r"^\s*ExecStart\s*=\s*(.+?)\s*$", re.M)


def _parse_execstart_paths(text: str) -> list[str]:
    """Return the resolved path(s) of every ExecStart=... line."""
    out: list[str] = []
    for m in _EXECSTART.finditer(text or ""):
        cmd = m.group(1).strip()
        # systemd allows a leading "@" / "-" / "+" prefix
        cmd = cmd.lstrip("@-+!:")
        try:
            tokens = shlex.split(cmd, posix=True)
        except ValueError:
            continue
        if not tokens:
            continue
        out.append(tokens[0])
    return out


def _is_under_user_writable(path: str) -> bool:
    return any(path.startswith(p) for p in _USER_WRITABLE_PREFIXES)


def _has_shell_shebang(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(80)
    except (PermissionError, OSError, FileNotFoundError, IsADirectoryError):
        return False
    if not head.startswith(b"#!"):
        return False
    first = head.split(b"\n", 1)[0]
    interpreter = _basename(first.split()[0].decode("utf-8", errors="replace")
                              .removeprefix("#!").strip())
    return interpreter in _SHELL_NAMES


def _file_owner_writable_by_user(path: str, owner_uid: int | None) -> bool:
    """True if the file lives under the same user's tree as owner_uid."""
    if owner_uid is None:
        return False
    try:
        st = os.stat(path)
        return st.st_uid == owner_uid
    except (PermissionError, OSError, FileNotFoundError):
        return _is_under_user_writable(path)


class PersistentSessionDetector(Detector):
    name = "persistent_sessions"
    description = (
        "Persistent-session footholds: multiplexer parented by a network "
        "service, detached listeners, user-systemd units pointing to "
        "user-writable shells."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Multiplexer (tmux / screen / zellij) parented by a network service",
            "id": "digger-persistent-sessions-template",
            "description": (
                "A terminal-multiplexer process is the direct child of a "
                "network-facing service (nginx / apache / php-fpm / "
                "postgres / mysqld / redis / java / node), the textbook "
                "long-lived attacker-foothold primitive."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": ["/tmux", "/screen", "/zellij", "/dtach"],
                    "ParentImage|endswith": [
                        "/nginx", "/httpd", "/apache2", "/php-fpm",
                        "/postgres", "/postmaster", "/mysqld", "/mariadbd",
                        "/redis-server", "/mongod", "/java", "/node",
                    ],
                },
                "condition": "selection",
            },
            "level": "critical",
            "tags": ["attack.t1546", "attack.t1543.002",
                    "attack.persistence"],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        procs = _collect_processes(store)

        # ---- S1 Multiplexer parented by a network service ----
        for p in procs.values():
            base = p["base"]
            if base not in _MULTIPLEXER_NAMES:
                continue
            chain = _ancestor_chain(procs, p["pid"], depth=6)
            # chain[0] = self; look at chain[1:] for the parent service
            offending = next(
                (a for a in chain[1:] if a["base"] in _NETWORK_SERVICE_PARENTS),
                None,
            )
            if not offending:
                continue
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"{base} session (pid {p['pid']}) parented by network "
                    f"service {offending['base']} (pid {offending['pid']})"
                ),
                summary=(
                    f"A {base} session is descended from {offending['base']}, "
                    "a network-facing service. Multiplexer sessions parented "
                    "by web/db servers are the canonical long-lived-foothold "
                    "primitive: the attacker breaks out of the service "
                    "context into a detachable shell that survives every "
                    "service reload."
                ),
                artifact_refs=[p["artifact_uuid"], offending["artifact_uuid"]],
                evidence={
                    "kind": "multiplexer_under_service",
                    "multiplexer": {"pid": p["pid"], "name": base,
                                     "cmdline": p["cmdline"][:200]},
                    "service":     {"pid": offending["pid"],
                                     "name": offending["base"]},
                    "chain": [{"pid": a["pid"], "name": a["base"]}
                              for a in chain],
                },
                mitre="T1546",
            )

        # ---- S2 Detached process with open INET socket ----
        # psutil doesn't expose session leader IDs; we infer "detached" from
        # cmdline shape (nohup / setsid) + a parent that is NOT a TTY-bearing
        # shell. The cheap, useful version: cmdline starts with "nohup" or
        # "setsid", and the process holds an INET socket.
        for p in procs.values():
            cmd = p["cmdline"]
            if not cmd:
                continue
            tokens = cmd.split()
            if not tokens:
                continue
            launcher = _basename(tokens[0]).lower()
            if launcher not in ("nohup", "setsid"):
                continue
            # Any INET socket bound or connected?
            socks = [c for c in p["connections"]
                     if c.get("status") in ("ESTABLISHED", "LISTEN", "SYN_SENT")]
            if not socks:
                continue
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Detached process with network socket: pid {p['pid']} "
                    f"({p['base']})"
                ),
                summary=(
                    f"Process {p['base']} (pid {p['pid']}) was launched with "
                    f"{launcher} (detached from any TTY) and holds "
                    f"{len(socks)} INET socket(s). Detached listeners "
                    "without a parent shell are a classic phone-home / "
                    "back-channel pattern. Confirm provenance."
                ),
                artifact_refs=[p["artifact_uuid"]],
                evidence={
                    "kind": "detached_listener",
                    "pid": p["pid"], "name": p["base"],
                    "launcher": launcher,
                    "socket_count": len(socks),
                    "cmdline": cmd[:300],
                },
                mitre="T1546",
            )

        # ---- S3 user-systemd unit ExecStart in user-writable shell script ----
        for art in store.iter_artifacts(collector="linux.systemd"):
            subj = art["subject"]
            if not subj.startswith("user-unit:"):
                continue
            d = art["data"]
            text = d.get("contents") or ""
            owner_uid = d.get("owner_uid")
            unit_path = d.get("path") or "?"
            for execstart in _parse_execstart_paths(text):
                if not _is_under_user_writable(execstart):
                    continue
                shell_shebang = _has_shell_shebang(execstart)
                ownership_user = _file_owner_writable_by_user(execstart, owner_uid)
                # Either signal alone is interesting; both together is critical.
                if not (shell_shebang or ownership_user):
                    continue
                sev = "critical" if (shell_shebang and ownership_user) else "high"
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=(
                        f"user-systemd ExecStart points to user-writable "
                        f"script: {execstart}"
                    ),
                    summary=(
                        f"systemd user-unit {unit_path} has "
                        f"ExecStart={execstart}, which lives in a user-"
                        "writable directory"
                        + (" and is a shell script" if shell_shebang else "")
                        + ". User-systemd units survive every login + can "
                        "be enabled with linger to outlive logout. "
                        "Operator-installed CI agents look like this; so "
                        "do attacker implants."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "user_systemd_user_script",
                        "unit": unit_path,
                        "execstart": execstart,
                        "shell_shebang": shell_shebang,
                        "ownership_user": ownership_user,
                    },
                    mitre="T1543.002",
                )
