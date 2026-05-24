"""Counter-surveillance: who is watching the investigation right now?

Forensic investigators sometimes run on hosts that *they* might be the
target of (live-response on a compromised endpoint; engagement against
an adversary who may have anti-forensic tooling). This module enumerates
processes whose presence implies someone or something is observing
digger or the host:

  * Active debuggers: gdb, lldb, dtrace, strace, ltrace
  * ptrace attached: a process whose PID is in TracerPid of /proc/self/status
  * Packet captures: tcpdump, tshark, wireshark, Wireshark.app
  * Endpoint security agents: CrowdStrike, SentinelOne, Carbon Black,
    Cylance, Defender ATP / MDE, Velociraptor, osquery, Sysmon
  * Audit listeners: auditd, auditbeat, splunkd, sysmon.exe
  * Screen/keystroke recorders: Loom, OBS, ScreenFlow, Snagit
  * Accessibility / TCC consumers (macOS) that hold AXIsProcessTrustedWithOptions
  * eBPF programs attached (Linux): bpftool prog list parsing

Output is a list of Watcher dicts with severity hint. Nothing is killed
or modified — discovery only.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

import psutil


@dataclass
class Watcher:
    pid: int | None
    name: str
    category: str             # debugger | packet_capture | edr | audit | recorder | ebpf | tcc
    severity: str             # info | low | medium | high
    cmdline: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---- name patterns ---- #


_NAMES = {
    "debugger": {
        # Source-level / dynamic debuggers + tracers
        "gdb", "lldb", "lldb-server", "dlv", "delve",
        "strace", "ltrace", "dtrace", "rr", "dtruss",
        # Reverse-engineering UI debuggers (Windows + cross-platform)
        "x64dbg", "x64dbg.exe", "x32dbg", "x32dbg.exe",
        "ida", "ida.exe", "ida64", "ida64.exe", "idaq", "idaq.exe",
        "idaq64", "idaq64.exe", "ida-pro", "idapro",
        "ghidra", "ghidra.bat", "ghidrarun", "ghidrarun.bat",
        "hopper", "hopperv4", "Hopper Disassembler",
        # Console/CLI RE tools
        "radare2", "r2", "rabin2", "rasm2", "rax2",
        "rizin", "rz",
        # Dynamic instrumentation
        "frida", "frida-server", "frida-cli", "frida-trace",
        "frida-discover", "frida-ls-devices",
        "windbg", "windbg.exe", "windbgx", "cdb", "cdb.exe",
        # Cheat Engine + game-hacking debuggers — relevant if seen against
        # a defender process
        "cheatengine-x86_64.exe", "cheatengine.exe",
        # Apple/iOS RE
        "fridump", "objection",
    },
    "packet_capture": {
        "tcpdump", "tshark", "wireshark", "wireshark-gtk",
        "dumpcap", "ngrep", "Wireshark", "Wireshark.app",
    },
    "edr": {
        # macOS / cross-platform EDR/AV agents
        "falconctl", "falcon-sensor", "Falcon", "CrowdStrike",
        "SentinelAgent", "SentinelOne", "sentineld",
        "carbonblack", "cb-defense-sensor", "cbsensord",
        "Microsoft Defender", "wdav", "wdavdaemon", "defender",
        "ESETService", "ESET",
        "kaspersky", "kav", "klnagent",
        "sophos", "SophosAntiVirusService",
        "trend micro", "tmccsf", "iCoreService",
        "velociraptor", "Velociraptor",
        "osqueryd", "osquery", "osqueryi",
        "Sysmon", "sysmon", "sysmon64.exe",
    },
    "audit": {
        "auditd", "auditbeat", "filebeat", "metricbeat",
        "splunkd", "splunk", "splunk-forwarder",
        "rsyslogd", "syslog-ng",
    },
    "recorder": {
        "OBS", "obs", "Loom", "loom", "ScreenFlow",
        "ScreenSearchd", "screencapture", "screenshotr",
        "QuickTime Player", "Snagit", "Camtasia",
    },
}


_DETAIL: dict[str, tuple[str, str]] = {
    "debugger":       ("high",   "an active debugger / tracer"),
    "packet_capture": ("high",   "live packet capture — every byte digger sends is being recorded"),
    "edr":            ("medium", "endpoint security agent — its telemetry pipeline will see digger's activity"),
    "audit":          ("low",    "audit / log shipper — collection events likely forwarded off-host"),
    "recorder":       ("medium", "screen / keystroke recorder — UI activity may be captured"),
    "ebpf":           ("medium", "active eBPF program attached"),
    "tcc":            ("low",    "TCC-trusted process (accessibility / screen recording permission)"),
}


def _classify(proc_name: str) -> str | None:
    lname = (proc_name or "").lower()
    for category, names in _NAMES.items():
        for needle in names:
            n_low = needle.lower()
            if lname == n_low or lname.startswith(n_low + ".") or n_low in lname:
                return category
    return None


def _ptrace_attacher_linux() -> int | None:
    """Read /proc/self/status to see if anyone is currently ptrace-attached to us."""
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    tpid = int(line.split()[1])
                    return tpid if tpid > 0 else None
    except (FileNotFoundError, OSError, ValueError):
        return None
    return None


def _ebpf_programs_linux() -> list[Watcher]:
    """bpftool prog list — if available — produces attached programs.

    A program being loaded does not imply it is observing digger
    specifically, but its presence is worth surfacing in a counter-
    surveillance review."""
    if not shutil.which("bpftool"):
        return []
    try:
        out = subprocess.run(
            ["bpftool", "prog", "list", "-j"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout
    except Exception:
        return []
    if not out.strip():
        return []
    try:
        import json
        progs = json.loads(out)
    except Exception:
        return []
    watchers: list[Watcher] = []
    for p in progs:
        watchers.append(Watcher(
            pid=None,
            name=p.get("name") or f"bpf-prog-{p.get('id', '?')}",
            category="ebpf",
            severity="medium",
            cmdline=f"type={p.get('type','?')}  attached={p.get('attached','?')}",
            note=_DETAIL["ebpf"][1],
        ))
    return watchers


def _macos_tcc_screen_recording() -> list[Watcher]:
    """Best-effort: enumerate TCC entries for kTCCServiceScreenCapture."""
    db = Path("/Library/Application Support/com.apple.TCC/TCC.db")
    if not db.exists():
        return []
    try:
        import sqlite3
        uri = f"file:{db}?immutable=1&mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            rows = conn.execute(
                "SELECT client, auth_value FROM access "
                "WHERE service = 'kTCCServiceScreenCapture' AND auth_value > 0"
            ).fetchall()
    except sqlite3.Error:
        return []
    return [
        Watcher(pid=None, name=client, category="tcc",
                severity="low" if auth >= 2 else "info",
                cmdline=f"auth_value={auth}",
                note="has TCC permission to record the screen")
        for client, auth in rows
    ]


# ---- main entry point ---- #


def find_watchers(include_ebpf: bool = True, include_tcc: bool = True) -> list[Watcher]:
    """Enumerate processes likely to be observing the investigation."""
    watchers: list[Watcher] = []
    my_pid = os.getpid()

    # 1. ptrace check on Linux
    tpid = _ptrace_attacher_linux()
    if tpid:
        try:
            tracer = psutil.Process(tpid)
            watchers.append(Watcher(
                pid=tpid,
                name=tracer.name(),
                category="debugger",
                severity="high",
                cmdline=" ".join(tracer.cmdline())[:200],
                note=f"ptrace-attached to digger (pid {my_pid})",
            ))
        except psutil.NoSuchProcess:
            pass

    # 2. classify every running process
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline", "exe"]):
        try:
            info = proc.info
            if info["pid"] == my_pid:
                continue
            category = _classify(info["name"] or "")
            if not category:
                continue
            sev, note = _DETAIL.get(category, ("low", ""))
            watchers.append(Watcher(
                pid=info["pid"],
                name=info["name"],
                category=category,
                severity=sev,
                cmdline=" ".join(info.get("cmdline") or [])[:200],
                note=note,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 3. eBPF (Linux)
    if include_ebpf:
        watchers.extend(_ebpf_programs_linux())

    # 4. macOS TCC (best-effort)
    if include_tcc:
        try:
            watchers.extend(_macos_tcc_screen_recording())
        except Exception:
            pass

    # de-dupe (same pid, same category)
    seen = set()
    unique: list[Watcher] = []
    for w in watchers:
        key = (w.pid, w.category, w.name)
        if key in seen:
            continue
        seen.add(key)
        unique.append(w)
    return unique


# ---- Targeted-debugger detection (#60: counter-RE-on-us) ---- #


# Patterns for extracting a target PID from a debugger argv.
# All are case-insensitive and applied to the joined argv string.
_DEBUGGER_TARGET_PID_PATTERNS = [
    # gdb / lldb / windbg / cdb common form: -p <pid> or --pid <pid>
    re.compile(r"(?:^|\s)(?:-p|--pid)\s+(\d+)\b", re.I),
    # lldb form: --attach-pid <pid>
    re.compile(r"--attach-pid\s+(\d+)\b", re.I),
    # gdb form: attach <pid> inside cmdline
    re.compile(r"\battach\s+(\d+)\b", re.I),
    # strace / ltrace: -p <pid> (already covered) plus shorthand
    # dtrace: -p <pid> (covered)
    # frida: -p <pid> or frida -n NAME -p PID
    re.compile(r"(?:^|\s)-n\s+(\d+)\b", re.I),
    # x64dbg / windbg open-by-pid: --pidPID or -pid:NNN
    re.compile(r"-pid[:=]?(\d+)\b", re.I),
    # IDA: -P<pid>
    re.compile(r"(?:^|\s)-P(\d+)\b"),
]


def _extract_target_pids(cmdline: str) -> set[int]:
    """Find numeric PID arguments inside a debugger cmdline."""
    out: set[int] = set()
    for rx in _DEBUGGER_TARGET_PID_PATTERNS:
        for m in rx.finditer(cmdline):
            try:
                out.add(int(m.group(1)))
            except (TypeError, ValueError):
                continue
    return out


@dataclass
class TargetedDebuggerHit:
    debugger_pid: int
    debugger_name: str
    debugger_cmdline: str
    target_pid: int
    target_name: str
    target_category: str   # "self" | "edr" | "other"


def _category_for_pid(pid: int) -> tuple[str, str]:
    """Return (category, name) for ``pid``: 'self' if it's a digger PID,
    'edr' if it's a known EDR/AV/audit process, 'other' otherwise."""
    try:
        proc = psutil.Process(pid)
        name = proc.name() or ""
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "other", ""
    # self?
    try:
        from digger.opsec.self_id import digger_self_pids
        if pid in digger_self_pids():
            return "self", name
    except Exception:
        pass
    # EDR / audit?
    cat = _classify(name)
    if cat in ("edr", "audit"):
        return "edr", name
    return "other", name


def find_debuggers_targeting(extra_target_pids: list[int] | None = None
                              ) -> list[TargetedDebuggerHit]:
    """Enumerate running debugger processes whose argv references a target
    PID belonging to digger itself, an EDR/audit process, or a caller-
    supplied list.

    This is the counter-RE-on-us signal: someone is actively pointing
    lldb / gdb / x64dbg / IDA / frida at a defender process.
    """
    extra = set(extra_target_pids or [])
    out: list[TargetedDebuggerHit] = []
    debugger_names = _NAMES["debugger"]
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            info = proc.info
            if not info.get("name"):
                continue
            lname = info["name"].lower()
            if not any(lname == n or lname.startswith(n + ".") or n in lname
                       for n in debugger_names):
                continue
            cmd = " ".join(info.get("cmdline") or [])
            for tpid in _extract_target_pids(cmd):
                cat, tname = _category_for_pid(tpid)
                if cat == "other" and tpid not in extra:
                    continue
                if tpid in extra and cat == "other":
                    cat = "explicit"
                out.append(TargetedDebuggerHit(
                    debugger_pid=info["pid"],
                    debugger_name=info["name"],
                    debugger_cmdline=cmd[:400],
                    target_pid=tpid,
                    target_name=tname,
                    target_category=cat,
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out
