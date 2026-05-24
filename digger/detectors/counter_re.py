"""Counter-RE-on-us: detect debuggers / instrumentation pointed at digger
or other defender processes.

Two data sources:

  1. **Live-process probe** via :func:`digger.opsec.watchers.find_debuggers_targeting`
     — at scan time, iterate all running processes; flag any debugger /
     RE tool (gdb / lldb / dtrace / x64dbg / IDA / radare2 / frida / WinDbg)
     whose argv carries a target-PID that maps to a digger process or a
     known EDR/audit process. This is the "active right now" signal.

  2. **Collected-artifact mine** of the ``processes`` artifacts already
     in the evidence store — same logic applied to historical command
     lines so a debugger that was attached during the previous collect
     run is still surfaced after the fact.

P5 (audit-visible) of the ethics contract requires that digger never
quietly suppress its own findings; when the *target* of the debugger is
digger itself, we emit the finding with a self-attribution note so the
analyst sees "yes, digger is being inspected" rather than "huh, nothing
to see."

MITRE: T1622 (Debugger Evasion / debugger detection),
T1057 (Process Discovery).
"""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector
from digger.opsec.self_id import identify
from digger.opsec.watchers import (
    _DEBUGGER_TARGET_PID_PATTERNS, _NAMES,
    TargetedDebuggerHit, find_debuggers_targeting,
)


_DEBUGGER_NAMES_LOWER = {n.lower() for n in _NAMES["debugger"]}


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


def _extract_target_pids(cmdline: str) -> set[int]:
    out: set[int] = set()
    for rx in _DEBUGGER_TARGET_PID_PATTERNS:
        for m in rx.finditer(cmdline):
            try:
                out.add(int(m.group(1)))
            except (TypeError, ValueError):
                continue
    return out


def _looks_like_debugger(name: str) -> bool:
    n = (name or "").lower()
    if not n:
        return False
    if n in _DEBUGGER_NAMES_LOWER:
        return True
    for needle in _DEBUGGER_NAMES_LOWER:
        if n.startswith(needle + ".") or needle in n:
            return True
    return False


class CounterREDetector(Detector):
    name = "counter_re"
    description = (
        "Counter-RE-on-us: debuggers / RE tools pointed at digger or other "
        "defender processes."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Debugger / RE tool attached to defender process",
            "id": "digger-counter-re-template",
            "description": (
                "A debugger (gdb / lldb / dtrace / strace / x64dbg / IDA / "
                "Ghidra / radare2 / frida / WindBg) is launched with a "
                "target-PID argument. SIEM-side this needs further "
                "correlation against the target PID's process identity to "
                "decide whether the target is a defender process."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": [
                        "/gdb", "/lldb", "/dtrace", "/strace", "/ltrace",
                        "/x64dbg.exe", "/x32dbg.exe",
                        "/ida.exe", "/ida64.exe", "/idaq64.exe",
                        "/ghidraRun", "/radare2", "/r2", "/rizin",
                        "/frida", "/frida-server",
                        "/windbg.exe", "/cdb.exe",
                    ],
                    "CommandLine|re": r"(?:-p|--pid|attach|-P)\s+\d+",
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": ["attack.t1622", "attack.t1057",
                    "attack.defense_evasion", "attack.discovery"],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- 1. Live probe via watchers ----
        try:
            hits: list[TargetedDebuggerHit] = find_debuggers_targeting()
        except Exception:
            hits = []
        for h in hits:
            self_note = ""
            sev = "high"
            if h.target_category == "self":
                self_note = (
                    " (target is digger itself — this may be the operator's "
                    "own debugging session; if not, someone is reverse-"
                    "engineering the investigation in flight)"
                )
            elif h.target_category == "edr":
                sev = "critical"
            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"{h.debugger_name} (pid {h.debugger_pid}) attached to "
                    f"{h.target_name or 'pid'} {h.target_pid}{self_note}"
                ),
                summary=(
                    f"Debugger {h.debugger_name} (pid {h.debugger_pid}) was "
                    f"observed with target-PID argument {h.target_pid} in its "
                    "command line. Active debugging of a defender process is "
                    "a counter-forensics primitive — it lets the operator "
                    "intercept syscalls, read decrypted buffers, or patch "
                    "behavior live. Confirm authorship of the debugger "
                    "session."
                ),
                artifact_refs=[],
                evidence={
                    "kind": "live_debugger_attach",
                    "debugger": {"pid": h.debugger_pid,
                                  "name": h.debugger_name,
                                  "cmdline": h.debugger_cmdline},
                    "target":   {"pid": h.target_pid,
                                  "name": h.target_name,
                                  "category": h.target_category},
                    "self_attribution": h.target_category == "self",
                },
                mitre="T1622",
            )

        # ---- 2. Collected-artifact mine: historical debugger cmdlines ----
        # Build a quick map of stored-process pid -> identification.
        pid_to_data: dict[int, dict] = {}
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"]
            pid = d.get("pid")
            if pid is not None:
                pid_to_data[pid] = d

        for art in store.iter_artifacts(collector="processes"):
            d = art["data"]
            pid = d.get("pid")
            name = (d.get("name") or "").lower()
            exe = d.get("exe") or ""
            base = (_basename(exe) or name).lower()
            cmd = _cmdline_str(d.get("cmdline"))
            if not _looks_like_debugger(base):
                continue
            targets = _extract_target_pids(cmd)
            if not targets:
                continue
            for tpid in targets:
                target_data = pid_to_data.get(tpid, {})
                target_name = (target_data.get("name") or "").lower()
                self_hit = bool(identify(target_data)) if target_data else False
                # If we have no data for the target, see if its NAME (when known
                # from cmdline shape) looks like a defender process.
                edr_hit = False
                if target_name:
                    # Reuse the watcher classifier
                    from digger.opsec.watchers import _classify as _watcher_classify
                    cat = _watcher_classify(target_name)
                    if cat in ("edr", "audit"):
                        edr_hit = True
                if not (self_hit or edr_hit):
                    continue
                sev = "critical" if edr_hit else "high"
                self_note = (
                    f"\n\nTarget pid {tpid} identifies as: "
                    f"{identify(target_data)}" if self_hit else ""
                )
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=(
                        f"{base} (pid {pid}) attached to "
                        f"{'digger' if self_hit else target_name or 'pid'} {tpid}"
                    ),
                    summary=(
                        f"Process artifact for {base} (pid {pid}) shows a "
                        f"debugger cmdline with target-pid {tpid}. "
                        + ("The target is a digger process — counter-RE on "
                           "the investigation tool itself."
                           if self_hit else
                           "The target is a defender / audit process — "
                           "an attacker hooking the EDR is the textbook "
                           "evasion primitive.")
                        + self_note
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "stored_debugger_attach",
                        "debugger": {"pid": pid, "name": base,
                                      "cmdline": cmd[:400]},
                        "target":   {"pid": tpid, "name": target_name or "?",
                                      "is_digger": self_hit,
                                      "is_edr": edr_hit},
                        "self_attribution": self_hit,
                    },
                    mitre="T1622",
                )
