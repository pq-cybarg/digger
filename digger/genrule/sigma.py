"""Generate Sigma YAML rules from digger findings.

Each detector that produces findings whose features map cleanly to a
Sigma log source (process_creation, network_connection, file_event)
gets a small generator function below. The output is a Sigma rule dict
ready for ``yaml.dump`` — portable, no digger-specific fields.

Findings whose semantics don't fit Sigma (memory regions, browser
extension permissions, unsigned binaries) are skipped — the function
returns None and the caller is expected to log "no Sigma mapping for
detector X."

Rule UUIDs are deterministic: SHA-256 of the canonical finding content,
truncated to UUID shape. Re-running the generator on the same case
produces the same UUIDs.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Optional


# ---- stable UUIDs ------------------------------------------------------ #


def _stable_uuid(*parts: str) -> str:
    """Deterministic UUIDv4-shaped string from arbitrary inputs."""
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


# ---- per-detector generators ------------------------------------------ #


def _shared(finding: dict, *, case_id: str, level: str | None = None) -> dict:
    """Common Sigma rule scaffold."""
    today = time.strftime("%Y/%m/%d")
    return {
        "id":          _stable_uuid("digger", finding["detector"], finding["title"]),
        "status":      "experimental",
        "author":      "digger",
        "date":        today,
        "modified":    today,
        "references":  [f"digger-case://{case_id}/{finding['finding_uuid']}"]
                       if case_id else [],
        "level":       level or finding["severity"],
        "tags":        _tags(finding),
        "falsepositives": ["Investigate context before alerting on this rule."],
    }


def _tags(finding: dict) -> list[str]:
    tags: list[str] = []
    mitre = (finding.get("mitre") or "").strip()
    if mitre:
        # Sigma convention is lowercased with dots, e.g. "attack.t1059.001"
        m = re.match(r"^T?(\d{4}(?:\.\d{3})?)$", mitre.upper())
        if m:
            tags.append(f"attack.t{m.group(1).lower()}")
    detector = finding.get("detector", "")
    detector_tag_map = {
        "lolbins":              ["attack.defense_evasion"],
        "c2":                   ["attack.command_and_control"],
        "shai_hulud":           ["attack.initial_access", "attack.supply_chain_compromise"],
        "supply_chain":         ["attack.initial_access", "attack.supply_chain_compromise"],
        "trapdoor":             ["attack.initial_access", "attack.supply_chain_compromise"],
        "exfiltration":         ["attack.exfiltration"],
        "impact":               ["attack.impact"],
        "collection":           ["attack.collection"],
        "nightmare_eclipse":    ["attack.privilege_escalation", "attack.defense_evasion",
                                  "attack.command_and_control"],
        "telemetry_jammer":     ["attack.collection"],
        "warbird_blocker":      ["attack.execution"],
        "macos_telemetry_jammer": ["attack.collection"],
        "linux_telemetry_jammer": ["attack.collection"],
        "browser_telemetry_jammer": ["attack.collection"],
        "mini_shai_hulud":      ["attack.initial_access", "attack.supply_chain_compromise",
                                  "attack.impact", "attack.persistence"],
        "shai_hulud_blocker":   ["attack.impact", "attack.persistence",
                                  "attack.privilege_escalation"],
        "discovery":            ["attack.discovery"],
        "vect":                 ["attack.impact", "attack.t1486", "attack.t1485"],
        "info_stealer":         ["attack.credential_access", "attack.t1555.003",
                                  "attack.t1041"],
        "threat_actor":         ["attack.execution"],
        "env_hijack":           ["attack.privilege_escalation", "attack.defense_evasion"],
        "persistence_outlier": ["attack.persistence"],
        "ssh_auth_keys":        ["attack.persistence", "attack.credential_access"],
        "suspicious_processes": ["attack.execution"],
    }
    tags += detector_tag_map.get(detector, [])
    # dedup while preserving order
    seen = set()
    return [t for t in tags if not (t in seen or seen.add(t))]


def _gen_lolbins(finding: dict, *, case_id: str) -> Optional[dict]:
    ev = finding.get("evidence") or {}
    name    = (ev.get("name") or "").strip()
    cmdline = (ev.get("cmdline") or "").strip()
    if not name:
        return None
    selection: dict[str, Any] = {"Image|endswith": "\\" + name}
    # Extract the distinguishing substring from the cmdline (first ~40 chars
    # after the process name) for the CommandLine contains check.
    cmd_tail = cmdline.split(name, 1)[-1].strip() if name in cmdline else cmdline
    fragment = cmd_tail.strip()[:80]
    if fragment:
        selection["CommandLine|contains"] = fragment

    return {
        "title": f"LOLBin abuse: {name}",
        "description": (f"{finding['summary']}\n\n"
                        f"Auto-generated from digger finding "
                        f"{finding['finding_uuid']}."),
        **_shared(finding, case_id=case_id),
        "logsource": {"category": "process_creation"},
        "detection": {"selection": selection, "condition": "selection"},
    }


def _gen_suspicious_proc(finding: dict, *, case_id: str) -> Optional[dict]:
    ev = finding.get("evidence") or {}
    proc = ev.get("process") or {}
    name = (proc.get("name") or "").strip()
    parent = (ev.get("parent") or {}).get("name", "")
    cmdline = " ".join(proc.get("cmdline") or []) if proc.get("cmdline") else (ev.get("cmdline") or "")
    if not name:
        return None
    selection: dict[str, Any] = {"Image|endswith": "\\" + name}
    if parent:
        selection["ParentImage|endswith"] = "\\" + parent
    if cmdline:
        # Use the first distinctive sequence
        first_50 = cmdline.strip()[:80]
        selection["CommandLine|contains"] = first_50
    return {
        "title": f"Suspicious process pattern: {finding['title']}",
        "description": finding["summary"] +
                       f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
        **_shared(finding, case_id=case_id),
        "logsource": {"category": "process_creation"},
        "detection": {"selection": selection, "condition": "selection"},
    }


def _gen_c2(finding: dict, *, case_id: str) -> Optional[dict]:
    ev = finding.get("evidence") or {}
    pattern = ev.get("pattern")
    framework = ev.get("framework")
    url = ev.get("url") or ev.get("observed")
    ip = ev.get("ip")
    cmdline = ev.get("cmdline")

    if cmdline and pattern:
        return {
            "title": f"C2 framework signature ({framework}) in process cmdline",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|re": pattern},
                "condition": "selection",
            },
        }
    if ip:
        return {
            "title": f"Connection to C2 IP {ip}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection": {"DestinationIp": ip},
                "condition": "selection",
            },
        }
    if url:
        return {
            "title": f"Browser-history URL matches C2 pattern",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="high"),
            "logsource": {"category": "proxy"},
            "detection": {
                "selection": {"c-uri|contains": url[:120]},
                "condition": "selection",
            },
        }
    return None


def _gen_trapdoor(finding: dict, *, case_id: str) -> Optional[dict]:
    """Sigma rules for TrapDoor crypto-stealer campaign findings.

    Routes by ``evidence.ecosystem``:
      - npm / pypi / cargo    → file_event on the package manifest
      - process / network     → process_creation on the marker / domain
      - persistence           → file_event on the persistence file
      - loader_file           → file_event on trap-core.js
    """
    ev = finding.get("evidence") or {}
    ecosystem = ev.get("ecosystem") or ""
    pkg = ev.get("package") or ""
    if ecosystem == "npm" and pkg:
        name = pkg.split("@", 1)[0]
        return {
            "title": f"TrapDoor compromised npm package: {pkg}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|endswith": f"/node_modules/{name}/package.json",
                },
                "condition": "selection",
            },
        }
    if ecosystem == "pypi" and pkg:
        name = pkg.split("@", 1)[0]
        return {
            "title": f"TrapDoor compromised PyPI package: {pkg}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|contains": [
                        f"/site-packages/{name}/",
                        f"/{name}-",  # dist-info dir prefix
                    ],
                },
                "condition": "selection",
            },
        }
    if ecosystem == "cargo" and pkg:
        name = pkg.split("@", 1)[0]
        return {
            "title": f"TrapDoor compromised crates.io package: {pkg}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|contains": f"/.cargo/registry/src/index.crates.io-",
                    "TargetFilename|endswith": f"/{name}/build.rs",
                },
                "condition": "selection",
            },
        }
    if ecosystem in ("process",) and ev.get("marker"):
        return {
            "title": f"TrapDoor marker in process cmdline: {ev.get('marker')}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": ev.get("marker")},
                "condition": "selection",
            },
        }
    if ecosystem == "network" and ev.get("domain"):
        return {
            "title": f"TrapDoor exfil domain: {ev.get('domain')}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="high"),
            "logsource": {"category": "dns"},
            "detection": {
                "selection": {
                    "QueryName|contains": ev.get("domain").split("/", 1)[0],
                },
                "condition": "selection",
            },
        }
    if ecosystem == "persistence" and ev.get("path"):
        return {
            "title": f"TrapDoor persistence file modified: {ev.get('path')}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|endswith": ev.get("path"),
                },
                "filter_marker": {
                    "Contents|contains": ev.get("marker") or "",
                },
                "condition": "selection AND filter_marker",
            },
        }
    if ecosystem == "loader_file" and ev.get("path"):
        return {
            "title": f"TrapDoor loader file present: {ev.get('path')}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|endswith": "/trap-core.js",
                },
                "condition": "selection",
            },
        }
    return None


def _gen_shai_hulud(finding: dict, *, case_id: str) -> Optional[dict]:
    ev = finding.get("evidence") or {}
    pkg = ev.get("package")
    if pkg and "@" in pkg:
        name, version = pkg.split("@", 1)
        return {
            "title": f"Shai-Hulud compromised npm package: {pkg}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|endswith": "/node_modules/" + name + "/package.json",
                    "TargetFilename|contains": "/node_modules/",
                },
                "filter_version": {"TargetFilename|contains": f'"version": "{version}"'},
                "condition": "selection AND filter_version",
            },
        }
    path = ev.get("path") or ""
    if "shai-hulud" in path.lower() or "shai-hulud" in (ev.get("markers") or []):
        return {
            "title": "Shai-Hulud worm workflow artifact",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|endswith": ".github/workflows/shai-hulud-workflow.yml",
                },
                "condition": "selection",
            },
        }
    return None


def _gen_env_hijack(finding: dict, *, case_id: str) -> Optional[dict]:
    ev = finding.get("evidence") or {}
    var = ev.get("var")
    value = ev.get("value")
    if not var:
        return None
    sel: dict[str, Any] = {f"EnvironmentVariables|contains": var + "="}
    if value:
        sel["EnvironmentVariables|contains"] = f"{var}={value}"
    return {
        "title": f"Process spawned with {var} set",
        "description": finding["summary"] +
                        f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
        **_shared(finding, case_id=case_id, level="high"),
        "logsource": {"category": "process_creation"},
        "detection": {"selection": sel, "condition": "selection"},
    }


def _gen_persistence_outlier(finding: dict, *, case_id: str) -> Optional[dict]:
    ev = finding.get("evidence") or {}
    paths = ev.get("paths") or []
    match = ev.get("match")
    subject = ev.get("subject") or ""
    if not (paths or match):
        return None
    fragments = paths[:5] if paths else [match]
    return {
        "title": f"Persistence entry referencing scratch/user paths",
        "description": finding["summary"] +
                        f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
        **_shared(finding, case_id=case_id, level="high"),
        "logsource": {"category": "file_event"},
        "detection": {
            "selection": {"TargetFilename|contains": fragments},
            "condition": "selection",
        },
    }


def _gen_threat_actor(finding: dict, *, case_id: str) -> Optional[dict]:
    ev = finding.get("evidence") or {}
    pattern = ev.get("pattern")
    actor = ev.get("actor")
    cmdline = ev.get("cmdline")
    if not pattern:
        return None
    if cmdline:
        return {
            "title": f"{actor} TTP signature in process cmdline",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="high"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|re": pattern},
                "condition": "selection",
            },
        }
    return None


def _gen_recon(finding: dict, *, case_id: str) -> Optional[dict]:
    """Sigma rules for counter-recon findings.

    Kinds we emit Sigma for:
      - ssh_brute_force / ssh_user_enum / ssh_banner_grab → authentication
        log source filtering on src_ip + sshd EventID-equivalents
      - portscan / single_source_portprobe → network_connection log
        source flagging many distinct dst_port from one src_ip
    """
    ev = finding.get("evidence") or {}
    kind = ev.get("kind") or ""
    if kind in ("ssh_brute_force", "ssh_user_enum", "ssh_banner_grab",
                "ssh_preauth_disconnect"):
        ip = ev.get("remote_ip") or ""
        return {
            "title": f"Inbound SSH recon from {ip}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id,
                      level=finding.get("severity") or "medium"),
            "logsource": {"product": "linux", "service": "auth"},
            "detection": {
                "selection": {
                    "Image|endswith": "/sshd",
                    "Message|contains|all": [ip],
                },
                "condition": "selection",
            },
            "tags": [
                "attack.reconnaissance",
                "attack.t1595.001",
                "attack.t1110.001" if kind == "ssh_brute_force" else "attack.t1592.002",
            ],
        }
    if kind in ("portscan_connection_table", "single_source_portprobe"):
        top = ev.get("top_scanners") or []
        ip = ev.get("remote_ip") or (top[0]["ip"] if top else "")
        return {
            "title": f"Inbound port-scan footprint from {ip or 'multiple sources'}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id,
                      level=finding.get("severity") or "high"),
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection": {
                    "Initiated": "false",
                    "SourceIp": ip if ip else "*",
                },
                "timeframe": "5m",
                "condition": "selection | count(DestinationPort) by SourceIp > 10",
            },
            "tags": [
                "attack.reconnaissance",
                "attack.t1595.001",
            ],
        }
    return None


def _gen_exploitation(finding: dict, *, case_id: str) -> Optional[dict]:
    """Sigma rules for counter-exploitation findings."""
    ev = finding.get("evidence") or {}
    kind = ev.get("kind") or ""
    if kind == "service_to_shell":
        parent = ev.get("parent") or {}
        child = ev.get("child") or {}
        return {
            "title": f"Listening service {parent.get('name')} spawned shell {child.get('name')}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "ParentImage|endswith": f"/{parent.get('name')}",
                    "Image|endswith": [f"/{n}" for n in
                                       ("sh", "bash", "zsh", "dash", "ksh",
                                        "cmd.exe", "powershell.exe", "pwsh.exe")],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1190", "attack.initial_access"],
        }
    if kind == "rce_chain":
        chain = ev.get("chain") or []
        return {
            "title": f"RCE spawn chain: {' → '.join(c.get('name') or '?' for c in reversed(chain))}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": [f"/{n}" for n in
                                       ("sh", "bash", "zsh", "cmd.exe", "powershell.exe")],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1203", "attack.execution"],
        }
    if kind == "shellcode_cmdline":
        pattern_label = ev.get("pattern") or ""
        # Map our human-label back to a useful Sigma keyword match.
        keywords = {
            "bash reverse-shell via /dev/tcp": ["/dev/tcp/", "bash -i"],
            "python -c reverse-shell oneliner": ["import socket", "python -c"],
            "perl -e reverse-shell": ["sockaddr_in", "perl -e"],
            "ruby reverse-shell": ["TCPSocket.new", "ruby -e", "ruby -re"],
            "netcat -e command execution": ["nc -e", "ncat -e", "nc --exec"],
            "socat exec reverse-shell": ["socat", "exec:"],
            "PowerShell -EncodedCommand payload": ["-EncodedCommand", "-enc "],
            "PowerShell IEX New-Object download cradle": ["IEX ", "New-Object Net.WebClient"],
            "pipe-to-shell download cradle": ["curl ", " | sh", " | bash"],
            "wget pipe-to-shell": ["wget ", " | sh", " | bash"],
        }.get(pattern_label, [pattern_label])
        return {
            "title": f"Shellcode-shape cmdline: {pattern_label}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains|all": keywords},
                "condition": "selection",
            },
            "tags": ["attack.t1059", "attack.execution"],
        }
    if kind == "encoded_payload_cmdline":
        return {
            "title": "Long base64 blob in process command line",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="medium"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "CommandLine|re": r"[A-Za-z0-9+/]{200,}={0,2}",
                },
                "condition": "selection",
            },
            "tags": ["attack.t1027", "attack.defense_evasion"],
        }
    if kind == "weblog_exploit_pattern":
        pattern_label = ev.get("pattern") or ""
        snippet = (ev.get("snippet") or "")[:120]
        sigma_pattern = {
            "Log4Shell — JNDI lookup in user-controlled input (CVE-2021-44228)": "${jndi:",
            "Spring4Shell — classLoader manipulation (CVE-2022-22965)": "class.module.classLoader.",
            "Path traversal probe": "../",
            "Inline PHP shell upload attempt": "<?php",
            "base64-encoded PHP eval": "eval(base64_decode",
            "SQL injection probe": "UNION SELECT",
            "Shellshock-style CGI exploit (CVE-2014-6271 family)": "() {",
            "WordPress plugin enumeration / known-CVE probe": "/wp-content/plugins/",
            "Laravel Ignition RCE (CVE-2021-3129) probe": "/_ignition/execute-solution",
            "Reflected XSS probe (onerror handler)": "onerror=",
        }.get(pattern_label, pattern_label[:80])
        return {
            "title": f"Webserver log exploit pattern: {pattern_label}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id,
                      level=finding.get("severity") or "high"),
            "logsource": {"category": "webserver"},
            "detection": {
                "selection": {"cs-uri-query|contains": sigma_pattern,
                              "cs-uri-stem|contains": sigma_pattern},
                "condition": "1 of selection*",
            },
            "tags": ["attack.t1190", "attack.initial_access"],
        }
    return None


def _gen_privesc(finding: dict, *, case_id: str) -> Optional[dict]:
    """Sigma rules for privesc findings.

    Privesc artifacts are mostly file-state (setuid bits, capabilities,
    sudoers contents). They map naturally to file_event log source for
    SIEMs that have a filesystem-monitoring auditbeat / sysmon / osquery.
    Kernel-taint findings emit a process_creation rule that looks for
    insmod/modprobe.
    """
    ev = finding.get("evidence") or {}
    kind = ev.get("kind") or ""
    sev = finding.get("severity") or "high"
    if kind in ("world_writable_setuid", "setuid_in_scratch", "gtfobins_setuid",
                "setuid_offpath"):
        path = ev.get("path") or ""
        return {
            "title": f"setuid privesc primitive: {path}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level=sev),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {"TargetFilename": path,
                              "FileMode|contains": ["4000", "2000"]},
                "condition": "selection",
            },
            "tags": ["attack.t1548.001", "attack.privilege_escalation"],
        }
    if kind == "dangerous_file_capability":
        path = ev.get("path") or ""
        return {
            "title": f"Linux file capability set on {path}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level=sev),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": "/setcap",
                    "CommandLine|contains": path,
                },
                "condition": "selection",
            },
            "tags": ["attack.t1548", "attack.privilege_escalation"],
        }
    if kind == "sudoers_nopasswd_all":
        return {
            "title": "sudoers NOPASSWD: ALL clause",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level=sev),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|startswith": "/etc/sudoers",
                    "Image|endswith": ["/visudo", "/tee", "/cp", "/install", "/sed"],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1548.003", "attack.privilege_escalation"],
        }
    if kind == "kernel_taint":
        return {
            "title": "Kernel taint flags set (unsigned/out-of-tree module loaded)",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level=sev),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": ["/insmod", "/modprobe"],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1547.006", "attack.persistence"],
        }
    return None


def _gen_lateral(finding: dict, *, case_id: str) -> Optional[dict]:
    """Sigma rules for lateral-movement findings."""
    ev = finding.get("evidence") or {}
    kind = ev.get("kind") or ""
    sev = finding.get("severity") or "high"
    if kind == "lateral_outbound":
        svc = ev.get("service") or "?"
        rport = ev.get("remote_port")
        return {
            "title": f"Outbound {svc} to RFC1918 host from non-admin process",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level=sev),
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection": {
                    "Initiated": "true",
                    "DestinationPort": rport,
                    "DestinationIp|cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                },
                "condition": "selection",
            },
            "tags": ["attack.lateral_movement", "attack.t1021"],
        }
    if kind == "credential_dumper":
        tool = ev.get("tool") or ""
        return {
            "title": f"Credential-dumping tool signature: {tool}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains|all":
                                  [tool.lower().split()[0]]},
                "condition": "selection",
            },
            "tags": ["attack.t1003", "attack.credential_access"],
        }
    if kind == "lateral_toolkit":
        tool = ev.get("tool") or ""
        return {
            "title": f"Lateral toolkit running: {tool}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="high"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"Image|endswith": f"/{tool}",
                              "CommandLine|contains": tool},
                "condition": "1 of selection*",
            },
            "tags": ["attack.t1570", "attack.lateral_movement"],
        }
    if kind == "ssh_proxyjump":
        return {
            "title": "SSH ProxyJump pivot chain",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="medium"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": "/ssh",
                    "CommandLine|contains": ["-J ", "ProxyJump=",
                                              "ProxyCommand=ssh"],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1021.004", "attack.lateral_movement"],
        }
    if kind == "pass_the_hash_marker":
        return {
            "title": "Pass-the-hash Windows event 4624",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"product": "windows", "service": "security"},
            "detection": {
                "selection": {
                    "EventID": 4624,
                    "LogonType": 3,
                    "AuthenticationPackageName": "NTLM",
                },
                "filter": {
                    "WorkstationName": ["-", "", "ANONYMOUS LOGON"],
                },
                "condition": "selection and filter",
            },
            "tags": ["attack.t1550.002", "attack.lateral_movement"],
        }
    return None


def _gen_ad_attacks(finding: dict, *, case_id: str) -> Optional[dict]:
    """Sigma rules for AD-attack findings."""
    ev = finding.get("evidence") or {}
    kind = ev.get("kind") or ""
    sev = finding.get("severity") or "high"
    if kind == "kerberoast_4769":
        return {
            "title": "Kerberoasting: TGS-REQ with RC4 encryption",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"product": "windows", "service": "security"},
            "detection": {
                "selection": {
                    "EventID": 4769,
                    "TicketEncryptionType": "0x17",
                },
                "filter": {"ServiceName|startswith": "krbtgt"},
                "condition": "selection and not filter",
            },
            "tags": ["attack.t1558.003", "attack.credential_access"],
        }
    if kind == "asrep_roast_candidate":
        return {
            "title": "AS-REP roast: TGT request without preauth",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="high"),
            "logsource": {"product": "windows", "service": "security"},
            "detection": {
                "selection": {
                    "EventID": 4768,
                    "PreAuthType": "0",
                },
                "condition": "selection",
            },
            "tags": ["attack.t1558.004", "attack.credential_access"],
        }
    if kind == "dcsync_4662":
        return {
            "title": "DCSync replication-rights access",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"product": "windows", "service": "security"},
            "detection": {
                "selection": {
                    "EventID": 4662,
                    "Properties|contains": ev.get("replication_guid") or "",
                },
                "condition": "selection",
            },
            "tags": ["attack.t1003.006", "attack.credential_access"],
        }
    if kind == "adminsdholder_modified":
        return {
            "title": "AdminSDHolder ACL modified",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"product": "windows", "service": "security"},
            "detection": {
                "selection": {
                    "EventID": 5136,
                    "ObjectDN|contains": "AdminSDHolder",
                },
                "condition": "selection",
            },
            "tags": ["attack.t1484.001", "attack.persistence",
                    "attack.privilege_escalation"],
        }
    if kind == "bloodhound_family":
        tool = ev.get("tool") or ""
        return {
            "title": f"AD graph-recon tool: {tool}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="high"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": [f"\\{tool}", f"/{tool}"],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1087.002", "attack.discovery"],
        }
    if kind == "ad_attack_cmdline":
        pattern = ev.get("pattern") or ""
        return {
            "title": f"AD-attack tradecraft cmdline: {pattern}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "CommandLine|contains": pattern.lower().split()[0],
                },
                "condition": "selection",
            },
            "tags": ["attack.credential_access",
                    "attack." + (finding.get("evidence") or {})
                        .get("mitre", "t1003").lower().replace(".", "_") if False else "attack.t1003"],
        }
    return None


def _gen_cloud_attacks(finding: dict, *, case_id: str) -> Optional[dict]:
    """Sigma rules for cloud-attack findings."""
    ev = finding.get("evidence") or {}
    kind = ev.get("kind") or ""
    sev = finding.get("severity") or "high"
    if kind in ("imds_unusual_process", "imds_cmdline_reference"):
        return {
            "title": "Cloud IMDS endpoint accessed by unusual process",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection": {
                    "DestinationIp": ["169.254.169.254", "fd00:ec2::254"],
                },
                "filter": {
                    "Image|endswith": [
                        "/aws", "/aws-cli", "/cloud-init", "/cloud-init-local",
                        "/ssm-agent", "/amazon-ssm-agent",
                        "/google_guest_agent", "/google-metadata-script",
                        "/kubelet", "/containerd", "/dockerd",
                    ],
                },
                "condition": "selection and not filter",
            },
            "tags": ["attack.t1552.005", "attack.credential_access"],
        }
    if kind == "cloud_creds_in_shell_env":
        return {
            "title": "Shell process inherited cloud credentials env vars",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="high"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": [f"/{s}" for s in
                                       ("bash", "sh", "zsh", "powershell.exe",
                                        "pwsh.exe", "cmd.exe")],
                    "ParentImage|contains": ["AWS_ACCESS_KEY_ID",
                                              "AZURE_CLIENT_SECRET",
                                              "GOOGLE_APPLICATION_CREDENTIALS"],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1552.001", "attack.credential_access"],
        }
    if kind == "container_escape_primitive":
        pattern = ev.get("pattern") or ""
        return {
            "title": f"Container-escape primitive: {pattern}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": pattern.lower().split()[0]},
                "condition": "selection",
            },
            "tags": ["attack.t1611", "attack.privilege_escalation"],
        }
    if kind == "kubeconfig_theft":
        return {
            "title": "Kubeconfig read by non-kube client",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="critical"),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|endswith": [
                        "/.kube/config", "/admin.conf",
                        "/var/lib/kubelet/kubeconfig",
                    ],
                },
                "filter": {
                    "Image|endswith": [f"/{n}" for n in
                                       ("kubectl", "kubelet", "helm",
                                        "kustomize", "k9s", "kubeadm")],
                },
                "condition": "selection and not filter",
            },
            "tags": ["attack.t1552.001", "attack.credential_access"],
        }
    if kind == "cloud_cli_privesc":
        pattern = ev.get("pattern") or ""
        return {
            "title": f"Cloud CLI privesc-relevant command: {pattern}",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="medium"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "CommandLine|contains": pattern.split()[0],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1098", "attack.persistence"],
        }
    if kind == "cloud_creds_file_perms":
        return {
            "title": "Cloud credentials file is group/world-readable",
            "description": finding["summary"] +
                            f"\n\nAuto-generated from digger finding {finding['finding_uuid']}.",
            **_shared(finding, case_id=case_id, level="high"),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|contains": ev.get("path") or "",
                },
                "condition": "selection",
            },
            "tags": ["attack.t1552.001"],
        }
    return None


_GENERATORS = {
    "lolbins":              _gen_lolbins,
    "suspicious_processes": _gen_suspicious_proc,
    "c2":                   _gen_c2,
    "shai_hulud":           _gen_shai_hulud,
    "trapdoor":             _gen_trapdoor,
    "nightmare_eclipse":    lambda f, *, case_id: {
        "title": f["title"],
        "description": f["summary"] +
                        f"\n\nAuto-generated from digger finding {f['finding_uuid']}.",
        **_shared(f, case_id=case_id, level=f.get("severity") or "critical"),
        "logsource": (
            {"category": "file_event"}
            if (f.get("evidence") or {}).get("kind") in ("filename", "hash")
                and (f.get("evidence") or {}).get("path")
            else {"category": "network_connection"}
            if (f.get("evidence") or {}).get("kind") == "c2"
                and (f.get("evidence") or {}).get("remote_ip")
            else {"category": "process_creation"}
        ),
        "detection": {
            "selection": (
                {"TargetFilename|endswith":
                      "\\" + ((f.get("evidence") or {}).get("basename") or "")}
                if (f.get("evidence") or {}).get("kind") == "filename"
                else {"Hashes|contains":
                          (f.get("evidence") or {}).get("hash") or ""}
                if (f.get("evidence") or {}).get("kind") == "hash"
                else {"DestinationIp":
                          (f.get("evidence") or {}).get("remote_ip") or ""}
                if (f.get("evidence") or {}).get("kind") == "c2"
                    and (f.get("evidence") or {}).get("remote_ip")
                else {"CommandLine|contains":
                          (f.get("evidence") or {}).get("domain") or ""}
                if (f.get("evidence") or {}).get("kind") == "c2"
                    and (f.get("evidence") or {}).get("domain")
                else {"CommandLine|contains":
                          (f.get("evidence") or {}).get("quarantine_name") or ""}
                if (f.get("evidence") or {}).get("kind") == "defender_quarantine"
                else {"CommandLine|re":
                          r"agent\.exe\s+-server\s+\S+:443\s+-hide"}
                if (f.get("evidence") or {}).get("signature") == "beigeburrow_tunnel"
                else {"CommandLine|contains":
                          (f.get("evidence") or {}).get("exploit") or ""}
            ),
            "condition": "selection",
        },
        "tags": [
            "attack.privilege_escalation", "attack.defense_evasion",
            "attack.t1068", "attack.t1562.001", "attack.t1572",
        ],
    },
    "collection":           lambda f, *, case_id: {
        "title": f["title"],
        "description": f["summary"] +
                        f"\n\nAuto-generated from digger finding {f['finding_uuid']}.",
        **_shared(f, case_id=case_id, level=f.get("severity") or "high"),
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"CommandLine|contains":
                              ((f.get("evidence") or {}).get("pattern") or "")
                              .split(" ")[0:2]},
            "condition": "selection",
        },
        "tags": ["attack.collection", "attack.t1056"],
    },
    "impact":               lambda f, *, case_id: (
        {
            "title": f["title"],
            "description": f["summary"] +
                            f"\n\nAuto-generated from digger finding {f['finding_uuid']}.",
            **_shared(f, case_id=case_id, level=f.get("severity") or "high"),
            "logsource": (
                {"category": "file_event"}
                if (f.get("evidence") or {}).get("kind") in
                    ("ransom_note_file", "mass_rename")
                else {"category": "process_creation"}
            ),
            "detection": {
                "selection": (
                    {"TargetFilename|endswith":
                          (f.get("evidence") or {}).get("basename") or ""}
                    if (f.get("evidence") or {}).get("kind") == "ransom_note_file"
                    else {"TargetFilename|endswith":
                              (f.get("evidence") or {}).get("extension") or ""}
                    if (f.get("evidence") or {}).get("kind") == "mass_rename"
                    else {"CommandLine|contains":
                              ((f.get("evidence") or {}).get("pattern") or "")
                              .split(" ")[0:2]}
                ),
                "condition": "selection",
            },
            "tags": ["attack.impact", "attack.t1486", "attack.t1490"],
        }
    ),
    "exfiltration":         lambda f, *, case_id: (
        {
            "title": f["title"],
            "description": f["summary"] +
                            f"\n\nAuto-generated from digger finding {f['finding_uuid']}.",
            **_shared(f, case_id=case_id, level=f.get("severity") or "high"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": (
                    {"CommandLine|re":
                         r"(?:tar|zip|7z|gzip|xz)[^|]*\|[^|]*(?:curl|wget|nc|ncat|socat)"}
                    if (f.get("evidence") or {}).get("kind") == "archive_pipe"
                    else {"CommandLine|contains":
                              (f.get("evidence") or {}).get("domain") or ""}
                    if (f.get("evidence") or {}).get("kind") == "web_service_exfil"
                    else {"CommandLine|contains":
                              (f.get("evidence") or {}).get("pattern", "").split(" ")[0]}
                    if (f.get("evidence") or {}).get("kind") in
                        ("cloud_bucket_exfil", "protocol_tunnel")
                    else {"CommandLine|re":
                              r"(?:/\.ssh/|/\.aws/credentials|/etc/shadow|/\.kube/config)"
                              r"[^|]*(?:curl|wget|nc\b|-Method\s+POST)"}
                    if (f.get("evidence") or {}).get("kind") == "sensitive_post"
                    else {"CommandLine|re":
                              r"\b[A-Z2-7]{40,63}\.[A-Z2-7]{40,63}\b"}
                ),
                "condition": "selection",
            },
            "tags": ["attack.exfiltration", "attack.t1041", "attack.t1567"],
        }
    ),
    "env_hijack":           _gen_env_hijack,
    "persistence_outlier": _gen_persistence_outlier,
    "threat_actor":         _gen_threat_actor,
    "recon":                _gen_recon,
    "exploitation":         _gen_exploitation,
    "privesc":              _gen_privesc,
    "lateral":              _gen_lateral,
    "ad_attacks":           _gen_ad_attacks,
    "cloud_attacks":        _gen_cloud_attacks,
    "anti_forensics":       lambda f, *, case_id: {
        "title": f["title"],
        "description": f["summary"] +
                        f"\n\nAuto-generated from digger finding {f['finding_uuid']}.",
        **_shared(f, case_id=case_id, level=f.get("severity") or "high"),
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": (
                {"CommandLine|contains":
                    ((f.get("evidence") or {}).get("pattern") or "")
                    .split(" ")[0:1] or [""]}
                if (f.get("evidence") or {}).get("kind") == "anti_forensics_cmdline"
                else {"TargetFilename|endswith":
                        [".bash_history", ".zsh_history"]}
            ),
            "condition": "selection",
        },
        "tags": ["attack.t1070", "attack.defense_evasion"],
    },
    "attacker_tooling":     lambda f, *, case_id: {
        "title": f["title"],
        "description": f["summary"] +
                        f"\n\nAuto-generated from digger finding {f['finding_uuid']}.",
        **_shared(f, case_id=case_id, level=f.get("severity") or "high"),
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": [
                    f"/{(f.get('evidence') or {}).get('tool') or ''}"
                ],
            },
            "condition": "selection",
        },
        "tags": ["attack.t1588.002", "attack.resource_development"],
    },
    "persistent_sessions":  lambda f, *, case_id: (
        {
            "title": f["title"],
            "description": f["summary"] +
                            f"\n\nAuto-generated from digger finding {f['finding_uuid']}.",
            **_shared(f, case_id=case_id, level=f.get("severity") or "high"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": [
                        "/tmux", "/screen", "/zellij", "/dtach",
                    ],
                    "ParentImage|endswith": [
                        "/nginx", "/httpd", "/apache2",
                        "/php-fpm", "/php-fpm8.1", "/php-fpm8.2", "/php-fpm8.3",
                        "/postgres", "/postmaster",
                        "/mysqld", "/mariadbd",
                        "/redis-server", "/mongod", "/java", "/node",
                    ],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1546", "attack.persistence"],
        } if (f.get("evidence") or {}).get("kind") == "multiplexer_under_service"
        else {
            "title": f["title"],
            "description": f["summary"] +
                            f"\n\nAuto-generated from digger finding {f['finding_uuid']}.",
            **_shared(f, case_id=case_id, level=f.get("severity") or "high"),
            "logsource": {"category": "file_event"},
            "detection": {
                "selection": {
                    "TargetFilename|contains": "/.config/systemd/user/",
                    "TargetFilename|endswith": ".service",
                },
                "condition": "selection",
            },
            "tags": ["attack.t1543.002", "attack.persistence"],
        } if (f.get("evidence") or {}).get("kind") == "user_systemd_user_script"
        else {
            "title": f["title"],
            "description": f["summary"] +
                            f"\n\nAuto-generated from digger finding {f['finding_uuid']}.",
            **_shared(f, case_id=case_id, level=f.get("severity") or "medium"),
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": ["/nohup", "/setsid"],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1546", "attack.persistence"],
        }
    ),
    "counter_re":           lambda f, *, case_id: {
        "title": f["title"],
        "description": f["summary"] +
                        f"\n\nAuto-generated from digger finding {f['finding_uuid']}.",
        **_shared(f, case_id=case_id, level=f.get("severity") or "high"),
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": [
                    "/gdb", "/lldb", "/dtrace", "/strace", "/ltrace",
                    "/x64dbg.exe", "/x32dbg.exe",
                    "/ida.exe", "/ida64.exe", "/idaq64.exe",
                    "/ghidraRun", "/ghidraRun.bat",
                    "/radare2", "/r2", "/rizin",
                    "/frida", "/frida-server",
                    "/windbg.exe", "/cdb.exe",
                ],
                "CommandLine|re": r"(?:-p|--pid|attach|-P)\s+\d+",
            },
            "condition": "selection",
        },
        "tags": ["attack.t1622", "attack.defense_evasion"],
    },
}


# ---- public API -------------------------------------------------------- #


def finding_to_sigma(finding: dict, *, case_id: str = "") -> Optional[dict]:
    """Translate one finding to a Sigma rule dict, or None if no mapping exists."""
    detector = finding.get("detector")
    gen = _GENERATORS.get(detector)
    if gen is None:
        return None
    try:
        return gen(finding, case_id=case_id)
    except Exception:
        return None


def generate_sigma_rules(findings: Iterable[dict], *, case_id: str = "") -> list[dict]:
    out: list[dict] = []
    for f in findings:
        rule = finding_to_sigma(f, case_id=case_id)
        if rule:
            out.append(rule)
    return out


def generate_detector_templates() -> list[dict]:
    """Collect every Detector's class-level Sigma template (one per detector
    that implements ``to_sigma_template()``)."""
    from digger.detectors import all_detectors
    out: list[dict] = []
    for det in all_detectors():
        try:
            rule = det.to_sigma_template()
        except Exception:
            continue
        if not rule or not isinstance(rule, dict):
            continue
        # Ensure mandatory fields
        rule.setdefault("status", "experimental")
        rule.setdefault("author", "digger")
        rule.setdefault("level", "medium")
        rule.setdefault("id", f"digger-{det.name}-template")
        out.append(rule)
    return out


def write_sigma_rules(rules: list[dict], out_dir: Path | str) -> list[Path]:
    """Dump each rule to its own .yml under ``out_dir``. Returns written paths."""
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError("write_sigma_rules needs pyyaml") from exc
    out_dir = Path(out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for rule in rules:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", rule.get("title", "rule"))[:80]
        path = out_dir / f"{rule['id']}_{safe}.yml"
        path.write_text(
            yaml.safe_dump(rule, sort_keys=False, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )
        written.append(path)
    return written
