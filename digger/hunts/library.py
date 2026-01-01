"""Bundled threat-hunting queries.

Each hunt is a thin function that iterates the evidence store and yields
rows. They're meant to be quick, composable, and tolerant of false
positives — analysts use them as a starting point, not as an alert source.
"""

from __future__ import annotations

import ipaddress
import math
import re
import time
from typing import Iterable

from digger.core.evidence import EvidenceStore
from digger.hunts.base import Hunt, register


# ---- small helpers ---- #


def _shell_name(name: str) -> bool:
    return (name or "").lower() in {
        "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh",
        "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh",
    }


def _browser_name(name: str) -> bool:
    return (name or "").lower() in {
        "chrome", "chrome.exe", "google chrome", "msedge.exe",
        "firefox", "firefox-bin", "safari", "brave", "brave-browser",
        "arc", "vivaldi",
    }


def _interpreter_name(name: str) -> bool:
    return (name or "").lower() in {
        "python", "python2", "python3",
        "perl", "ruby", "node", "java", "lua", "tcl",
        "python.exe", "python3.exe", "node.exe", "java.exe",
    }


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_global_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_loopback and not a.is_link_local
    except ValueError:
        return False


# ---- hunts ---- #


def hunt_browser_spawns_shell(store: EvidenceStore) -> Iterable[dict]:
    proc_by_pid = {a["data"].get("pid"): a["data"] for a in store.iter_artifacts(collector="processes")
                    if a["data"].get("pid")}
    for art in store.iter_artifacts(collector="processes"):
        d = art["data"]
        if not _shell_name(d.get("name", "")):
            continue
        parent = proc_by_pid.get(d.get("ppid"))
        if not parent:
            continue
        if _browser_name(parent.get("name", "")):
            yield {
                "child_pid":    d.get("pid"),
                "child_name":   d.get("name"),
                "parent_name":  parent.get("name"),
                "username":     d.get("username"),
                "cmdline":      " ".join(d.get("cmdline") or [])[:200],
                "_artifact":    art["artifact_uuid"],
            }


register(Hunt(
    id="browser-spawns-shell",
    title="Shell processes parented by a browser",
    description=("Browsers don't legitimately parent interactive shells. "
                 "Hits suggest post-exploitation via a malicious extension, "
                 "compromised renderer, or drive-by execution."),
    severity_hint="high",
    mitre="T1059",
    tags=["initial-access", "execution"],
    columns=["child_pid", "child_name", "parent_name", "username", "cmdline"],
    fn=hunt_browser_spawns_shell,
))


def hunt_encoded_powershell(store: EvidenceStore) -> Iterable[dict]:
    pat = re.compile(r"-e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{60,}", re.I)
    for art in store.iter_artifacts(collector="processes"):
        d = art["data"]
        if "powershell" not in (d.get("name") or "").lower():
            continue
        cmd = " ".join(d.get("cmdline") or [])
        m = pat.search(cmd)
        if m:
            yield {
                "pid": d.get("pid"),
                "username": d.get("username"),
                "encoded_len": len(m.group(0)),
                "cmdline_preview": cmd[:240],
                "_artifact": art["artifact_uuid"],
            }


register(Hunt(
    id="encoded-powershell",
    title="PowerShell with -EncodedCommand argument",
    description="powershell.exe invocation carrying a base64-encoded payload. "
                "Common evasion; nearly always worth reading the decoded form.",
    severity_hint="high", mitre="T1059.001",
    tags=["execution", "defense-evasion"],
    columns=["pid", "username", "encoded_len", "cmdline_preview"],
    fn=hunt_encoded_powershell,
))


def hunt_curl_pipe_bash(store: EvidenceStore) -> Iterable[dict]:
    pat1 = re.compile(r"(curl|wget)[^|]+\|\s*(bash|sh|zsh|fish)\b")
    pat2 = re.compile(r"(invoke-webrequest|iwr)[^|]+\|\s*iex\b", re.I)
    for art in store.iter_artifacts(collector="processes"):
        d = art["data"]
        cmd = " ".join(d.get("cmdline") or [])
        if pat1.search(cmd) or pat2.search(cmd):
            yield {
                "pid": d.get("pid"),
                "name": d.get("name"),
                "username": d.get("username"),
                "cmdline": cmd[:280],
                "_artifact": art["artifact_uuid"],
            }


register(Hunt(
    id="curl-pipe-bash",
    title="Remote download piped into a shell",
    description="curl/wget/Invoke-WebRequest output piped to bash/sh/iex. "
                "Classic dropper pattern.",
    severity_hint="high", mitre="T1105",
    tags=["initial-access", "execution"],
    columns=["pid", "name", "username", "cmdline"],
    fn=hunt_curl_pipe_bash,
))


def hunt_ld_preload(store: EvidenceStore) -> Iterable[dict]:
    for art in store.iter_artifacts(collector="env"):
        if art["subject"] != "interesting":
            continue
        vals = art["data"].get("values") or {}
        for var in ("LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE"):
            v = vals.get(var)
            if v:
                yield {
                    "variable": var,
                    "value": v,
                    "_artifact": art["artifact_uuid"],
                }


register(Hunt(
    id="dynamic-linker-hijack",
    title="LD_PRELOAD / DYLD_INSERT_LIBRARIES in environment",
    description="Dynamic-linker injection variable is set in the current "
                "process environment. Almost never legitimate on a workstation.",
    severity_hint="high", mitre="T1574.006",
    tags=["defense-evasion", "privilege-escalation"],
    columns=["variable", "value"],
    fn=hunt_ld_preload,
))


def hunt_shell_init_hook(store: EvidenceStore) -> Iterable[dict]:
    for art in store.iter_artifacts(collector="env"):
        if art["subject"] != "interesting":
            continue
        vals = art["data"].get("values") or {}
        for var in ("BASH_ENV", "ENV", "PROMPT_COMMAND"):
            v = vals.get(var)
            if v:
                yield {"variable": var, "value": v, "_artifact": art["artifact_uuid"]}


register(Hunt(
    id="shell-init-hook",
    title="Shell init hook variable set (BASH_ENV / ENV / PROMPT_COMMAND)",
    description="Variables read by shells on every startup. An attacker that "
                "writes to these gets execution on every new shell.",
    severity_hint="medium", mitre="T1546.004",
    tags=["persistence", "execution"],
    columns=["variable", "value"],
    fn=hunt_shell_init_hook,
))


def hunt_interpreter_in_temp(store: EvidenceStore) -> Iterable[dict]:
    drop_paths = ("/tmp/", "/var/tmp/", "/dev/shm/",
                  "/Users/Shared/", "/private/tmp/",
                  "\\Temp\\", "\\AppData\\Local\\Temp\\",
                  "\\Users\\Public\\")
    from digger.opsec.self_id import identify as _self_id

    def _in_drop(s: str) -> str | None:
        return next((p for p in drop_paths if p in s), None)

    for art in store.iter_artifacts(collector="processes"):
        d = art["data"]
        if not _interpreter_name(d.get("name", "")):
            continue
        exe = d.get("exe") or ""
        cmd_list = d.get("cmdline") or []

        # 1. Interpreter binary itself dropped into scratch.
        hit = _in_drop(exe)
        kind = "exe-in-drop" if hit else None

        # 2. Interpreter EXECUTING a script in a drop dir. The script is
        #    the first positional (non-flag) arg after the interpreter.
        if not kind:
            for arg in cmd_list[1:]:
                if not arg:
                    continue
                if arg.startswith("-"):
                    break
                if "/" not in arg and "\\" not in arg:
                    continue
                p = _in_drop(arg)
                if p:
                    hit, kind = p, "script-in-drop"
                break

        # 3. Broader net — drop path anywhere in cmdline. This is the
        #    pattern that flags digger itself when it has a /tmp/ case-
        #    dir on its argv. We surface it (don't silently filter) but
        #    the `self` column tells the analyst "yes, that's digger
        #    looking at itself" so it isn't mistaken for an unknown
        #    interpreter touching /tmp.
        if not kind:
            joined = " ".join(cmd_list)
            p = _in_drop(joined)
            if p:
                hit, kind = p, "cmdline-references-drop"

        if not kind:
            continue
        self_attribution = _self_id(d) or ""
        yield {
            "pid": d.get("pid"),
            "name": d.get("name"),
            "exe": exe,
            "username": d.get("username"),
            "drop_path": hit,
            "kind": kind,
            "self": self_attribution,
            "cmdline": " ".join(cmd_list)[:200],
            "_artifact": art["artifact_uuid"],
        }


register(Hunt(
    id="interpreter-in-temp",
    title="Interpreter (python/node/ruby/…) running from a drop location",
    description="Scripting runtimes referencing /tmp, %TEMP%, or other "
                "world-writable scratch directories on their command line.",
    severity_hint="medium", mitre="T1059",
    tags=["execution"],
    columns=["pid", "name", "exe", "username", "drop_path", "kind", "self", "cmdline"],
    fn=hunt_interpreter_in_temp,
))


def hunt_persistence_in_user_home(store: EvidenceStore) -> Iterable[dict]:
    for art in store.iter_artifacts(category="persistence"):
        blob = repr(art["data"]).lower()
        # any /Users/<not-Shared>/ or /home/ reference inside a persistence record
        if re.search(r"/users/[^/]+/", blob) or "/home/" in blob:
            yield {
                "collector": art["collector"],
                "subject": art["subject"],
                "snippet": blob[:180],
                "_artifact": art["artifact_uuid"],
            }


register(Hunt(
    id="persistence-in-user-home",
    title="Persistence entry referencing a user home directory",
    description="LaunchAgents / cron / systemd units / Run keys that point at "
                "binaries under /Users/<name>/ or /home/. Plausibly legitimate "
                "(many tools install per-user) but each is worth eyeballing.",
    severity_hint="low", mitre="T1547",
    tags=["persistence"],
    columns=["collector", "subject", "snippet"],
    fn=hunt_persistence_in_user_home,
))


def hunt_ssh_authorized_keys_with_command(store: EvidenceStore) -> Iterable[dict]:
    for art in store.iter_artifacts(collector="ssh_keys"):
        if not art["subject"].startswith("authorized_keys"):
            continue
        path = art["data"].get("path", "")
        for line in art["data"].get("lines") or []:
            if "command=" in line:
                yield {
                    "path": path,
                    "line_preview": line[:240],
                    "_artifact": art["artifact_uuid"],
                }


register(Hunt(
    id="ssh-key-forced-command",
    title="authorized_keys entries with forced commands",
    description='Keys with a `command="..."` constraint. Legitimate uses '
                "(rsync-only, git-shell) exist, but a forced-command shell "
                "is a classic SSH backdoor.",
    severity_hint="high", mitre="T1098.004",
    tags=["persistence", "credential-access"],
    columns=["path", "line_preview"],
    fn=hunt_ssh_authorized_keys_with_command,
))


def hunt_browser_extension_sweeping_perms(store: EvidenceStore) -> Iterable[dict]:
    risky = {"<all_urls>", "tabs", "webRequest", "cookies", "history",
             "clipboardRead", "clipboardWrite", "nativeMessaging",
             "debugger", "proxy", "management"}
    for art in store.iter_artifacts(category="browser"):
        if "extensions" not in art["subject"]:
            continue
        for ext in art["data"].get("entries") or []:
            perms = set(ext.get("permissions") or []) | set(ext.get("host_permissions") or [])
            hits = perms & risky
            if "<all_urls>" in (ext.get("host_permissions") or []) or hits:
                yield {
                    "browser": art["subject"].split(":")[0],
                    "name": ext.get("name") or ext.get("id"),
                    "id": ext.get("id"),
                    "version": ext.get("version"),
                    "risky_perms": ", ".join(sorted(hits)) or "<all_urls>",
                    "_artifact": art["artifact_uuid"],
                }


register(Hunt(
    id="browser-extension-sweeping-perms",
    title="Browser extensions holding sweeping permissions",
    description="Extensions with <all_urls>, debugger, nativeMessaging, "
                "cookies, history, etc. Each is a high-trust component "
                "whose maintainer changes are easy to miss.",
    severity_hint="low", mitre="T1176",
    tags=["initial-access", "credential-access"],
    columns=["browser", "name", "id", "version", "risky_perms"],
    fn=hunt_browser_extension_sweeping_perms,
))


def hunt_listener_on_uncommon_port(store: EvidenceStore) -> Iterable[dict]:
    benign = {22, 53, 80, 88, 110, 143, 389, 443, 445, 465, 514, 587,
              631, 636, 993, 995, 1024, 3000, 3306, 5000, 5432, 6379,
              6443, 8000, 8080, 8443, 8888, 9000, 9090, 27017,
              5353, 5354, 7000, 49152, 49153, 49154, 49155, 49156}
    for art in store.iter_artifacts(collector="network"):
        d = art["data"]
        if (d.get("status") or "").upper() != "LISTEN":
            continue
        laddr = d.get("laddr") or []
        if len(laddr) < 2:
            continue
        port = laddr[1]
        if port in benign or port >= 60000:
            continue
        yield {
            "laddr": f"{laddr[0]}:{port}",
            "port": port,
            "pid": d.get("pid"),
            "_artifact": art["artifact_uuid"],
        }


register(Hunt(
    id="uncommon-listener",
    title="Listening sockets on ports outside the common service range",
    description="Sockets in LISTEN state on a port not in the standard "
                "service map. Often benign (dev servers, electron apps) "
                "but worth a manual check.",
    severity_hint="low", mitre="T1571",
    tags=["command-and-control", "lateral-movement"],
    columns=["laddr", "port", "pid"],
    fn=hunt_listener_on_uncommon_port,
))


def hunt_high_entropy_domain(store: EvidenceStore) -> Iterable[dict]:
    """Browser-history domains with high Shannon entropy — DGA candidates."""
    for art in store.iter_artifacts(collector="browsers"):
        if "history" not in art["subject"]:
            continue
        for entry in art["data"].get("entries") or []:
            url = entry.get("url") if isinstance(entry, dict) else None
            if not url:
                continue
            m = re.match(r"https?://([^/]+)/?", url)
            if not m:
                continue
            host = m.group(1).lower()
            domain_part = host.split(":")[0].split(".")[0]
            if len(domain_part) < 12:
                continue
            ent = _shannon_entropy(domain_part)
            if ent < 3.6:
                continue
            yield {
                "entropy": round(ent, 2),
                "domain_part": domain_part,
                "host": host,
                "url": url[:140],
                "_artifact": art["artifact_uuid"],
            }


register(Hunt(
    id="high-entropy-domain",
    title="Browser history with high-entropy subdomains (DGA candidates)",
    description="Domains whose left-most label has high Shannon entropy. "
                "Often AWS S3 / CDN URLs (false positives) but also a hallmark "
                "of domain-generation-algorithm C2.",
    severity_hint="low", mitre="T1568.002",
    tags=["command-and-control"],
    columns=["entropy", "domain_part", "host", "url"],
    fn=hunt_high_entropy_domain,
))


def hunt_external_connections_to_tor(store: EvidenceStore) -> Iterable[dict]:
    """Established connections to IPs on the Tor bulk exit list (intel feed)."""
    try:
        from digger.intel import load_cached
        tor = load_cached("tor_exit_list") or {}
        exits = set(tor.get("entries", []) or [])
    except Exception:
        exits = set()
    if not exits:
        return
    for art in store.iter_artifacts(collector="network"):
        d = art["data"]
        raddr = d.get("raddr") or []
        if not raddr:
            continue
        ip = raddr[0]
        if ip in exits:
            yield {
                "remote_ip": ip,
                "remote_port": raddr[1] if len(raddr) > 1 else None,
                "status": d.get("status"),
                "pid": d.get("pid"),
                "_artifact": art["artifact_uuid"],
            }


register(Hunt(
    id="tor-exit-connection",
    title="Established connection to a Tor exit node",
    description="Cross-references current network connections with the Tor "
                "Project bulk-exit list (live intel feed). Not malicious "
                "per se, but unusual for most production workloads.",
    severity_hint="medium", mitre="T1090.003",
    tags=["command-and-control", "defense-evasion"],
    columns=["remote_ip", "remote_port", "status", "pid"],
    fn=hunt_external_connections_to_tor,
))


def hunt_process_with_no_exe(store: EvidenceStore) -> Iterable[dict]:
    for art in store.iter_artifacts(collector="processes"):
        d = art["data"]
        if d.get("pid", 0) <= 1:
            continue
        if not d.get("exe"):
            yield {
                "pid": d.get("pid"),
                "name": d.get("name"),
                "username": d.get("username"),
                "cmdline": " ".join(d.get("cmdline") or [])[:160],
                "_artifact": art["artifact_uuid"],
            }


register(Hunt(
    id="process-without-exe-path",
    title="Running processes with no exe path",
    description="The OS reports the process is running but no path on disk "
                "backs it. Consistent with memfd, unlinked binaries, or "
                "filesystems the user can't read. Investigate.",
    severity_hint="medium", mitre="T1055",
    tags=["defense-evasion"],
    columns=["pid", "name", "username", "cmdline"],
    fn=hunt_process_with_no_exe,
))


def hunt_interpreter_with_external_conn(store: EvidenceStore) -> Iterable[dict]:
    """Interpreters (python/node/ruby/perl) that own an external network connection."""
    from digger.opsec.self_id import identify as _self_id
    proc_by_pid = {a["data"].get("pid"): a["data"] for a in store.iter_artifacts(collector="processes")
                    if a["data"].get("pid")}
    for art in store.iter_artifacts(collector="network"):
        d = art["data"]
        if (d.get("status") or "").upper() != "ESTABLISHED":
            continue
        raddr = d.get("raddr") or []
        if len(raddr) < 1 or not _is_global_ip(raddr[0]):
            continue
        pid = d.get("pid")
        if not pid or pid not in proc_by_pid:
            continue
        proc = proc_by_pid[pid]
        if not _interpreter_name(proc.get("name", "")):
            continue
        yield {
            "pid": pid,
            "name": proc.get("name"),
            "username": proc.get("username"),
            "remote": f"{raddr[0]}:{raddr[1] if len(raddr) > 1 else '?'}",
            "self": _self_id(proc) or "",
            "cmdline": " ".join(proc.get("cmdline") or [])[:180],
            "_artifact": art["artifact_uuid"],
        }


register(Hunt(
    id="interpreter-with-external-conn",
    title="Scripting interpreter with an external (global) network connection",
    description="python/node/ruby/perl processes holding an open established "
                "connection to a public IP. Often legitimate (pip, npm, "
                "package fetches) but a great starting point for tracking "
                "down a reverse-shell.",
    severity_hint="low", mitre="T1059",
    tags=["execution", "command-and-control"],
    columns=["pid", "name", "username", "remote", "self", "cmdline"],
    fn=hunt_interpreter_with_external_conn,
))


def hunt_recent_executables_in_drop(store: EvidenceStore) -> Iterable[dict]:
    """Recently-modified executable files under common drop locations."""
    for art in store.iter_artifacts(collector="recent_files"):
        loc = art["data"].get("location", "")
        for e in art["data"].get("entries") or []:
            if not isinstance(e, dict):
                continue
            if not e.get("executable"):
                continue
            path = e.get("path", "")
            yield {
                "location": loc,
                "path": path,
                "size": e.get("size"),
                "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e.get("mtime", 0))) if e.get("mtime") else "",
                "_artifact": art["artifact_uuid"],
            }


register(Hunt(
    id="recent-executable-in-drop",
    title="Recently-modified executable files in /tmp, Downloads, /Users/Shared, %TEMP%",
    description="Anything executable that appeared in a common drop location "
                "in the last 14 days. Most are benign developer artifacts; "
                "a quick scan often turns up persistence droppers.",
    severity_hint="low", mitre="T1564.001",
    tags=["initial-access", "defense-evasion"],
    columns=["location", "path", "size", "mtime"],
    fn=hunt_recent_executables_in_drop,
))


def hunt_shai_hulud_packages(store: EvidenceStore) -> Iterable[dict]:
    """Direct package@version match against the bundled Shai-Hulud list."""
    try:
        from digger.detectors._rules_io import load_yaml
        rules = load_yaml("supply_chain/shai_hulud.yaml") or {}
    except Exception:
        rules = {}
    compromised = set()
    wildcards = set()
    for entry in rules.get("compromised_packages", []) or []:
        if entry.endswith("@*"):
            wildcards.add(entry[:-2])
        else:
            compromised.add(entry)
    for art in store.iter_artifacts(collector="npm_packages"):
        proj = art["data"].get("project", "")
        for name, ver in (art["data"].get("locked_packages") or {}).items():
            spec = f"{name}@{ver}"
            if spec in compromised or name in wildcards:
                yield {
                    "project": proj,
                    "package": spec,
                    "match_type": "exact" if spec in compromised else "wildcard",
                    "_artifact": art["artifact_uuid"],
                }


register(Hunt(
    id="shai-hulud-packages",
    title="npm packages on the Shai-Hulud worm compromised-versions list",
    description="Cross-reference lockfile entries against the bundled "
                "Shai-Hulud package@version list. Every hit is high-severity.",
    severity_hint="critical", mitre="T1195.002",
    tags=["initial-access", "supply-chain"],
    columns=["project", "package", "match_type"],
    fn=hunt_shai_hulud_packages,
))


def hunt_large_authorized_keys(store: EvidenceStore) -> Iterable[dict]:
    for art in store.iter_artifacts(collector="ssh_keys"):
        if not art["subject"].startswith("authorized_keys"):
            continue
        lines = [l for l in (art["data"].get("lines") or [])
                 if l.strip() and not l.strip().startswith("#")]
        if len(lines) > 5:
            yield {
                "path": art["data"].get("path"),
                "key_count": len(lines),
                "_artifact": art["artifact_uuid"],
            }


register(Hunt(
    id="large-authorized-keys",
    title="authorized_keys files with many entries",
    description=">5 active keys in a single authorized_keys file. Audit each "
                "key against current personnel and active automation.",
    severity_hint="low", mitre="T1098.004",
    tags=["persistence", "credential-access"],
    columns=["path", "key_count"],
    fn=hunt_large_authorized_keys,
))
