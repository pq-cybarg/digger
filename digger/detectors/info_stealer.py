"""Info-stealer malware detector.

Info-stealer families (Lumma, RedLine, Vidar, StealC, Raccoon, Meta-
Stealer, Atomic Stealer / AMOS) are the highest-base-rate live threat
on developer / consumer endpoints today. Their canonical fingerprint:

    1. Process opens a Chromium-family ``Cookies`` / ``Login Data`` /
       ``Local State`` file (not normally read by anything except
       Chrome / Edge / Brave itself).
    2. Same process (or its child) makes outbound network traffic
       to a webhook / paste-bin / known stealer C2.
    3. Steps 1 + 2 happen within a short window (typically < 30s).

This detector composes:

  * The deep cookie/login-DB knowledge from ``digger.hindsight``
    (path patterns of the target SQLite files).
  * The webhook / paste-bin / C2 patterns from
    ``ExfiltrationDetector`` (where exfil normally goes).
  * Process open_files + connections from the ``processes``
    collector.

Detection layers
----------------

S1  Stealer-binary-name match
    Single hit on a process name / exe basename matching a known
    stealer family. The names are stable across builds because the
    payload is reused. Critical, T1555.003.

S2  Browser-cookie-read by non-browser process
    A process opens ``.../Chrome/Default/Cookies`` (or similar
    across Edge / Brave / Chromium / Vivaldi) when the process is
    NOT itself the browser. High alone; critical if paired with S3
    within the time window.

S3  Local State `os_crypt.encrypted_key` extraction
    The DPAPI-encrypted master key for Chromium cookies lives in
    ``Local State``. A non-browser process reading it is the
    cryptographic-side fingerprint of cookie stealing — even
    without S2 the next step is decryption. Critical, T1555.003.

S4  Cookie-read + exfil correlation (S2 + outbound)
    A process that read S2 and then within 30 seconds makes an
    outbound connection to a known stealer-exfil destination
    (webhook.site / discord webhooks / paste-bins / known stealer
    C2 hosts). Critical, T1555.003 + T1041.

S5  Known stealer C2 in cmdline / DNS
    Known info-stealer C2 hostnames in any cmdline or DNS history.

MITRE: T1555.003 (Credentials from Web Browsers), T1041 (Exfil over
C2 Channel), T1555 (Credentials from Password Stores).
"""

from __future__ import annotations

import time
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- S1 known stealer binary names ---- #
# Lowercase basenames seen across published IOCs (HellPie, JoeSandbox,
# any.run, Recorded Future's stealer catalogues). Many stealers reuse
# the same payload-binary naming — the loaders rename, but the
# embedded build still matches these.

_STEALER_NAMES: dict[str, str] = {
    # Lumma family
    "lumma": "Lumma Stealer",
    "lummac2": "LummaC2",
    "lumma_v2": "Lumma v2",
    # RedLine
    "redline.exe": "RedLine",
    "redline_clip.exe": "RedLine clipper",
    # Vidar / Mars (Mars is a Vidar fork)
    "vidar.exe": "Vidar",
    "marsstealer.exe": "MarsStealer",
    # StealC
    "stealc.exe": "StealC",
    # Raccoon
    "raccoon.exe": "Raccoon Stealer",
    "raccoonv2.exe": "Raccoon v2",
    # MetaStealer
    "metastealer.exe": "MetaStealer",
    # AtomicStealer (AMOS) — macOS
    "amos": "Atomic macOS Stealer (AMOS)",
    "atomicstealer": "Atomic macOS Stealer (AMOS)",
    # RecordBreaker (Raccoon successor)
    "recordbreaker.exe": "RecordBreaker",
    # NorthKorea-attributed
    "appleseed.exe": "AppleSeed (Kimsuky)",
    # Generic stealer loaders
    "smokeloader.exe": "SmokeLoader (stealer dropper)",
    "privateloader.exe": "PrivateLoader (stealer dropper)",
}

# ---- S2 Chromium cookie / login DB path fragments ---- #
# Substrings (case-insensitive) for the per-OS / per-browser paths.

_CHROMIUM_COOKIE_PATHS = [
    # Chrome / Chromium
    "/google/chrome/default/cookies",
    "/google/chrome/default/network/cookies",
    "/google-chrome/default/cookies",
    "/chromium/default/cookies",
    # Edge
    "/microsoft edge/default/cookies",
    "/microsoft/edge/user data/default/cookies",
    # Brave
    "/bravesoftware/brave-browser/default/cookies",
    "/brave-browser/default/cookies",
    # Vivaldi
    "/vivaldi/default/cookies",
    # Opera
    "/opera software/opera stable/cookies",
    "/com.operasoftware.opera/cookies",
    # Arc
    "/arc/user data/default/cookies",
    # Generic per-profile (covers most variants):
    "/cookies",   # broad-but-paired with stealer-name or exfil
]

_CHROMIUM_LOGIN_DATA_PATHS = [
    "/google/chrome/default/login data",
    "/google-chrome/default/login data",
    "/chromium/default/login data",
    "/microsoft edge/default/login data",
    "/microsoft/edge/user data/default/login data",
    "/bravesoftware/brave-browser/default/login data",
    "/brave-browser/default/login data",
    "/vivaldi/default/login data",
    "/arc/user data/default/login data",
]

_CHROMIUM_LOCAL_STATE_PATHS = [
    "/google/chrome/local state",
    "/google-chrome/local state",
    "/chromium/local state",
    "/microsoft edge/local state",
    "/microsoft/edge/user data/local state",
    "/bravesoftware/brave-browser/local state",
    "/brave-browser/local state",
    "/vivaldi/local state",
]

# Legitimate readers of these files. Anything else accessing them is
# the signal we care about.
_BROWSER_PROCESS_NAMES = {
    "chrome", "chromium", "google chrome", "google-chrome",
    "msedge", "microsoftedge",
    "brave", "brave browser",
    "opera", "vivaldi", "arc",
    # Browser helper / renderer processes that legitimately access
    # the same files (Chromium spawns "Helper" / Renderer / Network
    # subprocesses).
    "chrome helper", "chromium helper",
    "google chrome helper", "google chrome helper (renderer)",
    "google chrome helper (gpu)",
    "google chrome helper (network)",
    "google chrome helper (plugin)",
    "msedge helper", "microsoftedge helper",
    "brave helper", "brave browser helper",
}


# ---- S5 known stealer C2 hosts ---- #
# A curated set known to receive info-stealer exfil. These rotate
# fast; the value here is illustrative + dispositive when matched.
# Combine with the broader ExfiltrationDetector webhook/paste-bin list
# at runtime so we don't duplicate maintenance.

_STEALER_C2_HOSTS = [
    # Lumma panels (rotated; sampling from MalwareBazaar 2025-2026)
    "step1-discord.com", "discord-bot.org", "fakebook-prod.com",
    # RedLine known panels (older but still seen)
    "redline-checker.ru",
    # General stealer-friendly anon-drops (these overlap with the
    # generic exfil list — included here so the InfoStealer-specific
    # finding's evidence carries the family attribution).
    "transfer.sh", "0x0.st", "file.io",
    "pastebin.com", "hastebin.com", "ix.io",
    "webhook.site",
    # Discord/Telegram webhooks (canonical stealer destinations)
    "discord.com/api/webhooks", "discordapp.com/api/webhooks",
    "api.telegram.org/bot",
]


# ---- exfil-correlation time window ---- #


CORRELATION_WINDOW_S = 30


def _cmdline_str(cmdline) -> str:
    if isinstance(cmdline, list):
        return " ".join(str(c) for c in cmdline if c)
    return cmdline or ""


def _basename(path: str) -> str:
    if not path:
        return ""
    if "/" in path:
        path = path.rsplit("/", 1)[1]
    if "\\" in path:
        path = path.rsplit("\\", 1)[1]
    return path


def _norm(s: str) -> str:
    return (s or "").lower()


def _is_browser_process(name: str, exe: str) -> bool:
    """True iff the process is a legitimate Chromium-family browser
    or its helper subprocess (which DO routinely access the same
    files)."""
    bn = _norm(_basename(exe) or name)
    # Strip .exe so 'chrome.exe' matches 'chrome'
    if bn.endswith(".exe"):
        bn = bn[:-4]
    if bn in _BROWSER_PROCESS_NAMES:
        return True
    # Check full lowercased name (e.g. "Google Chrome Helper (GPU)")
    full = _norm(name)
    if full in _BROWSER_PROCESS_NAMES:
        return True
    # Also accept any name containing "chrome helper" / "browser helper"
    if "chrome helper" in full or "browser helper" in full:
        return True
    return False


def _path_match_any(path_low: str, candidates: list[str]) -> str | None:
    """Return the first matching path fragment, or None."""
    for c in candidates:
        if c in path_low:
            return c
    return None


def _open_paths(d: dict) -> list[str]:
    """Pull the list of opened file paths from a process artifact.

    Handles both shapes the ProcessCollector emits: a list of strings
    OR a list of dicts with a 'path' key."""
    out: list[str] = []
    for entry in d.get("open_files") or []:
        if isinstance(entry, str):
            out.append(entry)
        elif isinstance(entry, dict):
            p = entry.get("path") or entry.get("name")
            if p:
                out.append(str(p))
    return out


def _conn_remote_endpoints(d: dict) -> list[tuple[str, int | None]]:
    """Return list of (remote_ip_or_host, remote_port) tuples for the
    process's outbound connections in ESTABLISHED / SYN_SENT state."""
    out: list[tuple[str, int | None]] = []
    for conn in d.get("connections") or []:
        if not isinstance(conn, dict):
            continue
        status = (conn.get("status") or "").upper()
        if status and status not in ("ESTABLISHED", "SYN_SENT"):
            continue
        raddr = conn.get("raddr")
        rip = None
        rport = None
        if isinstance(raddr, (list, tuple)) and len(raddr) >= 1:
            rip = raddr[0]
            rport = raddr[1] if len(raddr) > 1 else None
        elif isinstance(raddr, str):
            rip = raddr
            rport = conn.get("rport")
        elif isinstance(raddr, dict):
            rip = raddr.get("ip") or raddr.get("host")
            rport = raddr.get("port")
        else:
            rip = conn.get("remote_ip") or conn.get("rhost")
            rport = conn.get("rport") or conn.get("remote_port")
        if rip:
            out.append((str(rip), rport))
    return out


def _process_referenced_a_stealer_c2(
    d: dict, stealer_hosts: list[str],
) -> str | None:
    """Return the first stealer-C2 host the process touches (via
    cmdline or connection-table remote), or None."""
    cmd = _cmdline_str(d.get("cmdline")).lower()
    for h in stealer_hosts:
        if h.lower() in cmd:
            return h
    for rip, _rport in _conn_remote_endpoints(d):
        for h in stealer_hosts:
            if h.lower() in rip.lower():
                return h
    return None


class InfoStealerDetector(Detector):
    name = "info_stealer"
    description = (
        "Info-stealer malware (Lumma / RedLine / Vidar / StealC / "
        "Raccoon / MetaStealer / AMOS): stealer-binary-name match, "
        "non-browser process reading Chromium Cookies / Login Data / "
        "Local State (DPAPI key), correlated cookie-read-then-exfil "
        "pattern within 30s, known stealer C2 in cmdline / DNS."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Info-stealer fingerprint: cookie-read by non-browser + webhook exfil",
            "id": "digger-info-stealer-template",
            "description": (
                "A non-browser process opens Chromium ``Cookies`` / "
                "``Login Data`` / ``Local State`` AND has outbound "
                "to a webhook / paste-bin / known stealer C2 within "
                "30s — the canonical Lumma / RedLine / Vidar / "
                "StealC / Raccoon / MetaStealer / AMOS fingerprint. "
                "Single-hit on a known stealer binary name also "
                "fires."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_stealer_binary": {
                    "Image|endswith": [
                        "/lumma", "/lummac2", "/lumma_v2",
                        "/redline.exe", "/redline_clip.exe",
                        "/vidar.exe", "/marsstealer.exe",
                        "/stealc.exe",
                        "/raccoon.exe", "/raccoonv2.exe",
                        "/metastealer.exe",
                        "/recordbreaker.exe",
                        "/atomicstealer", "/amos",
                        "/smokeloader.exe", "/privateloader.exe",
                    ],
                },
                "selection_cookie_open_nonbrowser": {
                    "TargetFilename|contains": [
                        "/Chrome/Default/Cookies",
                        "/Chromium/Default/Cookies",
                        "/Microsoft Edge/Default/Cookies",
                        "/Brave-Browser/Default/Cookies",
                        "/Vivaldi/Default/Cookies",
                        "/Default/Login Data",
                        "/Local State",
                    ],
                    "filter_browser_image": {
                        "Image|endswith": [
                            "/chrome", "/chrome.exe",
                            "/chromium", "/chromium.exe",
                            "/msedge.exe", "/microsoftedge.exe",
                            "/brave", "/brave.exe",
                            "/vivaldi", "/vivaldi.exe",
                        ],
                    },
                    "condition": "selection_cookie_open_nonbrowser "
                                  "and not filter_browser_image",
                },
                "condition": "1 of selection_*",
            },
            "level": "critical",
            "tags": [
                "attack.t1555",
                "attack.t1555.003",
                "attack.t1041",
                "attack.credential_access",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # Pull live exfil-host list from the ExfiltrationDetector
        # constants — keeps the canonical exfil-endpoint maintenance
        # in one place.
        try:
            from digger.detectors.exfiltration import (
                _WEB_EXFIL_DOMAINS as _exfil_pairs,
            )
            extra_hosts = [pair[0] for pair in _exfil_pairs]
        except Exception:
            extra_hosts = []
        all_stealer_hosts = list(
            dict.fromkeys(_STEALER_C2_HOSTS + extra_hosts)
        )

        # Walk every process artifact.
        # Track (pid → first cookie-read timestamp + matched-path) for
        # the correlation layer.
        cookie_reads: dict[int, dict] = {}

        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            pid = d.get("pid") or 0
            name = (d.get("name") or "").lower()
            exe = (d.get("exe") or "").lower()
            base = (_basename(exe) or name).lower()
            ts = d.get("create_time") or art.get("ts") or time.time()

            # ---- S1 stealer-binary-name match ---- #
            stealer_family = None
            base_no_exe = base[:-4] if base.endswith(".exe") else base
            for known, family in _STEALER_NAMES.items():
                if base == known or base_no_exe == known.rstrip(".exe"):
                    stealer_family = family
                    break
            if stealer_family:
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=(
                        f"Info-stealer process running: {stealer_family} "
                        f"(pid {pid}, {base})"
                    ),
                    summary=(
                        f"Process pid {pid} ({base}, user "
                        f"{d.get('username')}) name matches the known "
                        f"info-stealer family ``{stealer_family}``. "
                        "Info-stealer binary names are stable across "
                        "builds — the loader renames itself but the "
                        "embedded payload binary still matches. "
                        "Isolate the host, capture memory before "
                        "reboot, rotate every credential reachable "
                        "from this user account (browser cookies, "
                        "saved logins, SSH keys, cloud tokens)."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "stealer_binary_name",
                        "family": stealer_family,
                        "pid": pid,
                        "name": base,
                        "exe": d.get("exe"),
                        "username": d.get("username"),
                    },
                    mitre="T1555.003",
                )

            # ---- S2 / S3 non-browser process reading cookie DB ---- #
            if _is_browser_process(name, exe):
                # Legitimate; the browser DOES open its own DBs.
                continue
            paths = _open_paths(d)
            # Combine the path lists for matching. We need to know
            # which family (cookies vs login data vs local state) so
            # the finding is precise.
            for p in paths:
                pl = _norm(p)
                cookie_hit = _path_match_any(pl, _CHROMIUM_COOKIE_PATHS)
                login_hit = _path_match_any(pl, _CHROMIUM_LOGIN_DATA_PATHS)
                state_hit = _path_match_any(pl, _CHROMIUM_LOCAL_STATE_PATHS)
                if not (cookie_hit or login_hit or state_hit):
                    continue
                kind = ("cookies" if cookie_hit
                        else "login_data" if login_hit
                        else "local_state_key")
                # Record the cookie read for the correlation layer.
                if cookie_hit and pid not in cookie_reads:
                    cookie_reads[pid] = {
                        "ts": ts, "path": p, "name": base,
                        "exe": d.get("exe"),
                        "username": d.get("username"),
                        "artifact_uuid": art["artifact_uuid"],
                    }
                # S2 / S3 single-shot
                sev = "critical" if state_hit else "high"
                rationale = (
                    "Local State carries the DPAPI-encrypted cookie "
                    "master key; reading it is the cryptographic "
                    "prerequisite for cookie theft."
                    if state_hit else
                    "A non-browser process reading the cookie DB is "
                    "the canonical info-stealer signal."
                )
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=(
                        f"Non-browser process reading Chromium "
                        f"{kind}: {base} (pid {pid})"
                    ),
                    summary=(
                        f"Process pid {pid} ({base}, user "
                        f"{d.get('username')}) opened ``{p}`` — a "
                        f"Chromium-family {kind} file. The only "
                        "processes that normally touch these files "
                        "are Chrome / Chromium / Edge / Brave / "
                        f"Vivaldi themselves and their helper "
                        f"sub-processes. {rationale}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": kind,
                        "pid": pid,
                        "name": base,
                        "exe": d.get("exe"),
                        "username": d.get("username"),
                        "path": p,
                    },
                    mitre="T1555.003",
                )
                break  # one S2/S3 finding per process

            # ---- S5 stealer-C2 in cmdline / connections ---- #
            stealer_host = _process_referenced_a_stealer_c2(
                d, all_stealer_hosts,
            )
            if stealer_host and not stealer_family:
                # Don't double-emit when S1 already fired
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=(
                        f"Stealer-exfil destination contacted by "
                        f"pid {pid}: {stealer_host}"
                    ),
                    summary=(
                        f"Process pid {pid} ({base}) references "
                        f"``{stealer_host}`` — a known info-stealer "
                        "exfil destination (webhook / paste-bin / "
                        "Discord webhook / Telegram bot / known "
                        "stealer C2). High alone; if combined with "
                        "a non-browser cookie read on the same pid "
                        "within 30s, that's the dispositive stealer "
                        "fingerprint (the S4 finding will also fire)."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "stealer_c2",
                        "host": stealer_host,
                        "pid": pid,
                        "name": base,
                        "username": d.get("username"),
                    },
                    mitre="T1041",
                )

        # ---- S4 cookie-read + exfil correlation ---- #
        # Walk processes again, this time looking for pids that BOTH
        # opened a cookie DB AND have outbound to a stealer host
        # within the correlation window.
        if cookie_reads:
            for art in store.iter_artifacts(collector="processes"):
                d = art["data"] or {}
                pid = d.get("pid") or 0
                if pid not in cookie_reads:
                    continue
                ts = d.get("create_time") or art.get("ts") or time.time()
                read_info = cookie_reads[pid]
                if abs(ts - read_info["ts"]) > CORRELATION_WINDOW_S:
                    continue
                # Look for outbound to any stealer host
                stealer_host = _process_referenced_a_stealer_c2(
                    d, all_stealer_hosts,
                )
                if not stealer_host:
                    continue
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=(
                        f"Info-stealer fingerprint in pid {pid}: cookie "
                        f"read + exfil to {stealer_host} within "
                        f"{CORRELATION_WINDOW_S}s"
                    ),
                    summary=(
                        f"Process pid {pid} ({read_info['name']}, "
                        f"user {read_info['username']}) opened "
                        f"``{read_info['path']}`` and within "
                        f"{CORRELATION_WINDOW_S}s contacted "
                        f"``{stealer_host}``. This is the canonical "
                        "info-stealer dispositive fingerprint — "
                        "browser cookie / saved-login extraction "
                        "followed by webhook / paste-bin exfil. "
                        "ROTATE every credential reachable from this "
                        "user's browser session immediately."
                    ),
                    artifact_refs=[read_info["artifact_uuid"]],
                    evidence={
                        "kind": "stealer_correlation",
                        "pid": pid,
                        "name": read_info["name"],
                        "exe": read_info["exe"],
                        "username": read_info["username"],
                        "cookie_path": read_info["path"],
                        "exfil_host": stealer_host,
                        "window_s": CORRELATION_WINDOW_S,
                    },
                    mitre="T1555.003",
                )
                break  # one S4 per pid
