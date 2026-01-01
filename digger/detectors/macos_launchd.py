"""macOS launchd plist deep-audit detector.

The existing ``persistence_outlier`` detector flags launchd plists
whose programs live in writable temp dirs. This detector covers
the macOS-launchd-specific patterns it MISSES:

  L1  Network-fetch in ProgramArguments:   high
      Plist runs ``/bin/sh -c "curl ... | sh"``, ``/usr/bin/python
      -c "import urllib..."`` or similar download cradle. Almost
      always malicious in a launchd context.

  L2  Encoded payload in ProgramArguments: medium
      Long base64 / hex blob in arguments. Common hiding place for
      shellcode or a one-line python downloader.

  L3  Label / filename mismatch:           medium
      Plist filename is ``com.evil.something.plist`` but the
      ``Label`` key inside is ``com.apple.softwareupdate``. Common
      masquerading pattern (Silver Sparrow / OSX-Cocyer / JaskaGO).

  L4  WatchPaths / QueueDirectories on writable dirs: high
      Event-triggered exec from a writable location — anyone who
      can write to that path can trigger the launchd payload. A
      classic "drop a file, get RCE" persistence chain.

  L5  Empty Label key:                     medium
      Most legit plists set Label. Empty / missing Label is
      uncommon and worth surfacing.

  L6  Suspicious interpreter + KeepAlive:  high
      Plist runs an interpreter (sh / bash / zsh / osascript /
      python / ruby / perl / curl / nc / socat) with KeepAlive
      true — i.e. respawn forever. Daemon-shaped malware
      almost always has this combination.

  L7  Plist runs osascript:                medium
      AppleScript runner is a privilege-escalation primitive
      (drives other apps via AppleEvents) and rarely needed in
      a daemon. Worth a manual review.

The existing persistence_outlier detector handles "binary lives
in /tmp / /Users/Shared" — we don't repeat that.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- pattern matchers ---- #

_INTERPRETERS = (
    "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash",
    "/usr/bin/python", "/usr/bin/python3", "/usr/local/bin/python3",
    "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/php",
    "/usr/bin/osascript",
    "sh", "bash", "zsh", "python", "python3",
    "perl", "ruby", "osascript",
)

_NETWORK_FETCH_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|socat|fetch|"
    r"do shell script\s+\"curl|"
    r"urllib|urllib2|urllib\.request|http\.client|requests\.get)",
    re.IGNORECASE,
)
_PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget|fetch)[^|]*\|\s*(?:sh|bash|zsh|/bin/sh|/bin/bash)",
    re.IGNORECASE,
)
_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_LONG_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}|(?:[0-9a-fA-F]{2}){80,}")

_USER_WRITABLE_PATH_FRAGMENTS = (
    "/Users/", "/private/var/folders/", "/tmp/",
    "/private/tmp/", "/Users/Shared/", "/Library/Caches/",
    "/var/tmp/",
)


def _argv_to_str(program_arguments) -> str:
    if program_arguments is None:
        return ""
    if isinstance(program_arguments, str):
        return program_arguments
    if isinstance(program_arguments, (list, tuple)):
        return " ".join(str(a) for a in program_arguments)
    return str(program_arguments)


def _looks_writable(p: str) -> bool:
    if not p:
        return False
    return any(frag in p for frag in _USER_WRITABLE_PATH_FRAGMENTS)


def _filename_label_match(path: str, label: str) -> bool:
    """The plist Label by convention matches the filename stem."""
    if not path or not label:
        return True  # can't determine
    import os
    stem = os.path.splitext(os.path.basename(path))[0]
    return stem.lower() == label.lower()


class MacosLaunchdDetector(Detector):
    name = "macos_launchd"
    description = (
        "macOS launchd plist deep audit: network-fetch in "
        "ProgramArguments, encoded payloads, Label/filename "
        "mismatch, event triggers on writable dirs, suspicious "
        "interpreter + KeepAlive, osascript runners."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Suspicious macOS launchd plist",
            "id": "digger-macos-launchd-template",
            "description": (
                "macOS LaunchAgent/LaunchDaemon plist matches a "
                "malware-style pattern (network-fetch, encoded "
                "payload, Label/filename mismatch, WatchPaths on "
                "writable dir, persistent interpreter)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "macos"},
            "detection": {
                "selection": {
                    "kind": [
                        "launchd_network_fetch",
                        "launchd_encoded_payload",
                        "launchd_label_mismatch",
                        "launchd_writable_trigger",
                        "launchd_empty_label",
                        "launchd_interpreter_keepalive",
                        "launchd_osascript",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1543.001", "attack.t1059.004",
                "attack.t1059.002", "attack.t1027",
                "attack.t1036",
                "attack.persistence",
                "attack.execution",
                "attack.defense_evasion",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="macos.launchd"):
            yield from self._check_plist(art)

    def _check_plist(self, art) -> Iterable[Finding]:
        data = art["data"] or {}
        path = data.get("path") or ""
        label = data.get("label") or ""
        ref = art["artifact_uuid"]

        # Skip Apple's own /System/Library/Launch* plists — they're
        # SIP-protected and any compromise there means digger's a
        # noise-detector, not the right tool.
        path_lower = path.lower()
        if path_lower.startswith("/system/library/launchdaemons/") or \
                path_lower.startswith("/system/library/launchagents/"):
            if label.lower().startswith("com.apple."):
                return

        argv = _argv_to_str(data.get("program_arguments"))
        program = data.get("program") or ""
        full_text = " ".join([str(program), argv])

        keep_alive = bool(data.get("keep_alive"))
        run_at_load = bool(data.get("run_at_load"))

        # L1 network fetch in ProgramArguments
        net_match = _NETWORK_FETCH_RE.search(full_text)
        pipe_match = _PIPE_TO_SHELL_RE.search(full_text)
        if net_match or pipe_match:
            sev = "critical" if pipe_match else "high"
            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"Launchd plist runs network-fetch command: "
                    f"{label or path}"
                ),
                summary=(
                    f"Plist ``{path}`` (label ``{label}``) runs "
                    f"``{argv[:200]}``. A launchd plist that "
                    "fetches from the network on every load is "
                    "almost always a malware downloader — Silver "
                    "Sparrow, Shlayer, OSAMiner, BundloreRunner "
                    "all use this exact pattern. The "
                    "RunAtLoad / KeepAlive flags determine "
                    "whether it runs once or persistently."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "launchd_network_fetch",
                    "path": path,
                    "label": label,
                    "program": program,
                    "args_snippet": argv[:400],
                    "run_at_load": run_at_load,
                    "keep_alive": keep_alive,
                    "pipe_to_shell": bool(pipe_match),
                },
                mitre="T1543.001",
            )

        # L2 encoded payload
        if _LONG_BASE64_RE.search(full_text) or _LONG_HEX_RE.search(full_text):
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Launchd plist contains long encoded payload: "
                    f"{label or path}"
                ),
                summary=(
                    f"Plist ``{path}`` carries a long base64 or "
                    "hex sequence in its ProgramArguments. "
                    "Sometimes legitimate (cert pinning, config "
                    "data), often a hidden Python/shell payload. "
                    "Decode and review."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "launchd_encoded_payload",
                    "path": path,
                    "label": label,
                    "args_snippet": argv[:400],
                },
                mitre="T1027",
            )

        # L3 Label/filename mismatch (masquerading)
        if label and path and not _filename_label_match(path, label):
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Launchd plist Label doesn't match "
                    f"filename: {label} ≠ {path}"
                ),
                summary=(
                    f"Plist file ``{path}`` declares Label "
                    f"``{label}``. By Apple convention these "
                    "should match (file stem = label). A "
                    "mismatch can be benign (operator-installed "
                    "tooling) but is a documented masquerade "
                    "pattern — OSX/Silver Sparrow, "
                    "OSX/Cocyer, JaskaGO all use a "
                    "``com.apple.*`` Label inside a "
                    "non-Apple-named plist."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "launchd_label_mismatch",
                    "path": path,
                    "label": label,
                },
                mitre="T1036",
            )

        # L4 WatchPaths / QueueDirectories on writable dirs
        wp = data.get("watch_paths") or []
        qd = data.get("queue_directories") or []
        watched_writable: list[str] = []
        if isinstance(wp, list):
            watched_writable += [p for p in wp
                                  if isinstance(p, str)
                                  and _looks_writable(p)]
        if isinstance(qd, list):
            watched_writable += [p for p in qd
                                  if isinstance(p, str)
                                  and _looks_writable(p)]
        if watched_writable:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Launchd plist triggered by writable "
                    f"directory: {label or path}"
                ),
                summary=(
                    f"Plist ``{path}`` is triggered by changes "
                    f"to: ``{', '.join(watched_writable[:5])}``. "
                    "WatchPaths and QueueDirectories cause the "
                    "plist's program to execute whenever a file "
                    "in those locations changes — when the "
                    "triggering location is user-writable, "
                    "anyone with write access to that path can "
                    "fire the payload."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "launchd_writable_trigger",
                    "path": path,
                    "label": label,
                    "watched": watched_writable,
                },
                mitre="T1546",
            )

        # L5 empty/missing Label
        if label == "" or label is None:
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Launchd plist missing Label key: {path}"
                ),
                summary=(
                    f"Plist ``{path}`` has no Label key. Most "
                    "legitimate plists set Label (it's how "
                    "launchctl references them). Unlabeled "
                    "plists still load — but they're a malware-"
                    "behaviour signature worth surfacing."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "launchd_empty_label",
                    "path": path,
                },
                mitre="T1543.001",
            )

        # L6 interpreter + KeepAlive
        if keep_alive and any(
            i in (program or "") or i in argv
            for i in _INTERPRETERS
        ):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Launchd interpreter respawn loop: "
                    f"{label or path}"
                ),
                summary=(
                    f"Plist ``{path}`` runs an interpreter "
                    f"(``{program or argv.split()[0] if argv else '?'}``) "
                    "with KeepAlive=true — launchd will keep "
                    "respawning it forever. Combined with the "
                    "interpreter-vs-compiled-binary choice, this "
                    "is the daemon-shaped malware fingerprint."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "launchd_interpreter_keepalive",
                    "path": path,
                    "label": label,
                    "program": program,
                    "args_snippet": argv[:400],
                },
                mitre="T1059.004",
            )

        # L7 osascript
        if "osascript" in (program or "") or "osascript" in argv:
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Launchd plist runs osascript: "
                    f"{label or path}"
                ),
                summary=(
                    f"Plist ``{path}`` runs ``osascript``. "
                    "AppleScript can drive other apps via "
                    "AppleEvents, prompt for credentials, scrape "
                    "browser state — privilege-escalation "
                    "primitive. Legitimate uses exist (Bartender, "
                    "Hammerspoon) but rare in a daemon. Verify."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "launchd_osascript",
                    "path": path,
                    "label": label,
                    "args_snippet": argv[:400],
                },
                mitre="T1059.002",
            )
