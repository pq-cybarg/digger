"""macOS TCC consent-database detector.

Apple's TCC (Transparency, Consent, Control) database tracks every
permission grant on the host: Camera, Microphone, Screen Recording,
AppleEvents (automation of other apps), Accessibility (keystroke /
synthetic-event injection), Full Disk Access (read every user file),
and ListenEvent / PostEvent (raw input). A compromised TCC entry
gets the app silent, permanent capability — no prompts, no UI.

Modern macOS-malware tradecraft (Shlayer, Silver Sparrow, XCSSET,
JaskaGO, and the commercial spyware families) consistently routes
its persistence through TCC. CVE-2022-26721, CVE-2022-26726,
CVE-2024-27821, CVE-2024-44170 all gave attackers a way to scribble
into TCC.db without the user's knowledge.

Existing collector ``digger.collectors.macos.tcc`` emits one
Artifact per TCC DB (system + user) with every row. This detector
consumes those Artifacts and surfaces:

  T1  Allowed entry for FullDiskAccess + non-Apple binary
  T2  Allowed entry for Accessibility / PostEvent / ListenEvent
      to a non-Apple binary (keystroke-injection primitive)
  T3  Allowed entry granted to a binary in a suspicious path
      (/tmp, /Users/Shared, /private/var/folders, ~/Library/Caches,
      ~/Downloads)
  T4  Allowed entry for ScreenCapture or Camera + non-Apple binary
  T5  User-DB has an entry that the system-DB doesn't have for the
      same client (the textbook "write user TCC.db directly to
      bypass the prompt" pattern — only valid when both DBs were
      collected in the same case)

The detector is *aggressive*: legitimate apps like Zoom, Slack,
1Password, Loom, Bartender will hit T2 / T4. The operator confirms
they expected those grants and suppresses by client identifier.
"""

from __future__ import annotations

from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# TCC service strings that are dangerous when granted to non-Apple
# binaries. Lifted from /System/Library/Frameworks/TCC.framework
# and the public Apple developer docs.
_DANGEROUS_SERVICES_KEY: dict[str, str] = {
    "kTCCServiceSystemPolicyAllFiles":   "fulldisk",
    "kTCCServiceAccessibility":          "accessibility",
    "kTCCServicePostEvent":              "postevent",
    "kTCCServiceListenEvent":            "listenevent",
    "kTCCServiceScreenCapture":          "screencap",
    "kTCCServiceCamera":                 "camera",
    "kTCCServiceMicrophone":             "microphone",
    "kTCCServiceAppleEvents":            "appleevents",
    "kTCCServiceSystemPolicyDesktopFolder":   "desktop",
    "kTCCServiceSystemPolicyDocumentsFolder": "documents",
    "kTCCServiceSystemPolicyDownloadsFolder": "downloads",
    "kTCCServiceSystemPolicyNetworkVolumes":  "network_volumes",
    "kTCCServiceSystemPolicyRemovableVolumes": "removable_volumes",
    "kTCCServiceSystemPolicySysAdminFiles":    "sysadmin_files",
    "kTCCServiceContactsFull":           "contacts_full",
}

# auth_value 2 = Allowed; 3 = Allowed (limited). 0 = denied,
# 1 = unknown. Only 2/3 grant actual capability.
_ALLOWED_AUTH_VALUES = (2, 3)

# Bundle-ID prefixes for Apple-signed clients. The TCC `client`
# column for type=0 (bundle ID) entries; for type=1 (anchor/path)
# clients, we substring-match a known set.
_APPLE_BUNDLE_PREFIXES = (
    "com.apple.",
)

# Path-form clients (client_type=1) that are first-party Apple.
_APPLE_PATH_PREFIXES = (
    "/System/", "/Library/Apple/", "/usr/libexec/", "/sbin/",
    "/usr/sbin/", "/bin/",
)

# Operator-extendable allowlist of bundle IDs we should never flag.
# Loaded from DIGGER_TCC_TRUSTED_CLIENTS (comma-separated).
KNOWN_GOOD_BUNDLE_IDS = {
    "us.zoom.xos",
    "com.microsoft.teams2",
    "com.microsoft.teams",
    "com.tinyspeck.slackmacgap",
    "com.google.Chrome",
    "com.brave.Browser",
    "company.thebrowser.Browser",
    "com.mozilla.firefox",
    "com.1password.1password",
    "com.1password.1password7",
    "com.linear.macapp",
    "com.docker.docker",
    "com.parsec-cloud.Parsec",
    "com.utmapp.UTM",
    "io.runtime.cyberduck",
    "com.loom.desktop",
    "com.cleanshot.cleanshot",
    "com.tencent.xinWeChat",
    "com.runningwithcrayons.Alfred",
    "com.raycast.macos",
    "com.bartender",
    "com.macpaw.CleanMyMac4",
    "anthropic.claude.electron",
    "ai.perplexity.mac",
    "com.openai.chat",
    "com.cursor.app",
    "com.todesktop.230313mzl4w4u92",  # Continue
    "com.warp.dev.Warp",
    "com.kapeli.dashdoc",
    "com.github.Electron",
    "com.electron.vscode",
    "com.microsoft.VSCode",
}


def _trusted_bundle_set() -> tuple[str, ...]:
    import os
    extra = os.environ.get("DIGGER_TCC_TRUSTED_CLIENTS", "")
    parts = [s.strip() for s in extra.split(",") if s.strip()]
    return tuple(sorted(set(KNOWN_GOOD_BUNDLE_IDS) | set(parts)))


# Suspicious path components for path-form (client_type=1) clients.
_SUSPICIOUS_PATH_FRAGMENTS = (
    "/tmp/",
    "/Users/Shared/",
    "/private/var/folders/",
    "/Library/Caches/",
    "/.Trash/",
    "/Downloads/",
    "/private/tmp/",
)


def _is_apple_client(client: str, client_type: int) -> bool:
    if not client:
        return False
    if client_type == 0:
        return any(client.startswith(p) for p in _APPLE_BUNDLE_PREFIXES)
    if client_type == 1:
        return any(client.startswith(p) for p in _APPLE_PATH_PREFIXES)
    return False


def _is_trusted_client(client: str, client_type: int) -> bool:
    if client_type == 0:
        return client in _trusted_bundle_set()
    return False


def _has_suspicious_path(client: str, client_type: int) -> bool:
    if client_type != 1:
        return False
    return any(frag in client for frag in _SUSPICIOUS_PATH_FRAGMENTS)


def _tcc_entry_records(store: EvidenceStore) -> list[tuple[dict, str, str]]:
    """Yield (entry, source_path, artifact_uuid) for every TCC row
    across all collected DBs."""
    out: list[tuple[dict, str, str]] = []
    for art in store.iter_artifacts(collector="macos.tcc"):
        data = art["data"] or {}
        path = data.get("path") or ""
        for e in data.get("entries") or []:
            if isinstance(e, dict):
                out.append((e, path, art["artifact_uuid"]))
    return out


class MacosTccDetector(Detector):
    name = "macos_tcc"
    description = (
        "macOS TCC consent-database analysis: flags Allowed grants "
        "for non-Apple, non-allowlisted apps to high-impact services "
        "(FullDiskAccess, Accessibility, ScreenCapture, "
        "Post/ListenEvent), grants to binaries at suspicious paths, "
        "and user-DB-only grants that bypass the system-DB."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Suspicious macOS TCC consent grant",
            "id": "digger-macos-tcc-template",
            "description": (
                "macOS TCC.db has an Allowed grant for a "
                "high-impact privacy service to a non-Apple, "
                "non-allowlisted client — keystroke injection / "
                "full-disk-read / screen-record persistence."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "macos"},
            "detection": {
                "selection": {
                    "kind": [
                        "tcc_fulldisk_nonapple",
                        "tcc_accessibility_nonapple",
                        "tcc_screencap_camera_nonapple",
                        "tcc_suspicious_path_grant",
                        "tcc_user_db_only_grant",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1543.001", "attack.t1056.001",
                "attack.t1417", "attack.t1113",
                "attack.t1123", "attack.t1125",
                "attack.persistence",
                "attack.collection",
                "attack.credential_access",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        entries = _tcc_entry_records(store)
        if not entries:
            return

        # Group source paths by (client, service) for the T5 cross-DB
        # check. T5 fires when a high-impact service was granted in
        # the per-user TCC.db but NOT in the system TCC.db — the
        # "write user DB directly, bypass the system prompt" pattern.
        system_sources = {
            src for _, src, _ in entries if "/Users/" not in src
        }
        user_sources = {
            src for _, src, _ in entries if "/Users/" in src
        }
        def _auth_value_int(entry: dict) -> int:
            try:
                v = entry.get("auth_value")
                return int(v) if v is not None else 0
            except (TypeError, ValueError):
                return 0

        client_service_to_sources: dict[tuple[str, str], set[str]] = {}
        for entry, src, _uuid in entries:
            if _auth_value_int(entry) not in _ALLOWED_AUTH_VALUES:
                continue
            key = (
                str(entry.get("client") or ""),
                str(entry.get("service") or ""),
            )
            client_service_to_sources.setdefault(key, set()).add(src)

        seen_t5: set[tuple[str, str]] = set()
        for entry, source_path, artifact_uuid in entries:
            yield from self._check_entry(
                entry, source_path, artifact_uuid,
            )
            # T5 cross-DB
            if not system_sources or not user_sources:
                continue   # both DBs must be present to compare
            if "/Users/" not in source_path:
                continue   # only emit T5 from the user side
            service = str(entry.get("service") or "")
            client = str(entry.get("client") or "")
            try:
                client_type_int = int(entry.get("client_type") or 0)
            except (TypeError, ValueError):
                client_type_int = 0
            auth_value_int = _auth_value_int(entry)
            if auth_value_int not in _ALLOWED_AUTH_VALUES:
                continue
            if service not in _DANGEROUS_SERVICES_KEY:
                continue
            if _is_apple_client(client, client_type_int):
                continue
            if _is_trusted_client(client, client_type_int):
                continue
            key = (client, service)
            if key in seen_t5:
                continue
            grants = client_service_to_sources.get(key, set())
            in_user_db = any("/Users/" in s for s in grants)
            in_system_db = any("/Users/" not in s for s in grants)
            if in_user_db and not in_system_db:
                seen_t5.add(key)
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=(
                        f"User-DB-only TCC grant (system DB has no "
                        f"matching entry): {client} → {service}"
                    ),
                    summary=(
                        f"Client ``{client}`` has an Allowed "
                        f"grant for ``{service}`` in the per-user "
                        "TCC.db, but the system-wide TCC.db has "
                        "no matching entry. The textbook "
                        "TCC-bypass shape: rather than route the "
                        "consent through the system prompt, the "
                        "attacker wrote directly into the user's "
                        "TCC.db. CVE-2022-26726, CVE-2024-27821 "
                        "and a long list of XCSSET / Shlayer / "
                        "JaskaGO variants used this path. "
                        "Verify by checking whether the user "
                        "remembers seeing the consent prompt; if "
                        "not, treat as compromise."
                    ),
                    artifact_refs=[artifact_uuid],
                    evidence={
                        "kind": "tcc_user_db_only_grant",
                        "client": client,
                        "service": service,
                        "client_type": client_type_int,
                        "user_db_source": source_path,
                    },
                    mitre="T1543.001",
                )

    def _check_entry(
        self,
        entry: dict,
        source_path: str,
        artifact_uuid: str,
    ) -> Iterable[Finding]:
        service = str(entry.get("service") or "")
        client = str(entry.get("client") or "")
        client_type = entry.get("client_type")
        try:
            client_type_int = int(client_type) if client_type is not None else -1
        except (TypeError, ValueError):
            client_type_int = -1
        auth_value = entry.get("auth_value")
        try:
            auth_value_int = int(auth_value) if auth_value is not None else 0
        except (TypeError, ValueError):
            auth_value_int = 0

        if auth_value_int not in _ALLOWED_AUTH_VALUES:
            return
        if service not in _DANGEROUS_SERVICES_KEY:
            return
        if _is_apple_client(client, client_type_int):
            return
        if _is_trusted_client(client, client_type_int):
            return

        # T3 suspicious path
        if _has_suspicious_path(client, client_type_int):
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"TCC grant to binary in suspicious path: "
                    f"{client} → {service}"
                ),
                summary=(
                    f"Client ``{client}`` (path-form) has an "
                    f"Allowed grant for ``{service}`` in "
                    f"``{source_path}``. The binary lives in a "
                    "world-writable / scratch location commonly "
                    "used as a malware staging directory. macOS "
                    "TCC tracks the binary's path; if it gets "
                    "replaced or executed from a scratch dir, "
                    "the consent persists silently."
                ),
                artifact_refs=[artifact_uuid],
                evidence={
                    "kind": "tcc_suspicious_path_grant",
                    "client": client,
                    "service": service,
                    "source_path": source_path,
                    "auth_value": auth_value_int,
                },
                mitre="T1543.001",
            )
            return

        service_class = _DANGEROUS_SERVICES_KEY[service]

        # T1 full-disk access for non-Apple binary
        if service_class in (
            "fulldisk", "sysadmin_files",
            "documents", "desktop", "downloads",
            "network_volumes", "removable_volumes",
        ):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"FullDiskAccess-class TCC grant to "
                    f"non-Apple client: {client} → {service}"
                ),
                summary=(
                    f"Client ``{client}`` has an Allowed grant "
                    f"for ``{service}`` in ``{source_path}``. "
                    "FullDiskAccess and the per-folder variants "
                    "let an app read every file under that scope "
                    "without further prompts — the textbook "
                    "credential-harvesting + cloud-token-theft "
                    "vector on macOS. Verify the app should have "
                    "this grant; add to the trusted-client "
                    "allowlist via "
                    "``DIGGER_TCC_TRUSTED_CLIENTS`` if expected."
                ),
                artifact_refs=[artifact_uuid],
                evidence={
                    "kind": "tcc_fulldisk_nonapple",
                    "client": client,
                    "service": service,
                    "client_type": client_type_int,
                    "source_path": source_path,
                },
                mitre="T1543.001",
            )
            return

        # T2 keystroke-injection class (Accessibility / PostEvent / ListenEvent)
        if service_class in (
            "accessibility", "postevent", "listenevent",
        ):
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"Keystroke-injection-class TCC grant to "
                    f"non-Apple client: {client} → {service}"
                ),
                summary=(
                    f"Client ``{client}`` has an Allowed grant "
                    f"for ``{service}``. Accessibility / "
                    "PostEvent / ListenEvent give the app the "
                    "ability to inject keystrokes, read raw input "
                    "(keylogger), and drive other apps' UI. The "
                    "canonical macOS spyware primitive — Pegasus, "
                    "OSX/Crisis, OSX/Cocyer, JaskaGO all required "
                    "Accessibility. Verify the user actually "
                    "approved this grant."
                ),
                artifact_refs=[artifact_uuid],
                evidence={
                    "kind": "tcc_accessibility_nonapple",
                    "client": client,
                    "service": service,
                    "client_type": client_type_int,
                    "source_path": source_path,
                },
                mitre="T1056.001",
            )
            return

        # T4 screen / camera / microphone / appleevents
        if service_class in (
            "screencap", "camera", "microphone", "appleevents",
            "contacts_full",
        ):
            mitre_map = {
                "screencap":     "T1113",
                "camera":        "T1125",
                "microphone":    "T1123",
                "appleevents":   "T1559.001",
                "contacts_full": "T1087",
            }
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Surveillance-class TCC grant to non-Apple "
                    f"client: {client} → {service}"
                ),
                summary=(
                    f"Client ``{client}`` has an Allowed grant "
                    f"for ``{service}``. Screen recording / "
                    "camera / microphone / AppleEvents are the "
                    "core surveillance + automation services. "
                    "Many legit apps (Zoom, Slack, Loom, "
                    "CleanShot) hit this — extend the trusted-"
                    "client allowlist via "
                    "``DIGGER_TCC_TRUSTED_CLIENTS`` to suppress "
                    "expected grants."
                ),
                artifact_refs=[artifact_uuid],
                evidence={
                    "kind": "tcc_screencap_camera_nonapple",
                    "client": client,
                    "service": service,
                    "service_class": service_class,
                    "client_type": client_type_int,
                    "source_path": source_path,
                },
                mitre=mitre_map.get(service_class, "T1113"),
            )
            return

