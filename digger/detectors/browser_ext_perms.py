"""Browser extension permission-combination detector.

The existing BrowserDetector flags any extension that holds at
least one risky permission. The output is a single medium-severity
finding the operator has to decode by hand. This detector runs
alongside it and emits actionable, finer-grained findings keyed
to specific permission *combinations* — each is a documented
malicious-extension fingerprint:

  B1  Native messaging:            high   (T1071.001)
      Permission ``nativeMessaging`` lets the extension talk to a
      host binary over a stdin/stdout JSON-RPC channel. Rare in
      legitimate extensions (1Password, LastPass, browser-tab
      managers); ubiquitous in commercial spyware and adware
      droppers.

  B2  All-URLs + webRequestBlocking: critical (T1557 / T1556)
      Combination lets the extension intercept, inspect, modify,
      or block every HTTP request the browser makes. The "adblock
      that's actually an evil-twin" pattern.

  B3  All-URLs + cookies + tabs:    high     (T1539 / T1185)
      Session-theft fingerprint — extension can read every site's
      cookies and exfil them via tab updates.

  B4  Proxy permission:             high     (T1090 / T1557)
      ``proxy`` lets the extension route all browser traffic
      through an attacker-controlled relay.

  B5  Debugger permission:          high     (T1056.001 / T1622)
      ``debugger`` attaches to other tabs via the Chrome DevTools
      Protocol — read DOM, execute JS, snapshot state. Very
      rarely needed in shipped extensions.

  B6  Spy stack (all_urls + tabs + storage + runtime + scripting):  medium
      Generic surveillance fingerprint. Many legitimate
      extensions (LastPass, Honey, Grammarly) hit this — the
      finding is medium-severity and informs operator review.

  B7  Hardware-bridging permission: medium   (T1543)
      ``usbDevices`` / ``printerProvider`` / ``vpnProvider`` /
      ``platformKeys`` give the extension access to peripherals
      or the platform key store. Very narrow legit set.

  B8  declarativeNetRequest + many host_permissions: medium
      Newer manifest-v3 cousin of B2. Less powerful (declarative
      not arbitrary code) but with many host patterns, becomes
      equivalent surveillance surface.
"""

from __future__ import annotations

from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# Perm names — match Chrome/Edge/Firefox manifest values.
_NATIVE_MESSAGING = "nativeMessaging"
_WEB_REQUEST = "webRequest"
_WEB_REQUEST_BLOCKING = "webRequestBlocking"
_COOKIES = "cookies"
_TABS = "tabs"
_STORAGE = "storage"
_RUNTIME = "runtime"
_SCRIPTING = "scripting"
_PROXY = "proxy"
_DEBUGGER = "debugger"
_DECL_NET_REQUEST = "declarativeNetRequest"
_DECL_NET_REQUEST_FB = "declarativeNetRequestWithHostAccess"
_USB = "usbDevices"
_PRINTER = "printerProvider"
_VPN = "vpnProvider"
_PLATFORM_KEYS = "platformKeys"
_HARDWARE_PERMS = {_USB, _PRINTER, _VPN, _PLATFORM_KEYS}

_ALL_URLS_TOKENS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def _ext_iter_from_artifact(art):
    """Yield each extension dict from an entries-bearing browser
    extension artifact."""
    if "extensions" not in (art.get("subject") or ""):
        return
    data = art.get("data") or {}
    for ext in data.get("entries") or []:
        if isinstance(ext, dict):
            yield ext


def _ext_perms(ext: dict) -> set[str]:
    return set(ext.get("permissions") or [])


def _ext_host_perms(ext: dict) -> list[str]:
    return ext.get("host_permissions") or []


def _has_all_urls(ext: dict) -> bool:
    hp = _ext_host_perms(ext)
    if any(t in hp for t in _ALL_URLS_TOKENS):
        return True
    perms = _ext_perms(ext)
    return any(t in perms for t in _ALL_URLS_TOKENS)


def _ext_label(ext: dict) -> str:
    name = ext.get("name") or ext.get("id") or "?"
    ext_id = ext.get("id") or "?"
    return f"{name} ({ext_id})"


class BrowserExtensionPermsDetector(Detector):
    name = "browser_ext_perms"
    description = (
        "Browser extension permission-combination audit: native "
        "messaging, webRequest blocking + all_urls, cookies + "
        "all_urls + tabs (session-theft), proxy / debugger "
        "permissions, spy stack, hardware bridges, "
        "declarativeNetRequest + many host permissions."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Browser extension permission-combination risk",
            "id": "digger-browser-ext-perms-template",
            "description": (
                "Browser extension holds a documented malicious-"
                "extension permission fingerprint."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "browser"},
            "detection": {
                "selection": {
                    "kind": [
                        "native_messaging",
                        "webrequest_blocking_all_urls",
                        "all_urls_cookies_tabs",
                        "proxy_permission",
                        "debugger_permission",
                        "spy_stack",
                        "hardware_bridge",
                        "decl_net_request_broad",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1176", "attack.t1185", "attack.t1539",
                "attack.t1071.001", "attack.t1557", "attack.t1556",
                "attack.t1090", "attack.t1056.001",
                "attack.t1543", "attack.t1622",
                "attack.collection", "attack.credential_access",
                "attack.command_and_control",
                "attack.defense_evasion",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(category="browser"):
            for ext in _ext_iter_from_artifact(art):
                yield from self._check_extension(ext, art)

    def _check_extension(self, ext: dict, art) -> Iterable[Finding]:
        perms = _ext_perms(ext)
        hp = _ext_host_perms(ext)
        label = _ext_label(ext)
        ref = art["artifact_uuid"]
        all_urls = _has_all_urls(ext)

        # B1 native messaging
        if _NATIVE_MESSAGING in perms:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Browser extension holds nativeMessaging "
                    f"permission: {label}"
                ),
                summary=(
                    f"Extension ``{label}`` declares the "
                    "``nativeMessaging`` permission. The "
                    "extension can pipe stdin/stdout to a host-"
                    "side binary registered in the user's "
                    "NativeMessagingHosts manifest — a clean "
                    "browser ↔ shell bridge. Legitimate uses "
                    "exist (1Password, LastPass, Bitwarden, "
                    "browser-tab managers) but the perm is the "
                    "primary primitive for ad-injectors and "
                    "credential-stealing browser malware. "
                    "Verify the matching native-host manifest in "
                    "``~/Library/Application Support/.../"
                    "NativeMessagingHosts/`` (macOS) or the "
                    "equivalent registry entry on Windows."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "native_messaging",
                    "extension_id": ext.get("id"),
                    "name": ext.get("name"),
                    "permissions": sorted(perms),
                },
                mitre="T1071.001",
            )

        # B2 webRequest blocking + all_urls (critical)
        if (_WEB_REQUEST_BLOCKING in perms
                or _WEB_REQUEST in perms) and all_urls:
            blocking = _WEB_REQUEST_BLOCKING in perms
            sev = "critical" if blocking else "high"
            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"Browser extension can "
                    f"{'modify' if blocking else 'observe'} every "
                    f"HTTP request: {label}"
                ),
                summary=(
                    f"Extension ``{label}`` holds "
                    f"{'webRequestBlocking' if blocking else 'webRequest'} "
                    "+ ``<all_urls>``. Manifest-V2 extensions "
                    "with this combination can intercept, "
                    "inspect, modify, or block every HTTP "
                    "request the browser makes — the "
                    "evil-adblock fingerprint (DataSpii et al). "
                    "Manifest-V3 deprecates webRequestBlocking "
                    "for general use, so seeing it in 2025+ is "
                    "noteworthy on its own."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "webrequest_blocking_all_urls",
                    "extension_id": ext.get("id"),
                    "name": ext.get("name"),
                    "blocking": blocking,
                    "host_permissions": hp,
                },
                mitre="T1557",
            )

        # B3 all_urls + cookies + tabs (session theft fingerprint)
        if all_urls and _COOKIES in perms and _TABS in perms:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Browser extension can steal session "
                    f"cookies: {label}"
                ),
                summary=(
                    f"Extension ``{label}`` holds the "
                    "session-theft combination: ``<all_urls>`` + "
                    "``cookies`` + ``tabs``. Read every site's "
                    "cookies, identify the user's logged-in "
                    "sessions, and exfil them via tab updates "
                    "or a configured C2. Legitimate password "
                    "managers fit this shape — operator should "
                    "verify the extension matches a known "
                    "password manager + the publisher is one "
                    "they expect."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "all_urls_cookies_tabs",
                    "extension_id": ext.get("id"),
                    "name": ext.get("name"),
                    "permissions": sorted(perms),
                    "host_permissions": hp,
                },
                mitre="T1539",
            )

        # B4 proxy permission
        if _PROXY in perms:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Browser extension holds proxy permission: "
                    f"{label}"
                ),
                summary=(
                    f"Extension ``{label}`` declares the "
                    "``proxy`` permission. The extension can "
                    "configure or override Chrome's proxy "
                    "settings, routing all browser traffic "
                    "through an attacker-controlled relay. "
                    "Legit cases (VPN extensions) exist but are "
                    "rare — verify the user installed a VPN "
                    "intentionally."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "proxy_permission",
                    "extension_id": ext.get("id"),
                    "name": ext.get("name"),
                },
                mitre="T1090",
            )

        # B5 debugger permission
        if _DEBUGGER in perms:
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Browser extension holds debugger "
                    f"permission: {label}"
                ),
                summary=(
                    f"Extension ``{label}`` declares the "
                    "``debugger`` permission. Attaches to other "
                    "tabs via Chrome DevTools Protocol — read "
                    "DOM, execute JS, snapshot state. Very rarely "
                    "needed by shipped extensions; legitimate "
                    "users are mostly browser-automation tools. "
                    "Spyware (Cyclops Blink-class browser "
                    "implants) uses it to record everything the "
                    "user does."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "debugger_permission",
                    "extension_id": ext.get("id"),
                    "name": ext.get("name"),
                },
                mitre="T1056.001",
            )

        # B6 spy stack
        spy_stack_perms = {_TABS, _STORAGE, _RUNTIME, _SCRIPTING}
        if all_urls and spy_stack_perms.issubset(perms):
            # Only emit if no stronger finding already fired
            # (B2/B3 already cover the dangerous cases).
            already_covered = (
                ((_WEB_REQUEST_BLOCKING in perms) or (_WEB_REQUEST in perms))
                or (_COOKIES in perms and _TABS in perms)
            )
            if not already_covered:
                yield Finding(
                    detector=self.name,
                    severity="medium",
                    title=(
                        f"Browser extension matches surveillance "
                        f"stack fingerprint: {label}"
                    ),
                    summary=(
                        f"Extension ``{label}`` holds "
                        "``<all_urls>`` + ``tabs`` + ``storage`` "
                        "+ ``runtime`` + ``scripting``. Generic "
                        "surveillance fingerprint — extension "
                        "can observe every tab, inject scripts "
                        "into every page, and persist state. "
                        "Many legitimate extensions (LastPass, "
                        "Honey, Grammarly, AdBlock, uBlock) "
                        "fit this shape. Confirm publisher + "
                        "verify the extension is one the user "
                        "deliberately installed."
                    ),
                    artifact_refs=[ref],
                    evidence={
                        "kind": "spy_stack",
                        "extension_id": ext.get("id"),
                        "name": ext.get("name"),
                        "permissions": sorted(perms),
                    },
                    mitre="T1176",
                )

        # B7 hardware bridge
        hardware_hits = perms & _HARDWARE_PERMS
        if hardware_hits:
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"Browser extension holds hardware-bridge "
                    f"permission(s): {label}"
                ),
                summary=(
                    f"Extension ``{label}`` declares hardware-"
                    f"bridging permissions: "
                    f"``{sorted(hardware_hits)}``. Browser "
                    "extensions usually don't need physical "
                    "device access; usbDevices, printerProvider, "
                    "vpnProvider, and platformKeys are rarely "
                    "legitimate. Confirm the extension's stated "
                    "purpose matches the hardware it can touch."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "hardware_bridge",
                    "extension_id": ext.get("id"),
                    "name": ext.get("name"),
                    "permissions": sorted(hardware_hits),
                },
                mitre="T1543",
            )

        # B8 declarativeNetRequest with many host_permissions
        has_dnr = (
            _DECL_NET_REQUEST in perms
            or _DECL_NET_REQUEST_FB in perms
        )
        if has_dnr and len(hp) >= 20:
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    f"declarativeNetRequest extension with "
                    f"{len(hp)} host patterns: {label}"
                ),
                summary=(
                    f"Extension ``{label}`` holds "
                    "``declarativeNetRequest`` and "
                    f"{len(hp)} explicit host patterns. The "
                    "manifest-v3 cousin of webRequest. With "
                    "broad host coverage, becomes an equivalent "
                    "surveillance surface — every match-listed "
                    "site's traffic is subject to declarative "
                    "rewrites."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "decl_net_request_broad",
                    "extension_id": ext.get("id"),
                    "name": ext.get("name"),
                    "host_count": len(hp),
                    "host_sample": hp[:10],
                },
                mitre="T1557",
            )
