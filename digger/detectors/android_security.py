"""Android device security detector.

Consumes Artifacts emitted by ``digger.android.collect_device`` and
flags the modern Android-attack patterns:

  A1  Installed from a non-trusted source.
      install_source is empty (sideloaded), or one of the well-
      known stalkerware-distribution apps (com.android.fileinstall),
      or the ``com.android.shell`` (adb install on a device the
      operator doesn't own). Medium per package.

  A2  AccessibilityService abuse fingerprint.
      Package requests / is granted BIND_ACCESSIBILITY_SERVICE AND
      the install source is NOT Google Play (and not a system app).
      Modern Android banking trojans (Anubis, Cerberus, ERMAC,
      SharkBot, Coper) absolutely require Accessibility to drain
      accounts. Critical.

  A3  Device admin / device-owner unexpectedly granted.
      Package has BIND_DEVICE_ADMIN granted AND came from a
      non-Play source. Device-policy lock-in is how stalkerware /
      ransomware survives. Critical.

  A4  Dangerous permission combination.
      Cross of (READ_SMS or RECEIVE_SMS) + (READ_CONTACTS or
      READ_CALL_LOG) + (CAMERA or RECORD_AUDIO or
      ACCESS_FINE_LOCATION) for a non-system, non-Play app. The
      "swiss-army-knife spyware" pattern. High.

  A5  Outdated security patch.
      ro.build.version.security_patch older than ~6 months. Single
      info-level finding, surfaced to the operator so unpatched
      shipping devices show up in the report.

  A6  install_non_market_apps was set globally.
      Pre-Android-8 toggle; if Settings.Global.install_non_market_apps
      ever was "1", the device was put in a state that lets any
      source install. Medium.

The detector is *aggressive*: any of these on a personal device is
worth surfacing, even if the user knows it. On a corporate-owned
device with EMM the operator can suppress by category.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- tunables ---- #

PLAY_STORE_PKGS = {
    "com.android.vending",          # Play Store
    "com.google.android.packageinstaller",  # legitimate Play installer
}

SAFE_SIDELOAD_INSTALLERS = {
    "com.google.android.apps.work.clouddpc",       # Android EMM
    "com.google.android.apps.work.cloudd",
    "com.android.shell",  # adb (note: dual-use; we still report)
}

STALKERWARE_KNOWN_INSTALLERS = {
    "com.android.fileinstall",
    "com.example.fileinstall",
    "com.system.helper",
}

# Permission groups
_ACCESSIBILITY_PERMS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}
_DEVICE_ADMIN_PERMS = {
    "android.permission.BIND_DEVICE_ADMIN",
}
_SMS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
}
_CONTACT_PERMS = {
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
}
_SENSITIVE_PERMS = {
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
}

# 180 days
_PATCH_STALE_DAYS = 180


def _is_play_source(install_source: str) -> bool:
    return install_source.strip() in PLAY_STORE_PKGS


def _is_known_stalkerware_installer(install_source: str) -> bool:
    return install_source.strip() in STALKERWARE_KNOWN_INSTALLERS


class AndroidSecurityDetector(Detector):
    name = "android_security"
    description = (
        "Modern Android-device attack patterns over the adb "
        "collector: sideloaded installs, AccessibilityService "
        "abuse fingerprint, unexpected device-admin grants, "
        "swiss-army-knife permission combos, outdated security "
        "patches, install_non_market_apps toggle."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Android device security",
            "id": "digger-android-security-template",
            "description": (
                "AccessibilityService abuse / sideloaded install / "
                "device-admin / sensitive-permission-combo on an "
                "adb-attached Android device."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "android"},
            "detection": {
                "selection": {
                    "kind": [
                        "sideload", "accessibility_abuse",
                        "device_admin_unexpected",
                        "permission_combo_swissarmy",
                        "stale_security_patch",
                        "non_market_installs_enabled",
                    ],
                },
                "condition": "selection",
            },
            "level": "high",
            "tags": [
                "attack.t1417", "attack.t1437.001",
                "attack.t1404", "attack.t1623",
                "attack.t1626", "attack.t1429",
                "attack.t1430", "attack.t1633",
                "attack.t1636.003", "attack.t1636.004",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        for art in store.iter_artifacts(collector="android.package",
                                          category="mobile"):
            yield from self._check_package(art)
        for art in store.iter_artifacts(
            collector="android.security_patch",
            category="mobile",
        ):
            yield from self._check_security_patch(art)
        for art in store.iter_artifacts(
            collector="android.install_non_market_apps",
            category="mobile",
        ):
            yield from self._check_non_market_apps(art)

    def _check_package(self, art) -> Iterable[Finding]:
        data = art["data"] or {}
        name = data.get("name") or "?"
        is_system = data.get("is_system") or False
        install_source = (data.get("install_source") or "").strip()
        granted = set(data.get("granted_permissions") or [])
        requested = set(data.get("requested_permissions") or [])
        serial = data.get("serial") or ""
        ref = art["artifact_uuid"]

        # ---- A1 sideload ---- #
        if not is_system and install_source and \
                not _is_play_source(install_source):
            sev = "high" if _is_known_stalkerware_installer(
                install_source,
            ) else "medium"
            yield Finding(
                detector=self.name,
                severity=sev,
                title=(
                    f"Sideloaded Android package: {name} "
                    f"(installer={install_source})"
                ),
                summary=(
                    f"Package ``{name}`` on device ``{serial}`` was "
                    f"installed by ``{install_source}``, not the "
                    "Google Play store. Sideloaded apps lack Play "
                    "Protect's review pipeline and are the primary "
                    "vehicle for Android banking trojans / "
                    "stalkerware / commercial spyware (Pegasus, "
                    "Predator). Verify the user knew about this "
                    "install."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "sideload",
                    "package": name,
                    "install_source": install_source,
                    "serial": serial,
                },
                mitre="T1404",
            )

        # ---- A2 accessibility abuse fingerprint ---- #
        if granted & _ACCESSIBILITY_PERMS and \
                not is_system and not _is_play_source(install_source):
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"AccessibilityService abuse fingerprint: "
                    f"{name}"
                ),
                summary=(
                    f"Package ``{name}`` is granted "
                    "BIND_ACCESSIBILITY_SERVICE, is not a system "
                    f"package, and was not installed from Google "
                    f"Play (installer=``{install_source or '<empty>'}``). "
                    "Modern Android banking trojans (Anubis, "
                    "Cerberus, ERMAC, SharkBot, Coper, "
                    "BRATA, BlackRock) require Accessibility to "
                    "drain bank apps; commercial stalkerware "
                    "requires it to log everything on screen. "
                    "Open Settings → Accessibility and remove "
                    "the service if the user doesn't recognize "
                    "it."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "accessibility_abuse",
                    "package": name,
                    "install_source": install_source,
                    "serial": serial,
                },
                mitre="T1417",
            )

        # ---- A3 unexpected device-admin ---- #
        if granted & _DEVICE_ADMIN_PERMS and \
                not is_system and not _is_play_source(install_source):
            yield Finding(
                detector=self.name,
                severity="critical",
                title=(
                    f"Device-admin granted to non-Play package: "
                    f"{name}"
                ),
                summary=(
                    f"Package ``{name}`` holds BIND_DEVICE_ADMIN. "
                    "Device-admin lets an app prevent uninstall, "
                    "wipe the device, force lock-screen "
                    "passwords, and block other apps. On a "
                    "non-EMM device this is almost always "
                    "malware (Doctor-Web reported many families "
                    "abusing device-admin as their persistence "
                    "primitive)."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "device_admin_unexpected",
                    "package": name,
                    "install_source": install_source,
                    "serial": serial,
                },
                mitre="T1626",
            )

        # ---- A4 swiss-army-knife permission combo ---- #
        all_perms = granted | requested
        if (all_perms & _SMS_PERMS) and \
                (all_perms & _CONTACT_PERMS) and \
                (all_perms & _SENSITIVE_PERMS) and \
                not is_system and not _is_play_source(install_source):
            yield Finding(
                detector=self.name,
                severity="high",
                title=(
                    f"Swiss-army-knife permission combo: {name}"
                ),
                summary=(
                    f"Package ``{name}`` holds the "
                    "stalkerware-style permission combo: SMS + "
                    "contacts/call-log + at least one sensor "
                    "(camera / mic / location). Legitimate apps "
                    "rarely need all three groups. Stalkerware "
                    "(mSpy, FlexiSpy, KidsGuard) and commercial "
                    "spyware require exactly this combination to "
                    "log every conversation channel the device "
                    "owner uses."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "permission_combo_swissarmy",
                    "package": name,
                    "sms_perms": sorted(all_perms & _SMS_PERMS),
                    "contact_perms": sorted(all_perms & _CONTACT_PERMS),
                    "sensitive_perms": sorted(all_perms & _SENSITIVE_PERMS),
                    "install_source": install_source,
                    "serial": serial,
                },
                mitre="T1430",
            )

    def _check_security_patch(self, art) -> Iterable[Finding]:
        data = art["data"] or {}
        raw = (data.get("raw") or "").strip()
        serial = data.get("serial") or ""
        ref = art["artifact_uuid"]
        # raw is like "2024-10-05"
        try:
            patch_date = _dt.datetime.strptime(raw, "%Y-%m-%d").date()
        except ValueError:
            return
        today = _dt.date.today()
        age = (today - patch_date).days
        if age <= _PATCH_STALE_DAYS:
            return
        yield Finding(
            detector=self.name,
            severity="medium" if age <= 365 else "high",
            title=(
                f"Outdated Android security patch: {raw} "
                f"({age} days old)"
            ),
            summary=(
                f"Device ``{serial}`` is on Android security "
                f"patch level ``{raw}``, {age} days behind today. "
                "Many vendor builds stop monthly updates; the "
                "device is exposed to all post-patch kernel and "
                "MediaServer CVEs."
            ),
            artifact_refs=[ref],
            evidence={
                "kind": "stale_security_patch",
                "patch_level": raw,
                "age_days": age,
                "serial": serial,
            },
            mitre="T1404",
        )

    def _check_non_market_apps(self, art) -> Iterable[Finding]:
        data = art["data"] or {}
        raw = (data.get("raw") or "").strip()
        serial = data.get("serial") or ""
        ref = art["artifact_uuid"]
        if raw == "1":
            yield Finding(
                detector=self.name,
                severity="medium",
                title=(
                    "Install-from-unknown-sources globally enabled"
                ),
                summary=(
                    f"Device ``{serial}`` has "
                    "Settings.Global.install_non_market_apps = 1. "
                    "Pre-Android-8 toggle that lets any source "
                    "install apks. Modern Android moved to per-"
                    "app permissions, but if this device is still "
                    "carrying the legacy flag, anything sideloaded "
                    "got in unchallenged."
                ),
                artifact_refs=[ref],
                evidence={
                    "kind": "non_market_installs_enabled",
                    "serial": serial,
                },
                mitre="T1404",
            )
