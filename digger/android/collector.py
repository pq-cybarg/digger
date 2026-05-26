"""adb (Android Debug Bridge) collector.

We never push or modify state on-device. We invoke `adb shell <cmd>`
for these enumeration commands:

  - pm list packages -f -i -U      (installed packages w/ installer)
  - pm list packages -d            (disabled packages)
  - dumpsys package <pkg>          (per-package metadata — granted
                                    permissions, install source,
                                    flags, signers, version)
  - dumpsys device_policy          (device admin / device-owner)
  - dumpsys accessibility          (AccessibilityServices enabled)
  - settings get secure enabled_accessibility_services
  - settings get global install_non_market_apps
  - getprop                        (build fingerprint, security_patch)

Each becomes one Artifact (collector="android.<resource>",
category="mobile", subject="android:<resource>:<key>"). Per-app
dumpsys output gets parsed into structured AndroidPackage records
so the detector can run rules against them cheanly.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


class AdbError(RuntimeError):
    """Raised on hard failures (binary missing where caller wanted
    one). collect_device() itself never raises — degraded result."""


# ---- tunables ---- #

_ADB_TIMEOUT_S = 60
_PER_PACKAGE_TIMEOUT_S = 10
_MAX_OUTPUT_BYTES = 16 * 1024 * 1024     # 16 MiB / cmd
_MAX_PACKAGES_DUMPED = 600                # cap noisy enumeration
_FIELD_TRUNC = 8192


# ---- binary discovery ---- #


def discover_binary() -> str | None:
    """Return path to adb or None.

    Honors ``DIGGER_ADB_BIN`` env var first."""
    explicit = os.environ.get("DIGGER_ADB_BIN")
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
        return None
    p = shutil.which("adb")
    return p if p else None


# ---- record types ---- #


@dataclass
class AndroidPackage:
    name: str
    version_name: str = ""
    version_code: str = ""
    install_source: str = ""           # com.android.vending = Play
    installer_session: str = ""
    target_sdk: str = ""
    flags: list[str] = field(default_factory=list)
    granted_permissions: list[str] = field(default_factory=list)
    requested_permissions: list[str] = field(default_factory=list)
    signers: list[str] = field(default_factory=list)
    primary_cpu_abi: str = ""
    code_path: str = ""
    enabled: bool = True
    debuggable: bool = False
    is_system: bool = False


@dataclass
class AndroidCollectSummary:
    binary: str | None
    serial: str | None
    devices_seen: list[str] = field(default_factory=list)
    packages_listed: int = 0
    packages_dumped: int = 0
    artifacts_emitted: int = 0
    elapsed_s: float = 0.0
    errors: list[str] = field(default_factory=list)


# ---- shell runners ---- #


def _run_adb(binary: str,
             args: list[str],
             *,
             timeout: float = _ADB_TIMEOUT_S,
             serial: str | None = None) -> tuple[int, str, str]:
    """Run `adb [args]` with a per-invocation timeout. Returns
    (rc, stdout, stderr) where each stream is a (possibly
    truncated) str."""
    cmd = [binary]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired,
            subprocess.SubprocessError,
            FileNotFoundError, PermissionError, OSError) as exc:
        return (124, "", f"adb invocation failed: {exc}")
    stdout = (proc.stdout or b"")[:_MAX_OUTPUT_BYTES].decode(
        "utf-8", errors="replace",
    )
    stderr = (proc.stderr or b"")[:_MAX_OUTPUT_BYTES].decode(
        "utf-8", errors="replace",
    )
    return (proc.returncode, stdout, stderr)


def _list_devices(binary: str) -> list[str]:
    """Return list of serial numbers reporting state 'device'.

    Skips 'offline' / 'unauthorized' / 'no permissions'."""
    rc, out, _ = _run_adb(binary, ["devices"])
    if rc != 0:
        return []
    serials: list[str] = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].strip() == "device":
            serials.append(parts[0])
    return serials


# ---- pm list packages parser ---- #


_PM_LIST_RE = re.compile(
    # package:/data/app/.../base.apk=com.example.foo  installer=...  uid:10042
    r"^package:(?P<path>\S+)=(?P<pkg>\S+?)"
    r"(?:\s+installer=(?P<installer>\S+))?"
    r"(?:\s+uid:\d+)?$",
)


def parse_pm_list_packages(output: str) -> list[dict[str, str]]:
    """Parse `pm list packages -f -i -U` output."""
    out: list[dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        m = _PM_LIST_RE.match(line)
        if m:
            out.append({
                "name": m.group("pkg"),
                "code_path": m.group("path") or "",
                "installer": (m.group("installer") or "").strip(),
            })
        else:
            # fallback: simple "package:com.foo.bar"
            raw = line[len("package:"):]
            if "=" in raw:
                path, pkg = raw.split("=", 1)
                out.append({"name": pkg.strip(),
                            "code_path": path.strip(),
                            "installer": ""})
            else:
                out.append({"name": raw.strip(),
                            "code_path": "", "installer": ""})
    return out


# ---- dumpsys package parser ---- #


def parse_dumpsys_package(output: str, name: str) -> AndroidPackage:
    """Parse `dumpsys package <name>` into AndroidPackage.

    The format isn't documented; we tolerate variation across
    Android versions by grepping for stable label substrings."""
    pkg = AndroidPackage(name=name)

    def _grep_value(key: str) -> str | None:
        for line in output.splitlines():
            line = line.strip()
            if line.startswith(key):
                v = line.split("=", 1)[-1].strip() \
                    if "=" in line else line.split(":", 1)[-1].strip()
                return v[:_FIELD_TRUNC]
        return None

    pkg.version_name = _grep_value("versionName") or ""
    pkg.version_code = _grep_value("versionCode") or ""
    pkg.install_source = _grep_value("installerPackageName") or ""
    pkg.installer_session = _grep_value("installerAttributionTag") or ""
    pkg.target_sdk = _grep_value("targetSdk") or ""
    pkg.primary_cpu_abi = _grep_value("primaryCpuAbi") or ""
    pkg.code_path = _grep_value("codePath") or pkg.code_path

    flags_str = _grep_value("flags") or _grep_value("pkgFlags") or ""
    if flags_str:
        pkg.flags = [
            tok.strip("[],")
            for tok in re.findall(r"[A-Z_]+", flags_str)
            if len(tok) > 2
        ]
        if "SYSTEM" in pkg.flags or "PRIVILEGED" in pkg.flags:
            pkg.is_system = True
        if "DEBUGGABLE" in pkg.flags:
            pkg.debuggable = True
        if "ENABLED" in pkg.flags:
            pkg.enabled = True

    granted_block: list[str] = []
    requested_block: list[str] = []
    section = None
    for line in output.splitlines():
        s = line.rstrip()
        ls = s.strip()
        if not ls:
            continue
        if "requested permissions:" in ls.lower():
            section = "requested"
            continue
        if "install permissions:" in ls.lower() or \
                "runtime permissions:" in ls.lower() or \
                "granted=true" in ls.lower() and section is None:
            section = "granted"
            continue
        if ls.startswith("User") or ls.endswith(":"):
            if not ls.startswith("android.permission") and \
                    not ls.startswith("permission") and \
                    ":" in ls and not ls.startswith("granted="):
                if "permission" not in ls.lower():
                    section = None
        if section == "requested" and \
                (ls.startswith("android.permission")
                 or ls.startswith("permission.")):
            requested_block.append(ls.split(":", 1)[0].strip())
        elif section == "granted":
            if "granted=true" in ls and \
                    (ls.startswith("android.permission")
                     or ls.startswith("permission.")):
                granted_block.append(ls.split(":", 1)[0].strip())
            elif ls.startswith("android.permission") and \
                    "granted=false" not in ls:
                granted_block.append(ls.split(":", 1)[0].strip())

    pkg.granted_permissions = sorted(set(granted_block))
    pkg.requested_permissions = sorted(set(requested_block))

    signer_re = re.compile(
        r"^\s*Signature:\s*(?P<sig>[0-9a-fA-F:]{16,})",
    )
    for line in output.splitlines():
        m = signer_re.match(line)
        if m:
            pkg.signers.append(m.group("sig")[:_FIELD_TRUNC])

    return pkg


# ---- main collect ---- #


def collect_device(
    case_dir: str | Path,
    *,
    serial: str | None = None,
    binary: str | None = None,
    max_packages: int = _MAX_PACKAGES_DUMPED,
) -> AndroidCollectSummary:
    """Connect to one device via adb and emit Artifacts.

    Strictly read-only. Returns an AndroidCollectSummary; never
    raises (apart from a programmer error in the caller).
    """
    from digger.core.evidence import Artifact, EvidenceStore
    started = time.time()
    binary = binary or discover_binary()
    if not binary:
        return AndroidCollectSummary(
            binary=None, serial=serial,
            errors=["no adb binary discovered "
                    "(install android-platform-tools)"],
        )
    devices = _list_devices(binary)
    summary = AndroidCollectSummary(binary=binary, serial=serial,
                                      devices_seen=devices)
    if not devices:
        summary.errors.append("no adb devices in 'device' state")
        summary.elapsed_s = time.time() - started
        return summary
    if serial and serial not in devices:
        summary.errors.append(
            f"serial {serial!r} not present (have: {devices})",
        )
        summary.elapsed_s = time.time() - started
        return summary
    target_serial = serial or devices[0]

    store = EvidenceStore(case_dir)
    try:
        for resource, cmd in (
            ("build_fingerprint",
                ["shell", "getprop", "ro.build.fingerprint"]),
            ("security_patch",
                ["shell", "getprop", "ro.build.version.security_patch"]),
            ("device_model",
                ["shell", "getprop", "ro.product.model"]),
            ("install_non_market_apps",
                ["shell", "settings", "get", "global",
                 "install_non_market_apps"]),
            ("enabled_accessibility_services",
                ["shell", "settings", "get", "secure",
                 "enabled_accessibility_services"]),
            ("device_policy",
                ["shell", "dumpsys", "device_policy"]),
            ("accessibility",
                ["shell", "dumpsys", "accessibility"]),
        ):
            rc, out, err = _run_adb(binary, cmd, serial=target_serial)
            if rc != 0:
                summary.errors.append(
                    f"{resource}: rc={rc} {err[:_FIELD_TRUNC]}",
                )
                continue
            store.add_artifact(Artifact(
                collector=f"android.{resource}",
                category="mobile",
                subject=f"android:{resource}:{target_serial}",
                data={"serial": target_serial,
                      "raw": out[:_FIELD_TRUNC],
                      "lines": out.count("\n")},
            ))
            summary.artifacts_emitted += 1

        rc, out, err = _run_adb(
            binary, ["shell", "pm", "list", "packages", "-f", "-i", "-U"],
            serial=target_serial,
        )
        if rc != 0:
            summary.errors.append(f"pm list packages: rc={rc} "
                                    f"{err[:_FIELD_TRUNC]}")
            packages: list[dict[str, str]] = []
        else:
            packages = parse_pm_list_packages(out)
            summary.packages_listed = len(packages)
            store.add_artifact(Artifact(
                collector="android.packages_index",
                category="mobile",
                subject=f"android:packages:{target_serial}",
                data={"serial": target_serial,
                      "count": len(packages),
                      "packages": packages[:max_packages]},
            ))
            summary.artifacts_emitted += 1

        disabled: list[str] = []
        rc, out, err = _run_adb(
            binary, ["shell", "pm", "list", "packages", "-d"],
            serial=target_serial,
        )
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("package:"):
                    disabled.append(line[len("package:"):].strip())
            store.add_artifact(Artifact(
                collector="android.packages_disabled",
                category="mobile",
                subject=f"android:packages_disabled:{target_serial}",
                data={"serial": target_serial,
                      "disabled": disabled},
            ))
            summary.artifacts_emitted += 1

        for entry in packages[:max_packages]:
            name = entry["name"]
            rc, dump_out, err = _run_adb(
                binary,
                ["shell", "dumpsys", "package", name],
                serial=target_serial,
                timeout=_PER_PACKAGE_TIMEOUT_S,
            )
            if rc != 0:
                continue
            pkg = parse_dumpsys_package(dump_out, name)
            if entry.get("installer") and not pkg.install_source:
                pkg.install_source = entry["installer"]
            pkg.code_path = pkg.code_path or entry.get("code_path", "")
            if name in disabled:
                pkg.enabled = False
            from dataclasses import asdict
            store.add_artifact(Artifact(
                collector="android.package",
                category="mobile",
                subject=f"android:package:{target_serial}:{name}",
                data={"serial": target_serial,
                      **asdict(pkg)},
            ))
            summary.artifacts_emitted += 1
            summary.packages_dumped += 1
    finally:
        store.close()
    summary.elapsed_s = time.time() - started
    return summary


# ---- convenience for tests ---- #


def _ingest_dump(store, serial: str, pkg: AndroidPackage) -> None:
    """Internal helper — exposed for tests that want to seed
    fake packages without running adb."""
    from dataclasses import asdict
    from digger.core.evidence import Artifact
    store.add_artifact(Artifact(
        collector="android.package",
        category="mobile",
        subject=f"android:package:{serial}:{pkg.name}",
        data={"serial": serial, **asdict(pkg)},
    ))
