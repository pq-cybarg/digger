"""Linux telemetry jammer — owner-sovereignty disabler for distro,
desktop, and application telemetry on Linux.

Completes the cross-platform sovereignty trio (TelemetryJammer for
Windows, MacOSTelemetryJammer for Apple, LinuxTelemetryJammer here).
Same architecture: observation-only detection + copy-pasteable opt-in
remediation commands the owner runs themselves at an elevated shell.
``digger`` never applies the commands; see ethics-contract P2.

What this exists to disable
---------------------------
Ubuntu / Debian:
  * whoopsie       — Ubuntu error-report submission
  * apport         — Ubuntu/Debian crash reporter
  * popularity-contest (popcon) — package-usage polling
  * ubuntu-advantage-tools — UA esm-cache telemetry
  * ubuntu-report  — first-boot install report
  * canonical-livepatch — kernel-livepatch service (has telemetry)
  * snapd          — snap refresh / metric submission
  * packagekit     — background metadata refresh + reporting

Fedora / RHEL family:
  * abrt-applet / abrtd — Automatic Bug Reporting Tool
  * ureport-libreport — central bug-report queue

GNOME desktop:
  * tracker3-miner-fs — system-wide indexing (privacy + battery)
  * gnome-software refresh
  * goa-daemon (online-accounts auto-sync)
  * evolution-data-server (caldav/carddav background sync)
  * geoclue — location service

Firefox / Thunderbird:
  * normandy / shavar / self-repair endpoints
  * incoming.telemetry.mozilla.org

VSCode / vendor Microsoft on Linux:
  * mobile.events.data.microsoft.com (VSCode telemetry — same as
    Windows endpoint)

DNS-block targets are the Ubuntu / Mozilla / Microsoft telemetry
endpoints commonly published in privacy-tool lists (e.g., Karelia,
EFF's privacy-conscious-config corpus).

Each finding emits ``info`` or ``low`` severity. These are present-
state observations on the owner's machine, not attack signals.
"""

# live-first-ok: Distro / desktop telemetry service names are stable
# across Linux releases. Distros publish no machine-readable list of
# telemetry endpoints; the bundled rules are the right place.

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector
from digger.ethics.contract import redact_dangerous_command


# ---- systemd unit table (unit_name, friendly purpose, family) ---- #

_TELEMETRY_UNITS: list[tuple[str, str, str]] = [
    # Ubuntu / Debian
    ("whoopsie.service",                "Ubuntu error-report submission", "ubuntu"),
    ("whoopsie.path",                   "whoopsie path trigger",          "ubuntu"),
    ("apport.service",                  "Apport crash reporter daemon",   "ubuntu"),
    ("apport-autoreport.path",          "Apport autoreport trigger",      "ubuntu"),
    ("apport-autoreport.timer",         "Apport autoreport timer",        "ubuntu"),
    ("ubuntu-report.service",           "Ubuntu install-report agent",    "ubuntu"),
    ("ubuntu-advantage.service",        "Ubuntu Advantage tools (esm)",   "ubuntu"),
    ("ua-license-check.timer",          "Ubuntu Advantage license check", "ubuntu"),
    ("ua-timer.timer",                  "Ubuntu Advantage periodic timer", "ubuntu"),
    ("canonical-livepatch.service",     "Canonical livepatch daemon",     "ubuntu"),
    ("popularity-contest.timer",        "popcon weekly submission",       "ubuntu"),
    ("popularity-contest.service",      "popcon submission service",      "ubuntu"),
    # Snap / PackageKit
    ("snapd.service",                   "Snapd (snap refresh + metrics)", "snap"),
    ("snapd.refresh.timer",             "Snapd refresh timer (telemetry)", "snap"),
    ("snapd.snap-repair.service",       "Snapd repair service",           "snap"),
    ("snapd.snap-repair.timer",         "Snapd repair timer",             "snap"),
    ("packagekit.service",              "PackageKit background daemon",   "packagekit"),
    ("packagekit-offline-update.service", "PackageKit offline updater",   "packagekit"),
    # Fedora / RHEL family
    ("abrtd.service",                   "Automatic Bug Reporting daemon", "fedora"),
    ("abrt-journal-core.service",       "ABRT systemd-journal core dump", "fedora"),
    ("abrt-oops.service",               "ABRT kernel-oops collector",     "fedora"),
    ("abrt-vmcore.service",             "ABRT vmcore collector",          "fedora"),
    ("abrt-xorg.service",               "ABRT xorg-crash collector",      "fedora"),
    ("ureport-watchdog.service",        "ureport upload watchdog",        "fedora"),
    # GNOME
    ("tracker-miner-fs-3.service",      "Tracker3 filesystem indexer",    "gnome"),
    ("tracker-extract-3.service",       "Tracker3 metadata extractor",    "gnome"),
    ("goa-daemon.service",              "GNOME Online Accounts daemon",   "gnome"),
    ("evolution-source-registry.service", "Evolution source registry",    "gnome"),
    ("geoclue.service",                 "Geoclue location service",       "gnome"),
    # KDE
    ("baloo_file.service",              "Baloo filesystem indexer (KDE)", "kde"),
    # Firmware / hardware
    ("fwupd-refresh.timer",             "fwupd vendor-firmware check-in", "firmware"),
    # Smart TV / Bluetooth opportunistic
    ("ModemManager.service",            "ModemManager (telemetry for cellular)", "hardware"),
]

# Same as a fast-membership set, lowercased.
_TELEMETRY_UNITS_LOWER = {u[0].lower() for u in _TELEMETRY_UNITS}
_UNIT_LABEL = {u[0].lower(): (u[1], u[2]) for u in _TELEMETRY_UNITS}


# Process basenames that, when running, indicate a telemetry daemon.
_TELEMETRY_PROCESSES = {
    "whoopsie", "apport", "ureport-watchdog", "abrtd", "abrt-applet",
    "tracker-miner-fs-3", "tracker-extract-3", "baloo_file",
    "popularity-contest", "ubuntu-report", "ua-timer",
    "fwupd-refresh", "geoclue", "packagekitd",
    "evolution-source-registry", "evolution-calendar-factory",
}


# Telemetry endpoints to block at /etc/hosts.
_TELEMETRY_HOSTS = [
    # Ubuntu / Canonical
    "daisy.ubuntu.com",                    # whoopsie
    "popcon.ubuntu.com",
    "metrics.ubuntu.com",
    "motd.ubuntu.com",
    "contracts.canonical.com",
    "livepatch.canonical.com",
    "api.snapcraft.io",
    "search.apps.ubuntu.com",
    # Fedora
    "retrace.fedoraproject.org",
    "abrt.fedoraproject.org",
    # Mozilla
    "incoming.telemetry.mozilla.org",
    "self-repair.mozilla.org",
    "shavar.services.mozilla.com",
    "tracking-protection.cdn.mozilla.net",
    "normandy.cdn.mozilla.net",
    "experiments.mozilla.org",
    "settings.services.mozilla.com",
    "push.services.mozilla.com",
    "location.services.mozilla.com",
    # GNOME / freedesktop
    "extensions.gnome.org",                # extension auto-update polling
    # Microsoft VSCode-on-Linux
    "vortex.data.microsoft.com",
    "mobile.events.data.microsoft.com",
    "raw.githubusercontent.com/microsoft/vscode/main/extensions/configuration-editing/schemas/devContainer.codespaces.schema.json",
]


# ---- remediation blocks ---- #

_REM_SYSTEMCTL_DISABLE = """\
# Stop and disable {unit}. Reversible:
#   sudo systemctl enable --now {unit}
sudo systemctl stop {unit} 2>/dev/null || true
sudo systemctl disable {unit} 2>/dev/null || true
# For services that are masked back on at upgrade, mask instead:
# sudo systemctl mask {unit}
"""

_REM_APT_PURGE_POPCON = """\
# Permanently remove popularity-contest (Debian/Ubuntu). Reversible
# via `sudo apt install popularity-contest` and re-run dpkg-reconfigure.
sudo apt purge -y popularity-contest
sudo dpkg --purge popularity-contest 2>/dev/null || true
# If you'd rather keep it installed but never submit:
# sudo sed -i 's/^PARTICIPATE=.*/PARTICIPATE="no"/' /etc/popularity-contest.conf
"""

_REM_APT_PURGE_WHOOPSIE = """\
# Remove whoopsie + apport entirely. Reversible via apt install.
sudo systemctl stop whoopsie.service whoopsie.path 2>/dev/null || true
sudo systemctl disable whoopsie.service whoopsie.path 2>/dev/null || true
sudo apt purge -y whoopsie apport
# If you want to keep them installed but stop submissions:
# echo "enabled=0" | sudo tee /etc/default/apport
"""

_REM_SNAPD_FULL_REMOVE = """\
# Remove snapd entirely (and all installed snaps). Reversible but
# requires reinstalling each snap manually. WARNING: this removes
# all currently-installed snap applications.
sudo snap list | awk 'NR>1 {print $1}' | xargs -r sudo snap remove --purge
sudo apt purge -y snapd
sudo rm -rf /var/cache/snapd /snap /root/snap ~/snap
sudo apt-mark hold snapd
"""

_REM_UBUNTU_REPORT = """\
# Disable the first-boot Ubuntu install-report agent.
sudo ubuntu-report -f send no 2>/dev/null || true
sudo systemctl disable ubuntu-report.service 2>/dev/null || true
sudo apt purge -y ubuntu-report
"""

_REM_FIREFOX_TELEMETRY = """\
# Firefox telemetry opt-out. Per-profile; loops over all profiles.
# Reversible: edit each profile's user.js and remove these lines.
for prof in ~/.mozilla/firefox/*.default*; do
    [ -d "$prof" ] || continue
    cat >> "$prof/user.js" <<'PREFS_EOF'
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.ping-centre.telemetry", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("services.sync.prefs.sync.app.shield.optoutstudies.enabled", false);
PREFS_EOF
done
"""

_REM_HOSTS_BLOCK = """\
# Block telemetry endpoints at /etc/hosts. Reversible: edit /etc/hosts
# and remove lines between the digger markers.
HOSTS=(
{host_lines}
)
sudo tee -a /etc/hosts <<'HOSTS_EOF'

# digger linux-telemetry-jammer begin
HOSTS_EOF
for h in "${{HOSTS[@]}}"; do
    grep -qxF "0.0.0.0 $h" /etc/hosts || echo "0.0.0.0 $h" | sudo tee -a /etc/hosts >/dev/null
done
echo "# digger linux-telemetry-jammer end" | sudo tee -a /etc/hosts >/dev/null
# Flush nscd / systemd-resolved caches:
sudo systemd-resolve --flush-caches 2>/dev/null || true
sudo resolvectl flush-caches 2>/dev/null || true
sudo systemctl restart nscd 2>/dev/null || true
"""


def _redact_block(block: str) -> str:
    if not block:
        return ""
    out_lines: list[str] = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(line)
            continue
        annotated, was_dangerous = redact_dangerous_command(stripped)
        out_lines.append(annotated if was_dangerous else line)
    return "\n".join(out_lines)


def _build_hosts_remediation() -> str:
    lines = "\n".join(f"    '{h}'" for h in _TELEMETRY_HOSTS)
    return _REM_HOSTS_BLOCK.format(host_lines=lines)


def _purge_command_for(unit: str) -> str:
    """Pick the cleaner remediation when an apt-purge alternative exists."""
    u = unit.lower()
    if u.startswith("popularity-contest"):
        return _REM_APT_PURGE_POPCON
    if u.startswith("whoopsie") or u.startswith("apport"):
        return _REM_APT_PURGE_WHOOPSIE
    if u.startswith("snapd"):
        return _REM_SNAPD_FULL_REMOVE
    if u.startswith("ubuntu-report"):
        return _REM_UBUNTU_REPORT
    return _REM_SYSTEMCTL_DISABLE.format(unit=unit)


def _basename(path: str) -> str:
    if not path:
        return ""
    if "/" in path:
        path = path.rsplit("/", 1)[1]
    return path


class LinuxTelemetryJammerDetector(Detector):
    name = "linux_telemetry_jammer"
    description = (
        "Detects active Linux distro / desktop / application telemetry "
        "surface (whoopsie, apport, popularity-contest, ubuntu-report, "
        "snapd, fwupd-refresh, abrt/ureport, tracker3-miner-fs, "
        "Mozilla telemetry endpoints) on the owner's machine and emits "
        "systemctl disable + apt purge + about:config-style opt-in "
        "commands. Observation-only; user runs the commands themselves "
        "(same pattern as firewall_audit)."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Linux telemetry / crash-reporter component active",
            "id": "digger-linux-telemetry-jammer-template",
            "description": (
                "A Linux telemetry / crash-reporter / desktop-indexing "
                "process is running: whoopsie / apport / popularity-"
                "contest / ubuntu-report / snapd / abrtd / tracker3-"
                "miner-fs / baloo_file / fwupd-refresh / geoclue / "
                "packagekitd. Use this for owner-sovereignty audits, "
                "not as an attack signal."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "linux", "category": "process_creation"},
            "detection": {
                "selection_telemetry_proc": {
                    "Image|contains": sorted(_TELEMETRY_PROCESSES),
                },
                "condition": "selection_telemetry_proc",
            },
            "level": "informational",
            "tags": [
                "attack.collection",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- L1 systemd units present and enabled ---- #
        seen_units: set[str] = set()
        for art in store.iter_artifacts(collector="linux.systemd"):
            d = art["data"] or {}
            # systemd collector ships either `raw` text (systemctl
            # list-unit-files / list-units output) or `entries` lists
            # depending on subject. We scan both.
            raw = (d.get("raw") or "")
            entries = d.get("entries") or []

            text_blocks = [raw] + [
                str(e) if not isinstance(e, dict)
                else " ".join(str(v) for v in e.values())
                for e in entries
            ]

            for block in text_blocks:
                low = block.lower()
                for unit in _TELEMETRY_UNITS_LOWER:
                    if unit not in low or unit in seen_units:
                        continue
                    # Heuristic: line containing the unit must NOT
                    # contain "disabled" or "masked" or "static" right
                    # next to it. Find the line bearing the unit name
                    # and inspect its state column.
                    state = "enabled"
                    for line in low.splitlines():
                        if unit not in line:
                            continue
                        if " disabled" in line or "\tdisabled" in line:
                            state = "disabled"
                        elif " masked" in line or "\tmasked" in line:
                            state = "masked"
                        elif " static" in line or "\tstatic" in line:
                            state = "static"
                        break
                    if state in ("disabled", "masked"):
                        continue
                    seen_units.add(unit)
                    label, family = _UNIT_LABEL[unit]
                    yield Finding(
                        detector=self.name,
                        severity="low",
                        title=(
                            f"Linux telemetry unit active: {unit} "
                            f"({label})"
                        ),
                        summary=(
                            f"systemd unit ``{unit}`` ({label}) is "
                            "present and not disabled / masked. On a "
                            "machine you own, you may wish to disable "
                            "it. The remediation_commands block "
                            "contains the systemctl disable + "
                            "(where applicable) apt purge commands. "
                            "Reversible."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "linux_telemetry_unit",
                            "unit": unit,
                            "label": label,
                            "family": family,
                            "state": state,
                            "remediation_commands": _redact_block(
                                _purge_command_for(unit)
                            ),
                            "reversible": True,
                        },
                        mitre="T1059.004",  # Unix shell — closest fit
                    )

        # ---- L2 telemetry processes running ---- #
        seen_proc: set[tuple[int, str]] = set()
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            name = (d.get("name") or "").lower()
            exe = (d.get("exe") or "").lower()
            base = (_basename(exe) or name).lower()
            for tn in _TELEMETRY_PROCESSES:
                tn_l = tn.lower()
                if tn_l == base or tn_l == name or tn_l in base:
                    key = (d.get("pid") or 0, tn)
                    if key in seen_proc:
                        continue
                    seen_proc.add(key)
                    yield Finding(
                        detector=self.name,
                        severity="info",
                        title=(
                            f"Linux telemetry process running: {tn} "
                            f"(pid {d.get('pid')})"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} ({base}) "
                            f"matches Linux-telemetry component "
                            f"``{tn}``. Disable the underlying systemd "
                            "unit via the remediation_commands block; "
                            "the process exits after stop+disable."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "linux_telemetry_process",
                            "component": tn,
                            "pid": d.get("pid"),
                            "exe": d.get("exe"),
                            "remediation_commands": _redact_block(
                                _purge_command_for(f"{tn}.service")
                            ),
                            "reversible": True,
                        },
                        mitre="T1059.004",
                    )
                    break

        # ---- L3 popcon config: PARTICIPATE=yes in /etc/popularity-contest.conf ---- #
        # Heuristic: scan any text-bearing artifact for the participate=yes
        # line; emit one informational finding pointing at the per-config
        # opt-out.
        popcon_emitted = False
        for art in store.iter_artifacts():
            if popcon_emitted:
                break
            d = art.get("data") or {}
            try:
                import json as _json
                text = _json.dumps(d, default=str)
            except Exception:
                continue
            if re.search(r'PARTICIPATE[^a-z]{0,5}yes', text, re.I):
                popcon_emitted = True
                yield Finding(
                    detector=self.name,
                    severity="low",
                    title=(
                        "popularity-contest PARTICIPATE=yes configured"
                    ),
                    summary=(
                        "/etc/popularity-contest.conf indicates "
                        "PARTICIPATE=yes. Package-usage data is being "
                        "submitted to popcon.ubuntu.com weekly. "
                        "Disable via the remediation_commands block "
                        "(apt purge popularity-contest is cleanest; "
                        "sed-based PARTICIPATE=no is the lighter "
                        "alternative)."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "popcon_participate",
                        "remediation_commands": _redact_block(_REM_APT_PURGE_POPCON),
                        "reversible": True,
                    },
                    mitre="T1059.004",
                )

        # ---- L4 telemetry-host DNS resolutions ---- #
        seen_hosts: set[str] = set()
        host_rem = None
        for art in store.iter_artifacts(collector="dns"):
            d = art["data"] or {}
            host = (d.get("host") or d.get("name") or "").lower()
            entries = d.get("entries") or []
            hay = [host] + [
                (e.get("host") or e.get("name") or "").lower()
                for e in entries if isinstance(e, dict)
            ]
            for h in hay:
                if not h:
                    continue
                for th in _TELEMETRY_HOSTS:
                    if th in h and th not in seen_hosts:
                        seen_hosts.add(th)
                        if host_rem is None:
                            host_rem = _redact_block(_build_hosts_remediation())
                        yield Finding(
                            detector=self.name,
                            severity="info",
                            title=(
                                f"Linux-telemetry host resolved: {th}"
                            ),
                            summary=(
                                f"DNS history shows resolution of "
                                f"``{th}``. Block at /etc/hosts via "
                                "the remediation_commands block. "
                                "Reversible (edit /etc/hosts between "
                                "the digger markers)."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "linux_telemetry_dns",
                                "host": th,
                                "remediation_commands": host_rem,
                                "reversible": True,
                            },
                            mitre="T1059.004",
                        )
                        break

        # ---- L5 Firefox profile present → emit telemetry-opt-out advisory ---- #
        # Firefox stores profiles under ~/.mozilla/firefox/*.default*. We
        # can't reliably inspect prefs.js / user.js for telemetry state
        # without parsing them, so we emit one advisory per case when a
        # Firefox profile path appears in any artifact JSON. The user
        # ignores if their profile is already opted out.
        ff_emitted = False
        for art in store.iter_artifacts():
            if ff_emitted:
                break
            d = art.get("data") or {}
            try:
                import json as _json
                text = _json.dumps(d, default=str)
            except Exception:
                continue
            if ".mozilla/firefox" in text or "/firefox/" in text:
                ff_emitted = True
                yield Finding(
                    detector=self.name,
                    severity="info",
                    title=(
                        "Firefox profile present — telemetry opt-out "
                        "command available"
                    ),
                    summary=(
                        "A Firefox profile was observed in collected "
                        "artifacts. Mozilla telemetry, Normandy "
                        "experiments, Shield studies, and ping-centre "
                        "are opt-out per-profile. The "
                        "remediation_commands block appends a "
                        "user.js with the full opt-out set to every "
                        "profile under ~/.mozilla/firefox/*.default*. "
                        "Reversible: edit user.js and remove the lines."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "firefox_telemetry_advisory",
                        "remediation_commands": _redact_block(
                            _REM_FIREFOX_TELEMETRY
                        ),
                        "reversible": True,
                    },
                    mitre="T1059.004",
                )
