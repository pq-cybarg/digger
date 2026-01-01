"""macOS telemetry jammer — owner-sovereignty disabler for Apple
telemetry / iCloud / Siri / Spotlight-Suggestions surface.

Parallel to the Windows TelemetryJammerDetector. Same architecture:
observation-only detection + copy-pasteable opt-in disable commands
the owner runs themselves at an elevated shell. ``digger`` never
applies these commands; see ethics-contract P2
(``assert_user_consent_for_modification``).

Why this exists
---------------
macOS opts a fresh install into:

  * Apple-Seed beta-feedback agent (com.apple.appleseed.fbahelperd)
  * OSAnalytics diagnostic-report submission (com.apple.osanalytics.*)
  * SiriAnalytics + assistantd telemetry
  * Spotlight Suggestions (cloud-side query routing)
  * Photos / Knowledge-graph analysis daemons
    (photoanalysisd, knowledge-agent)
  * iCloud Drive / iCloud Photos auto-sync (bird, cloudd)
  * Symptoms framework diagnostics (symptomsd-diag)
  * Wi-Fi analytics agent

Many of these are unobjectionable in isolation, but the owner-
sovereignty principle is the same: the user paid for the hardware,
they get to choose. This detector enumerates what's on, and ships
the commands to turn it off.

What this detects
-----------------

  M1  Apple-telemetry launchd agent active (LoadedAgents +
      DisableState matched against a list of telemetry-related labels)
  M2  Telemetry-related processes running (osanalyticshelper,
      symptomsd-diag, knowledge-agent, photoanalysisd, etc.)
  M3  Crash-report auto-submit enabled (DiagnosticMessagesHistory
      .plist AutoSubmit ≠ false)
  M4  Apple-telemetry endpoint DNS resolution
      (gs-loc.apple.com, configuration.apple.com,
      metrics.icloud.com, etc.)
  M5  TCC entries granting access to AppleSeed / FeedbackAssistant
      (these are usually a sign the user opted into beta-feedback at
      some point and may want to revoke)

Each finding carries severity ``info`` or ``low`` — these are not
attack indicators, they're present-state observations on the user's
own Mac with an opt-in remediation block.
"""

# live-first-ok: Apple telemetry launchd labels and endpoint hostnames
# are stable across macOS releases (com.apple.appleseed.fbahelperd,
# com.apple.osanalytics.osanalyticshelper, gs-loc.apple.com, etc.).
# Apple publishes no machine-readable list of telemetry components;
# bundled rules-base is the right place when names rotate.

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector
from digger.ethics.contract import redact_dangerous_command


# ---- Apple-telemetry launchd labels ---- #
# (label, friendly purpose)
_APPLE_TELEMETRY_LABELS: list[tuple[str, str]] = [
    ("com.apple.appleseed.fbahelperd",
     "Apple-Seed beta-feedback assistant helper"),
    ("com.apple.appleseed.seedusaged",
     "Apple-Seed usage-data submission daemon"),
    ("com.apple.appleseed.seedusaged.postinstall",
     "Apple-Seed post-install usage report"),
    ("com.apple.osanalytics.osanalyticshelper",
     "OSAnalytics diagnostic-report helper"),
    ("com.apple.analyticsd",
     "Generic Apple analytics daemon"),
    ("com.apple.diagnosticd",
     "System diagnostic daemon"),
    ("com.apple.symptomsd-diag",
     "Symptoms framework diagnostic submission"),
    ("com.apple.SiriAnalytics.siri-analyticsd",
     "Siri analytics submission daemon"),
    ("com.apple.assistantd",
     "Siri assistant daemon"),
    ("com.apple.spindump",
     "spindump report uploader"),
    ("com.apple.spindump_agent",
     "spindump per-user report agent"),
    ("com.apple.SubmitDiagInfo",
     "diagnostic-info submission service"),
    ("com.apple.knowledge-agent",
     "Knowledge-graph (KnowledgeC.db) agent"),
    ("com.apple.photoanalysisd",
     "Photos face / scene analysis daemon"),
    ("com.apple.bird",
     "CloudDocs / iCloud Drive sync daemon"),
    ("com.apple.cloudd",
     "CloudKit synchronization daemon"),
    ("com.apple.identityservicesd",
     "Apple ID / iMessage / FaceTime identity services"),
    ("com.apple.wifianalyticsagent",
     "Wi-Fi analytics agent"),
    ("com.apple.searchpartyd",
     "FindMy network search-party daemon"),
    ("com.apple.parsec-fbf",
     "Parsec (Siri/Spotlight cloud-suggestions) feedback"),
    ("com.apple.parsecd",
     "Parsec (Siri/Spotlight cloud-suggestions) daemon"),
    ("com.apple.suggestd",
     "Spotlight Suggestions cloud-query daemon"),
    ("com.apple.coreduetd",
     "CoreDuet usage-pattern collection daemon"),
    ("com.apple.duetexpertd",
     "Duet Expert (predictive suggestions) daemon"),
]

# Same set, as a fast-membership set for cmdline / exe matches.
_APPLE_TELEMETRY_PROCESS_NAMES = {
    "osanalyticshelper", "appleseed.fbahelperd", "analyticsd",
    "symptomsd-diag", "siri-analyticsd", "assistantd",
    "spindump", "spindump_agent", "SubmitDiagInfo",
    "knowledge-agent", "photoanalysisd", "bird", "cloudd",
    "identityservicesd", "wifianalyticsagent", "searchpartyd",
    "parsec-fbf", "parsecd", "suggestd", "coreduetd", "duetexpertd",
    "fbahelperd", "diagnosticd", "seedusaged",
}

# Apple-side telemetry endpoints worth blocking. Drawn from public
# privacy-tooling lists (Karelia, Little Snitch published rules).
_APPLE_TELEMETRY_HOSTS = [
    "metrics.apple.com",
    "metrics.icloud.com",
    "configuration.apple.com",
    "gs-loc.apple.com",
    "gs-loc-cn.apple.com",
    "gsp10-ssl.ls.apple.com",
    "gsp-ssl.ls.apple.com",
    "gsp64-ssl.ls.apple.com",
    "diagassets.apple.com",
    "stats.appleseed.apple.com",
    "feedbackassistant.apple.com",
    "ic.apple.com",
    "iadsdk.apple.com",          # iAd / advertising attribution
    "weather-data.apple.com",
    "init.itunes.apple.com",     # iTunes init telemetry
    "smoot.apple.com",           # Siri/Spotlight cloud
    "api.smoot.apple.com",
    "guzzoni.apple.com",         # Siri voice recognition
]


# ---- remediation blocks ---- #

_REM_LAUNCHD_DISABLE = """\
# Unload + disable the {label} launchd job.
# Reversible:
#   sudo launchctl enable system/{label}
#   sudo launchctl bootstrap system /System/Library/LaunchDaemons/{label}.plist
sudo launchctl disable system/{label}
sudo launchctl bootout system /System/Library/LaunchDaemons/{label}.plist 2>/dev/null || true
sudo launchctl bootout gui/$(id -u) /System/Library/LaunchAgents/{label}.plist 2>/dev/null || true
"""

_REM_DIAG_AUTOSUBMIT = """\
# Disable diagnostic-report auto-submit to Apple. Reversible:
#   sudo defaults write /Library/Application\\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit -bool true
sudo defaults write /Library/Application\\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit -bool false
sudo defaults write /Library/Application\\ Support/CrashReporter/DiagnosticMessagesHistory.plist ThirdPartyDataSubmit -bool false
sudo defaults write com.apple.SubmitDiagInfo AutoSubmit -bool false
sudo defaults write com.apple.SubmitDiagInfo AutoSubmitVersion -int 4
# Per-user: opt out Siri analytics
defaults write com.apple.assistant.support "Siri Data Sharing Opt-In Status" -int 2
"""

_REM_HOSTS_BLOCK = """\
# Block Apple-telemetry endpoints at the hosts file. Reversible: edit
# /etc/hosts and remove the lines between the markers.
HOSTS=(
{host_lines}
)
sudo tee -a /etc/hosts <<'HOSTS_EOF'

# digger macos-telemetry-jammer begin
HOSTS_EOF
for h in "${{HOSTS[@]}}"; do
    grep -qxF "0.0.0.0 $h" /etc/hosts || echo "0.0.0.0 $h" | sudo tee -a /etc/hosts >/dev/null
done
echo "# digger macos-telemetry-jammer end" | sudo tee -a /etc/hosts >/dev/null
# Flush DNS so the block takes effect immediately:
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
"""

_REM_SPOTLIGHT_SUGGESTIONS = """\
# Turn off Spotlight Suggestions (web/cloud query routing). The kill
# of suggestd is needed for the change to take effect immediately.
# Reversible via System Settings > Spotlight > Search Results.
defaults write com.apple.lookup.shared LookupSuggestionsDisabled -bool true
defaults write com.apple.Safari UniversalSearchEnabled -bool false
defaults write com.apple.Safari SuppressSearchSuggestions -bool true
# Per-user: kill the suggestd daemon so it picks up new prefs
killall -HUP suggestd 2>/dev/null || true
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
    lines = "\n".join(f"    '{h}'" for h in _APPLE_TELEMETRY_HOSTS)
    return _REM_HOSTS_BLOCK.format(host_lines=lines)


def _basename(path: str) -> str:
    if not path:
        return ""
    if "/" in path:
        path = path.rsplit("/", 1)[1]
    if "\\" in path:
        path = path.rsplit("\\", 1)[1]
    return path


class MacOSTelemetryJammerDetector(Detector):
    name = "macos_telemetry_jammer"
    description = (
        "Detects active Apple-telemetry surface on the owner's Mac "
        "(OSAnalytics, AppleSeed, Siri analytics, Spotlight "
        "Suggestions, iCloud Drive auto-sync, FindMy search-party, "
        "Photos/Knowledge analysis daemons) and emits launchctl "
        "disable + defaults-write + hosts-file disable commands the "
        "owner can copy-paste. Observation-only; user runs the "
        "commands themselves (same pattern as firewall_audit)."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Apple-telemetry component active on macOS",
            "id": "digger-macos-telemetry-jammer-template",
            "description": (
                "An Apple-telemetry launchd job or process is active "
                "on macOS: appleseed / osanalytics / SiriAnalytics / "
                "symptomsd-diag / suggestd / parsecd / coreduetd / "
                "photoanalysisd / knowledge-agent / bird / cloudd / "
                "wifianalyticsagent / searchpartyd. Use this for "
                "owner-sovereignty audits, not as an attack signal."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "macos", "category": "process_creation"},
            "detection": {
                "selection_apple_telemetry_proc": {
                    "Image|contains": sorted(_APPLE_TELEMETRY_PROCESS_NAMES),
                },
                "condition": "selection_apple_telemetry_proc",
            },
            "level": "informational",
            "tags": [
                "attack.collection",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        labels_set = {lbl for lbl, _ in _APPLE_TELEMETRY_LABELS}
        labels_friendly = dict(_APPLE_TELEMETRY_LABELS)

        # ---- M1 telemetry launchd jobs (loaded / present) ---- #
        seen_labels: set[str] = set()
        for art in store.iter_artifacts(collector="macos.launchd"):
            d = art["data"] or {}
            label = (d.get("label") or "").strip()
            if not label or label in seen_labels:
                continue
            if label not in labels_set:
                # Allow substring match against compound parsec/seedusaged
                # variants that share a common prefix.
                if not any(label == k for k in labels_set):
                    continue
            seen_labels.add(label)
            yield Finding(
                detector=self.name,
                severity="low",
                title=(
                    f"Apple-telemetry launchd job present: {label}"
                ),
                summary=(
                    f"Launchd job ``{label}`` "
                    f"({labels_friendly.get(label, '')}) is configured "
                    "on this Mac. On hardware you own, you may wish "
                    "to disable it. The remediation_commands block "
                    "contains the launchctl disable + bootout commands "
                    "(reversible via launchctl enable + bootstrap)."
                ),
                artifact_refs=[art["artifact_uuid"]],
                evidence={
                    "kind": "apple_telemetry_launchd",
                    "label": label,
                    "friendly": labels_friendly.get(label, ""),
                    "plist_path": d.get("path"),
                    "remediation_commands": _redact_block(
                        _REM_LAUNCHD_DISABLE.format(label=label)
                    ),
                    "reversible": True,
                },
                mitre="T1059.004",  # macOS shell — closest fit
            )

        # ---- M2 telemetry processes running ---- #
        seen_proc: set[tuple[int, str]] = set()
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            name = (d.get("name") or "").lower()
            exe = (d.get("exe") or "").lower()
            base = (_basename(exe) or name).lower()
            for tn in _APPLE_TELEMETRY_PROCESS_NAMES:
                tn_l = tn.lower()
                if tn_l in base or tn_l in name:
                    key = (d.get("pid") or 0, tn)
                    if key in seen_proc:
                        continue
                    seen_proc.add(key)
                    yield Finding(
                        detector=self.name,
                        severity="info",
                        title=(
                            f"Apple-telemetry process running: {tn} "
                            f"(pid {d.get('pid')})"
                        ),
                        summary=(
                            f"Process pid {d.get('pid')} ({base}) "
                            f"matches Apple-telemetry component "
                            f"``{tn}``. Disable the underlying "
                            "launchd job via the remediation_commands "
                            "block; the process will exit after "
                            "bootout."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "apple_telemetry_process",
                            "component": tn,
                            "pid": d.get("pid"),
                            "exe": d.get("exe"),
                            "remediation_commands": _redact_block(
                                _REM_LAUNCHD_DISABLE.format(label=(
                                    f"com.apple.{tn}"
                                    if not tn.startswith("com.apple.") else tn
                                ))
                            ),
                            "reversible": True,
                        },
                        mitre="T1059.004",
                    )
                    break

        # ---- M3 crash-report / SubmitDiagInfo AutoSubmit ---- #
        # Some collectors ship profile / preference state. Heuristic:
        # look for AutoSubmit = true in any collected artifact JSON.
        emitted_diag_finding = False
        for art in store.iter_artifacts():
            if emitted_diag_finding:
                break
            d = art.get("data") or {}
            try:
                import json as _json
                text = _json.dumps(d, default=str).lower()
            except Exception:
                continue
            if ("autosubmit" in text and
                    re.search(r'"autosubmit"\s*:\s*(?:true|1|"yes")', text, re.I)):
                emitted_diag_finding = True
                yield Finding(
                    detector=self.name,
                    severity="low",
                    title=(
                        "Diagnostic-report auto-submit to Apple is "
                        "enabled"
                    ),
                    summary=(
                        f"Artifact from collector {art.get('collector')} "
                        "indicates AutoSubmit=true for CrashReporter "
                        "or SubmitDiagInfo. Crash reports and "
                        "diagnostic data are being uploaded to Apple. "
                        "The remediation_commands block disables this "
                        "system-wide and opts out of Siri data sharing "
                        "per-user. Reversible."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "apple_diag_autosubmit",
                        "collector": art.get("collector"),
                        "remediation_commands": _redact_block(
                            _REM_DIAG_AUTOSUBMIT
                        ),
                        "reversible": True,
                    },
                    mitre="T1059.004",
                )

        # ---- M4 Apple-telemetry hosts in DNS history ---- #
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
                for ah in _APPLE_TELEMETRY_HOSTS:
                    if ah in h and ah not in seen_hosts:
                        seen_hosts.add(ah)
                        if host_rem is None:
                            host_rem = _redact_block(_build_hosts_remediation())
                        yield Finding(
                            detector=self.name,
                            severity="info",
                            title=(
                                f"Apple-telemetry host resolved: {ah}"
                            ),
                            summary=(
                                f"DNS history shows resolution of "
                                f"``{ah}``. Block at the hosts file via "
                                "the remediation_commands block. "
                                "Reversible (edit /etc/hosts between "
                                "the digger markers)."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "apple_telemetry_dns",
                                "host": ah,
                                "remediation_commands": host_rem,
                                "reversible": True,
                            },
                            mitre="T1059.004",
                        )
                        break

        # ---- M5 TCC entries granting FeedbackAssistant / AppleSeed ---- #
        emitted_tcc = False
        for art in store.iter_artifacts(collector="macos.tcc"):
            if emitted_tcc:
                break
            d = art["data"] or {}
            try:
                import json as _json
                text = _json.dumps(d, default=str).lower()
            except Exception:
                continue
            if ("feedbackassistant" in text or "appleseed" in text):
                emitted_tcc = True
                yield Finding(
                    detector=self.name,
                    severity="info",
                    title=(
                        "TCC entries grant access to AppleSeed / "
                        "FeedbackAssistant"
                    ),
                    summary=(
                        "TCC database contains entries granting "
                        "AppleSeed or FeedbackAssistant access to "
                        "user data. This indicates beta-feedback "
                        "participation. Revoke per-app in System "
                        "Settings > Privacy & Security; the relevant "
                        "TCC table rows can be cleared via:\n\n"
                        "  tccutil reset All com.apple.appleseed.FeedbackAssistant\n"
                        "  tccutil reset All com.apple.appleseed.FBAHelperService"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "tcc_appleseed_grant",
                        "remediation_commands": _redact_block(
                            "tccutil reset All com.apple.appleseed.FeedbackAssistant\n"
                            "tccutil reset All com.apple.appleseed.FBAHelperService"
                        ),
                        "reversible": True,
                    },
                    mitre="T1059.004",
                )

        # ---- Spotlight Suggestions advisory (always emit one) ---- #
        # We don't have a clean way to scan macOS preference state for
        # the Spotlight Suggestions toggle, so we emit one informational
        # finding per case with the disable command. The user can
        # ignore if already disabled.
        suggested_emitted = False
        for _ in store.iter_artifacts(collector="macos.launchd"):
            if not suggested_emitted:
                suggested_emitted = True
                yield Finding(
                    detector=self.name,
                    severity="info",
                    title=(
                        "Spotlight Suggestions (cloud-side query "
                        "routing) opt-out command available"
                    ),
                    summary=(
                        "Spotlight Suggestions sends partial search "
                        "queries to Apple for web/Siri suggestions. "
                        "On a Mac you own, you may wish to disable "
                        "this. The remediation_commands block contains "
                        "the defaults-write commands plus the "
                        "suggestd HUP to apply immediately. Reversible "
                        "via System Settings > Spotlight > Search "
                        "Results."
                    ),
                    artifact_refs=[],
                    evidence={
                        "kind": "spotlight_suggestions_advisory",
                        "remediation_commands": _redact_block(
                            _REM_SPOTLIGHT_SUGGESTIONS
                        ),
                        "reversible": True,
                    },
                    mitre="T1059.004",
                )
            break
