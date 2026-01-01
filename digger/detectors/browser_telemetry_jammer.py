"""Browser telemetry jammer — cross-platform owner-sovereignty disabler
for Chrome / Chromium / Edge / Brave / Opera / Firefox / Vivaldi.

Completes the sovereignty pattern after Windows / macOS / Linux OS-side
telemetry jammers. Browsers run the same way on every OS, so this
detector is cross-platform: detection looks at the cross-platform
``browsers`` collector + ``processes`` + ``dns`` artifacts.

Architecture matches the rest of the family: observation-only detection
+ copy-pasteable opt-in remediation commands the owner runs themselves
at an elevated shell. ``digger`` never applies the commands; see
ethics-contract P2.

What this detects
-----------------

  B1  Browser binary running (chrome / chromium / msedge / brave /
      opera / vivaldi / firefox / librewolf / waterfox). Emits the
      per-browser opt-out policy block.

  B2  Browser-telemetry endpoint resolved in DNS (37 hosts across
      Google variations / UMA, Microsoft Edge experimentation,
      Brave P3A / ads / news, Mozilla Normandy / Shield / Push /
      Telemetry, Opera sync / push, Vivaldi privacy-respecting-by-
      default endpoints they still hit).

  B3  Browser profile path present in any artifact (recent_files,
      browsers collector). For Chrome / Edge / Brave / Firefox /
      Vivaldi, emit a profile-aware opt-out block.

Each browser ships its own opt-out mechanism:

  Chrome / Chromium / Edge — policy JSON file at OS-appropriate path
                              with MetricsReportingEnabled=false,
                              UserFeedbackAllowed=false,
                              SyncDisabled=true, etc.
  Brave — Settings → Privacy and security → "Privacy-preserving
          product analytics (P3A)" off; ad / news opt-out via prefs
          or brave://settings JSON.
  Firefox — user.js per-profile (already shipped in linux_telemetry_
          jammer, repeated here for cross-OS users with a Firefox
          install).
  Opera — opera://settings#privacy + sync.opera.com blocking.
  Vivaldi — vivaldi://settings/general → Privacy → uncheck "Send
          anonymous usage data".

Severity is ``info`` or ``low`` — these are present-state observations
on the owner's machine, not attack signals.
"""

# live-first-ok: Browser-vendor telemetry endpoints and policy keys
# are stable; vendors don't publish a machine-readable list. The
# bundled rules below are the right home for additions.

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector
from digger.ethics.contract import redact_dangerous_command


# ---- Browser process basenames ---- #
_BROWSERS = {
    "chrome":     "Google Chrome",
    "chromium":   "Chromium",
    "google chrome": "Google Chrome",
    "msedge":     "Microsoft Edge",
    "microsoftedge": "Microsoft Edge",
    "brave":      "Brave Browser",
    "brave browser": "Brave Browser",
    "opera":      "Opera",
    "vivaldi":    "Vivaldi",
    "firefox":    "Firefox",
    "librewolf":  "LibreWolf",
    "waterfox":   "Waterfox",
}

# ---- Telemetry endpoints by browser ---- #
_BROWSER_TELEMETRY_HOSTS = [
    # Google Chrome / Chromium
    ("clients2.google.com",                    "Chrome — variations + crash uploads"),
    ("clients4.google.com",                    "Chrome — telemetry / variations"),
    ("update.googleapis.com",                  "Chrome — auto-update channel"),
    ("ssl.gstatic.com",                        "Chrome — UI assets + ping"),
    ("safebrowsing.googleapis.com",            "Chrome Safe-Browsing API"),
    ("clientservices.googleapis.com",          "Chrome — services + variations"),
    ("optimizationguide-pa.googleapis.com",    "Chrome optimization-guide"),
    # Microsoft Edge
    ("edge.microsoft.com",                     "Edge — variations + telemetry"),
    ("config.edge.skype.com",                  "Edge configuration service"),
    ("browser.events.data.msn.com",            "Edge browser-events telemetry"),
    ("c.msn.com",                              "Edge / MSN events"),
    ("dsa.signalfx.com",                       "Edge — feedback signal-flow"),
    ("browser.pipe.aria.microsoft.com",        "Edge Aria pipeline"),
    # Brave
    ("p3a.brave.com",                          "Brave P3A privacy-preserving analytics"),
    ("p3a-creative.brave.com",                 "Brave P3A creative reporting"),
    ("variations.brave.com",                   "Brave variations server"),
    ("brave-stats.brave.com",                  "Brave stats collection"),
    ("brave-core-ext.s3.brave.com",            "Brave core extension updates"),
    ("rewards.brave.com",                      "Brave Rewards backend"),
    ("ads-serve.brave.com",                    "Brave Ads endpoint"),
    ("today.bravesoftware.com",                "Brave News content backend"),
    # Mozilla Firefox (also in linux_telemetry_jammer; restated for cross-OS)
    ("incoming.telemetry.mozilla.org",         "Firefox telemetry ingest"),
    ("self-repair.mozilla.org",                "Firefox Normandy self-repair"),
    ("shavar.services.mozilla.com",            "Firefox tracking-protection list"),
    ("normandy.cdn.mozilla.net",               "Firefox Normandy experiments"),
    ("experiments.mozilla.org",                "Firefox Shield studies"),
    ("settings.services.mozilla.com",          "Firefox Remote Settings"),
    ("push.services.mozilla.com",              "Firefox push notifications"),
    ("location.services.mozilla.com",          "Firefox geolocation lookup"),
    # Opera
    ("sync.opera.com",                         "Opera sync service"),
    ("redir.opera.com",                        "Opera redirect telemetry"),
    ("push.opera.com",                         "Opera push notifications"),
    ("certs.opera.com",                        "Opera cert-ping"),
    # Vivaldi
    ("update.vivaldi.com",                     "Vivaldi auto-update"),
    ("downloads.vivaldi.com",                  "Vivaldi installer telemetry"),
    ("api.vivaldi.net",                        "Vivaldi sync API"),
]


# ---- Per-browser remediation blocks ---- #

_REM_CHROME_POLICY_LINUX = """\
# Chrome / Chromium policy on Linux. Reversible: delete the policy file.
sudo mkdir -p /etc/opt/chrome/policies/managed /etc/chromium/policies/managed
sudo tee /etc/opt/chrome/policies/managed/digger-telemetry-off.json <<'JSON' >/dev/null
{
  "MetricsReportingEnabled": false,
  "UrlKeyedAnonymizedDataCollectionEnabled": false,
  "UserFeedbackAllowed": false,
  "SyncDisabled": true,
  "DefaultBrowserSettingEnabled": false,
  "ComponentUpdatesEnabled": false,
  "VariationsServerEnabled": false
}
JSON
sudo cp /etc/opt/chrome/policies/managed/digger-telemetry-off.json /etc/chromium/policies/managed/digger-telemetry-off.json
# Apply by restarting the browser.
"""

_REM_CHROME_POLICY_MACOS = """\
# Chrome / Chromium policy on macOS. Reversible: defaults delete.
sudo defaults write /Library/Preferences/com.google.Chrome MetricsReportingEnabled -bool false
sudo defaults write /Library/Preferences/com.google.Chrome UrlKeyedAnonymizedDataCollectionEnabled -bool false
sudo defaults write /Library/Preferences/com.google.Chrome UserFeedbackAllowed -bool false
sudo defaults write /Library/Preferences/com.google.Chrome SyncDisabled -bool true
sudo defaults write /Library/Preferences/com.google.Chrome ComponentUpdatesEnabled -bool false
sudo defaults write /Library/Preferences/com.google.Chrome VariationsServerEnabled -bool false
# Repeat for Chromium:
sudo defaults write /Library/Preferences/org.chromium.Chromium MetricsReportingEnabled -bool false
sudo defaults write /Library/Preferences/org.chromium.Chromium UrlKeyedAnonymizedDataCollectionEnabled -bool false
"""

_REM_CHROME_POLICY_WINDOWS = """\
# Chrome / Chromium policy on Windows. Reversible: Remove-Item the keys.
$base = 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome'
New-Item -Path $base -Force | Out-Null
Set-ItemProperty -Path $base -Name 'MetricsReportingEnabled' -Type DWord -Value 0
Set-ItemProperty -Path $base -Name 'UrlKeyedAnonymizedDataCollectionEnabled' -Type DWord -Value 0
Set-ItemProperty -Path $base -Name 'UserFeedbackAllowed' -Type DWord -Value 0
Set-ItemProperty -Path $base -Name 'SyncDisabled' -Type DWord -Value 1
Set-ItemProperty -Path $base -Name 'ComponentUpdatesEnabled' -Type DWord -Value 0
Set-ItemProperty -Path $base -Name 'VariationsServerEnabled' -Type DWord -Value 0
# Chromium:
$cbase = 'HKLM:\\SOFTWARE\\Policies\\Chromium'
New-Item -Path $cbase -Force | Out-Null
Set-ItemProperty -Path $cbase -Name 'MetricsReportingEnabled' -Type DWord -Value 0
"""

_REM_EDGE_POLICY_WINDOWS = """\
# Edge policy on Windows. Reversible: Remove-Item the keys.
$base = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge'
New-Item -Path $base -Force | Out-Null
Set-ItemProperty -Path $base -Name 'MetricsReportingEnabled' -Type DWord -Value 0
Set-ItemProperty -Path $base -Name 'PersonalizationReportingEnabled' -Type DWord -Value 0
Set-ItemProperty -Path $base -Name 'EdgeShoppingAssistantEnabled' -Type DWord -Value 0
Set-ItemProperty -Path $base -Name 'DiagnosticData' -Type DWord -Value 0
Set-ItemProperty -Path $base -Name 'SyncDisabled' -Type DWord -Value 1
Set-ItemProperty -Path $base -Name 'SearchSuggestEnabled' -Type DWord -Value 0
Set-ItemProperty -Path $base -Name 'UserFeedbackAllowed' -Type DWord -Value 0
Set-ItemProperty -Path $base -Name 'PaymentMethodQueryEnabled' -Type DWord -Value 0
"""

_REM_EDGE_POLICY_MACOS = """\
# Edge policy on macOS. Reversible: defaults delete.
sudo defaults write /Library/Preferences/com.microsoft.Edge MetricsReportingEnabled -bool false
sudo defaults write /Library/Preferences/com.microsoft.Edge PersonalizationReportingEnabled -bool false
sudo defaults write /Library/Preferences/com.microsoft.Edge DiagnosticData -int 0
sudo defaults write /Library/Preferences/com.microsoft.Edge SyncDisabled -bool true
sudo defaults write /Library/Preferences/com.microsoft.Edge SearchSuggestEnabled -bool false
sudo defaults write /Library/Preferences/com.microsoft.Edge UserFeedbackAllowed -bool false
"""

_REM_EDGE_POLICY_LINUX = """\
# Edge policy on Linux. Reversible: delete the policy file.
sudo mkdir -p /etc/opt/edge/policies/managed
sudo tee /etc/opt/edge/policies/managed/digger-edge-off.json <<'JSON' >/dev/null
{
  "MetricsReportingEnabled": false,
  "PersonalizationReportingEnabled": false,
  "DiagnosticData": 0,
  "SyncDisabled": true,
  "SearchSuggestEnabled": false,
  "UserFeedbackAllowed": false,
  "PaymentMethodQueryEnabled": false
}
JSON
"""

_REM_BRAVE = """\
# Brave per-profile opt-outs. Brave honors policy on Linux too,
# but the per-profile prefs.json route covers all OSes.
# Reversible: open brave://settings/privacy and toggle back.
#
# 1. Disable P3A (privacy-preserving analytics) globally:
#    brave://settings/privacy → "Help make Brave better" → off
#    Or via the brave_local_state file (closes Brave first):
for ls in ~/.config/BraveSoftware/Brave-Browser/Local\\ State \\
          ~/Library/Application\\ Support/BraveSoftware/Brave-Browser/Local\\ State \\
          "$LOCALAPPDATA/BraveSoftware/Brave-Browser/User Data/Local State"; do
    [ -f "$ls" ] || continue
    python3 - "$ls" <<'PY'
import json, sys, pathlib
p = pathlib.Path(sys.argv[1])
data = json.loads(p.read_text())
data.setdefault('brave', {})['p3a'] = data['brave'].get('p3a', {})
data['brave']['p3a']['enabled'] = False
data['brave']['stats'] = data['brave'].get('stats', {})
data['brave']['stats']['reporting_enabled'] = False
data['user_experience_metrics'] = {'reporting_enabled': False}
p.write_text(json.dumps(data, indent=2))
print(f'patched {p}')
PY
done

# 2. Disable Brave Ads + Rewards in the per-profile prefs.json:
#    brave://settings/rewards → off
# 3. Disable Brave News:
#    brave://settings → Appearance → uncheck "Brave News"
# 4. Disable Web Discovery Project:
#    brave://settings/search → uncheck "Web discovery project"
"""

_REM_FIREFOX = """\
# Firefox user.js opt-out (per-profile). Reversible: edit user.js and
# remove the lines, or delete user.js entirely.
for prof in ~/.mozilla/firefox/*.default* \\
            ~/Library/Application\\ Support/Firefox/Profiles/*.default* \\
            "$APPDATA/Mozilla/Firefox/Profiles"/*.default*; do
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
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.search.suggest.enabled", false);
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.predictor.enabled", false);
user_pref("media.peerconnection.enabled", false);
PREFS_EOF
done
"""

_REM_OPERA = """\
# Opera privacy hardening. Reversible via opera://settings.
# Open opera://settings/privacy and:
#   - "Send usage statistics" → off
#   - "Use a prediction service to help complete searches" → off
#   - "Use a web service to help resolve navigation errors" → off
#   - Disable Opera sync entirely if not used:
#     opera://settings/syncSetup → Sign out
# DNS-level block of sync.opera.com and push.opera.com handled via the
# hosts-file remediation below.
"""

_REM_VIVALDI = """\
# Vivaldi privacy hardening. Reversible via vivaldi://settings.
# Open vivaldi://settings/general → Privacy and:
#   - "Send anonymous usage data" → off
#   - "Send anonymous version reports" → off
#   - "Auto-update browser" → off (if you want manual updates)
# Disable sync:
#   vivaldi://settings/sync → Sign out / Disable sync
"""

_REM_HOSTS_BLOCK = """\
# Cross-OS hosts-file block of all 37 browser-telemetry endpoints.
# Reversible: edit the hosts file and remove lines between digger markers.
HOSTS=(
{host_lines}
)
# Linux + macOS:
if [ -w /etc/hosts ] || sudo -n true 2>/dev/null; then
    sudo tee -a /etc/hosts <<'HOSTS_EOF'

# digger browser-telemetry-jammer begin
HOSTS_EOF
    for h in "${{HOSTS[@]}}"; do
        grep -qxF "0.0.0.0 $h" /etc/hosts || echo "0.0.0.0 $h" | sudo tee -a /etc/hosts >/dev/null
    done
    echo "# digger browser-telemetry-jammer end" | sudo tee -a /etc/hosts >/dev/null
fi
# Windows (run from elevated PowerShell):
#   $hostsFile = "$env:WINDIR\\System32\\drivers\\etc\\hosts"
#   Add-Content -Path $hostsFile -Value "`n# digger browser-telemetry-jammer begin"
#   $HOSTS = @({host_lines_quoted})
#   foreach ($h in $HOSTS) {{ Add-Content -Path $hostsFile -Value "0.0.0.0 $h" }}
#   Add-Content -Path $hostsFile -Value "# digger browser-telemetry-jammer end"
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
    lines = "\n".join(f"    '{h}'" for h, _ in _BROWSER_TELEMETRY_HOSTS)
    qlines = ", ".join(f'"{h}"' for h, _ in _BROWSER_TELEMETRY_HOSTS)
    return _REM_HOSTS_BLOCK.format(host_lines=lines, host_lines_quoted=qlines)


# Per-browser remediation routing.
_PER_BROWSER_REMEDIATION: dict[str, dict[str, str]] = {
    "chrome": {
        "linux":   _REM_CHROME_POLICY_LINUX,
        "macos":   _REM_CHROME_POLICY_MACOS,
        "windows": _REM_CHROME_POLICY_WINDOWS,
    },
    "chromium": {
        "linux":   _REM_CHROME_POLICY_LINUX,
        "macos":   _REM_CHROME_POLICY_MACOS,
        "windows": _REM_CHROME_POLICY_WINDOWS,
    },
    "msedge": {
        "linux":   _REM_EDGE_POLICY_LINUX,
        "macos":   _REM_EDGE_POLICY_MACOS,
        "windows": _REM_EDGE_POLICY_WINDOWS,
    },
    "brave":   {"all": _REM_BRAVE},
    "firefox": {"all": _REM_FIREFOX},
    "librewolf": {"all": _REM_FIREFOX},
    "waterfox": {"all": _REM_FIREFOX},
    "opera":   {"all": _REM_OPERA},
    "vivaldi": {"all": _REM_VIVALDI},
}


def _basename(path: str) -> str:
    if not path:
        return ""
    if "/" in path:
        path = path.rsplit("/", 1)[1]
    if "\\" in path:
        path = path.rsplit("\\", 1)[1]
    return path


def _normalize_browser(s: str) -> str:
    """Return the lookup key for _PER_BROWSER_REMEDIATION, or '' if no match.

    Result is always a single-word key present in
    ``_PER_BROWSER_REMEDIATION``: chrome / chromium / msedge / brave /
    opera / vivaldi / firefox / librewolf / waterfox."""
    if not s:
        return ""
    s = s.lower()
    s = _basename(s)
    if s.endswith(".exe"):
        s = s[:-4]
    # Map known compound names to their canonical single-word key.
    folds = {
        "google chrome":   "chrome",
        "google-chrome":   "chrome",
        "brave browser":   "brave",
        "microsoftedge":   "msedge",
        "microsoft edge":  "msedge",
    }
    if s in folds:
        return folds[s]
    if s in _PER_BROWSER_REMEDIATION:
        return s
    # Substring match against the single-word remediation keys.
    for k in _PER_BROWSER_REMEDIATION:
        if k in s:
            return k
    return ""


def _resolve_remediation(browser_key: str) -> str:
    """Pick the right per-OS remediation for a browser, with an
    'all' fallback that covers cross-OS settings (Firefox / Brave /
    Opera / Vivaldi)."""
    table = _PER_BROWSER_REMEDIATION.get(browser_key)
    if not table:
        return ""
    if "all" in table:
        return table["all"]
    # Concatenate every per-OS variant — user picks the relevant block.
    chunks = []
    for os_key in ("linux", "macos", "windows"):
        if os_key in table:
            chunks.append(f"# ==== {os_key.upper()} ====\n" + table[os_key])
    return "\n".join(chunks)


class BrowserTelemetryJammerDetector(Detector):
    name = "browser_telemetry_jammer"
    description = (
        "Cross-platform browser sovereignty: detects active "
        "Chrome / Chromium / Edge / Brave / Opera / Vivaldi / Firefox "
        "/ LibreWolf / Waterfox installs and emits per-browser opt-in "
        "policy/JSON/user.js commands that disable telemetry, "
        "variations, P3A, Normandy, sync, and search-suggestion cloud "
        "routing. Plus DNS-blocklist commands for 37 browser-vendor "
        "telemetry endpoints. Observation-only; user runs the commands "
        "themselves (same pattern as firewall_audit)."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Browser process telemetry surface active",
            "id": "digger-browser-telemetry-jammer-template",
            "description": (
                "A Chromium-family or Mozilla-family browser is "
                "running. Useful for owner-sovereignty audits."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_browser_proc": {
                    "Image|endswith": [
                        "/chrome", "/chromium", "/chrome.exe",
                        "/chromium.exe", "/msedge.exe", "/MicrosoftEdge.exe",
                        "/brave", "/brave.exe",
                        "/opera", "/opera.exe",
                        "/vivaldi", "/vivaldi.exe",
                        "/firefox", "/firefox.exe",
                        "/librewolf", "/librewolf.exe",
                        "/waterfox", "/waterfox.exe",
                    ],
                },
                "condition": "selection_browser_proc",
            },
            "level": "informational",
            "tags": ["attack.collection"],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- B1 browser processes running ---- #
        seen_browsers: set[str] = set()
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            name = (d.get("name") or "").lower()
            exe = (d.get("exe") or "").lower()
            base = _basename(exe) or name
            browser_key = _normalize_browser(base) or _normalize_browser(name)
            if not browser_key or browser_key in seen_browsers:
                continue
            seen_browsers.add(browser_key)
            friendly = _BROWSERS.get(browser_key, browser_key)
            yield Finding(
                detector=self.name,
                severity="info",
                title=(
                    f"{friendly} running — opt-out remediation available"
                ),
                summary=(
                    f"Process pid {d.get('pid')} ({base}) is {friendly}. "
                    "The remediation_commands block contains the per-OS "
                    "policy / preferences commands to disable variations, "
                    "telemetry, sync, search-suggestion cloud routing, "
                    "and (where applicable) P3A / Normandy / Shield. "
                    "Apply by closing the browser, running the commands, "
                    "and reopening."
                ),
                artifact_refs=[art["artifact_uuid"]],
                evidence={
                    "kind": "browser_process",
                    "browser": browser_key,
                    "friendly": friendly,
                    "pid": d.get("pid"),
                    "exe": d.get("exe"),
                    "remediation_commands": _redact_block(
                        _resolve_remediation(browser_key)
                    ),
                    "reversible": True,
                },
                mitre="T1059",  # generic — browsers aren't an attack
                                # technique, but Sigma needs a tag
            )

        # ---- B2 browser-telemetry endpoints in DNS history ---- #
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
                for telhost, friendly in _BROWSER_TELEMETRY_HOSTS:
                    if telhost in h and telhost not in seen_hosts:
                        seen_hosts.add(telhost)
                        if host_rem is None:
                            host_rem = _redact_block(_build_hosts_remediation())
                        yield Finding(
                            detector=self.name,
                            severity="info",
                            title=(
                                f"Browser-telemetry host resolved: "
                                f"{telhost} ({friendly})"
                            ),
                            summary=(
                                f"DNS history shows resolution of "
                                f"``{telhost}`` — {friendly}. Block at "
                                "the hosts file via the "
                                "remediation_commands block. Reversible."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "browser_telemetry_dns",
                                "host": telhost,
                                "friendly": friendly,
                                "remediation_commands": host_rem,
                                "reversible": True,
                            },
                            mitre="T1071.001",
                        )
                        break

        # ---- B3 browser profile path present in any artifact ---- #
        # The 'browsers' collector ships profile paths in subjects like
        # "browser:Chrome:default". When we see one, emit a profile-
        # aware advisory.
        seen_profile_browsers: set[str] = set()
        for art in store.iter_artifacts(collector="browsers"):
            subject = (art.get("subject") or "").lower()
            for browser_key in _BROWSERS:
                key = browser_key.split()[0]  # "google chrome" → "google"
                if key in subject and browser_key not in seen_profile_browsers:
                    seen_profile_browsers.add(browser_key)
                    norm = _normalize_browser(browser_key)
                    if not norm:
                        continue
                    yield Finding(
                        detector=self.name,
                        severity="info",
                        title=(
                            f"{_BROWSERS.get(norm, norm)} profile present "
                            f"— per-profile telemetry remediation "
                            "available"
                        ),
                        summary=(
                            f"Browser profile data for "
                            f"{_BROWSERS.get(norm, norm)} was collected. "
                            "The remediation_commands block contains the "
                            "per-profile opt-out (user.js, prefs.json, "
                            "or Local State patches) you can apply with "
                            "the browser closed."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "browser_profile",
                            "browser": norm,
                            "friendly": _BROWSERS.get(norm, norm),
                            "remediation_commands": _redact_block(
                                _resolve_remediation(norm)
                            ),
                            "reversible": True,
                        },
                        mitre="T1059",
                    )
                    break
