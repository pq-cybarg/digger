"""Active blockers against Shai-Hulud + Mini Shai-Hulud destructive
abilities (and the wider class of npm/PyPI worms that share the same
primitives).

This is the *hardening* mirror of ShaiHuludDetector and
MiniShaiHuludDetector — those find compromise. This one inventories
the attack surface those worms use and emits owner-runnable
hardening commands that neuter the primitives. Same architecture as
the rest of the sovereignty family: observation only, copy-pasteable
opt-in commands, redact_dangerous_command on display.

What this hardens against
-------------------------

  H1  Destructive ``rm -rf ~/`` on token revocation
      Both Shai-Hulud variants persist via ``gh-token-monitor``
      (LaunchAgent / systemd) and trigger a home-dir wipe if the
      harvested GitHub token is revoked while the service is alive.
      Hardening: detect the presence of the service file AND emit
      the DISARM-FIRST sequence (kill, unload/disable, remove the
      file) BEFORE the user rotates any GitHub token.

  H2  npm preinstall / postinstall script execution
      The dropper enters via lifecycle scripts. Hardening: set
      ``ignore-scripts=true`` in ~/.npmrc + projects' .npmrc,
      and recommend ``npm config set unsafe-perm false``. Reversible.

  H3  IDE-config write surface (.claude/, .vscode/)
      The worm self-propagates by overwriting these directories.
      Hardening: detect their existence + recommend making them
      append-only (chattr +a on Linux, chflags uappnd on macOS) or
      fully immutable (chattr +i / chflags uchg). The user must
      remove the flag temporarily when legitimately editing.

  H4  LaunchAgent / systemd-user persistence write surface
      Both worms drop ``gh-token-monitor`` into ~/Library/Launch
      Agents/ or ~/.config/systemd/user/. Hardening: keep an
      allow-list of what *should* be there (snapshot it once) and
      detect drift; chmod the directory 500 between deployments to
      prevent silent writes.

  H5  Privilege-escalation surface (sudoers, wheel, capabilities)
      A foothold trying to escalate from user → root via these
      paths. Hardening: recommend pruning ``NOPASSWD`` from /etc/
      sudoers, removing user from wheel/admin if not needed, and
      auditing ``getcap -r / 2>/dev/null`` output for unexpected
      caps. (Detection-only; we never modify sudoers ourselves.)

  H6  Network egress to known C2 / exfil hosts
      git-tanstack.com, webhook.site, filev2.getsession.org,
      seed[123].getsession.org, ddjidd564.github.io, plus the
      published IPs (78.29.48.29, 212.232.23.69, 179.43.140.214,
      83.142.209.194). Hardening: hosts-file block + firewall
      rule.

  H7  GitHub Actions / token least-privilege defaults
      Most worms harvest GITHUB_TOKEN with default workflow
      permissions (write to repo). Hardening: per-repo +
      organisation-level ``permissions: read-all`` default + enable
      "Require approval for first-time contributors" + prune
      ``actions/cache`` write scope. (Documentation finding;
      requires user action via GitHub UI.)

  H8  Session messenger client presence
      The worm uses the Session messenger network for stealthy C2.
      Hardening: detect any Session-client install or its config
      directory (~/.config/Session, ~/Library/Application Support/
      Session, %APPDATA%/Session) and flag for review. A legitimate
      Session user should know this is here.

Architecture: every finding ships severity ``info`` or ``low`` —
they are present-state observations on owner hardware with an
opt-in hardening block. Like ``firewall_audit``, ``digger`` shows
the facts; the owner chooses the response.
"""

# live-first-ok: Shai-Hulud-family IOCs are vendor-blog-published
# (Wiz, Aikido, Socket, Huntress). The hardening commands targeting
# their primitives are stable shell / npm / chmod / chattr commands.
# No upstream live feed for either side; bundled rules are the home.

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector
from digger.ethics.contract import redact_dangerous_command


# ---- Hardening command blocks (all reversible) ---- #

_HARDEN_DISARM_FIRST = """\
# CRITICAL: DISARM-FIRST sequence. Both Shai-Hulud and Mini Shai-Hulud
# trigger `rm -rf ~/` if their gh-token-monitor service detects the
# harvested GitHub token has been revoked. DO NOT revoke any token
# until this sequence completes successfully.

# 1. Identify the service:
ps -fe | grep -E 'gh-token-monitor|router_init|router_runtime' | grep -v grep
launchctl list 2>/dev/null | grep -E 'gh-token-monitor|token-monitor' || true
systemctl --user list-units --type=service --all 2>/dev/null | grep gh-token-monitor || true

# 2. KILL the running process FIRST, then disable persistence:
pkill -9 -f gh-token-monitor 2>/dev/null || true
pkill -9 -f router_runtime 2>/dev/null || true
pkill -9 -f tanstack_runner 2>/dev/null || true

# 3. Unload + remove persistence files:
launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null || true
rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
systemctl --user stop gh-token-monitor.service 2>/dev/null || true
systemctl --user disable gh-token-monitor.service 2>/dev/null || true
rm -f ~/.config/systemd/user/gh-token-monitor.service

# 4. Confirm nothing matches anymore:
pgrep -af gh-token-monitor || echo "OK: no gh-token-monitor process"
test ! -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist && \\
    test ! -f ~/.config/systemd/user/gh-token-monitor.service && \\
    echo "OK: persistence files removed"

# 5. NOW it is safe to rotate the GitHub token at github.com/settings/tokens.
"""

_HARDEN_NPM_IGNORE_SCRIPTS = """\
# Block npm lifecycle scripts (preinstall / postinstall / install) from
# executing automatically. The dropper for both Shai-Hulud variants is
# a setup.mjs in the preinstall hook.
# Reversible: npm config delete ignore-scripts
npm config set ignore-scripts true --global
npm config set unsafe-perm false --global
# Per-project .npmrc:
for proj in ~/code/* ~/projects/* ~/dev/* ~/src/*; do
    [ -d "$proj" ] || continue
    [ -f "$proj/package.json" ] || continue
    if ! grep -q '^ignore-scripts=true' "$proj/.npmrc" 2>/dev/null; then
        echo 'ignore-scripts=true' >> "$proj/.npmrc"
        echo "hardened: $proj/.npmrc"
    fi
done
# To run a trusted package's install hooks one-off after this:
#   npm install --ignore-scripts=false --foreground-scripts <pkg>
"""

_HARDEN_IDE_DIRS_IMMUTABLE = """\
# Make IDE configuration directories append-only or immutable so the
# worm's GitHub-GraphQL commit-poisoner can't silently rewrite them.
# Choose the right variant for your OS:

# ==== macOS ====
# chflags uchg makes a file/dir immutable (user-flag, removable by owner)
for d in ~/.claude ~/.vscode; do
    [ -d "$d" ] || continue
    chflags -R uchg "$d"
    echo "macOS: marked $d immutable (chflags uchg)"
done
# Unset before legitimate edits:
#   chflags -R nouchg ~/.claude && <edit> && chflags -R uchg ~/.claude

# ==== Linux ====
# chattr +a is append-only; +i is fully immutable.
for d in ~/.claude ~/.vscode; do
    [ -d "$d" ] || continue
    sudo chattr -R +i "$d"
    echo "Linux: marked $d immutable (chattr +i)"
done
# Unset before legitimate edits:
#   sudo chattr -R -i ~/.claude && <edit> && sudo chattr -R +i ~/.claude

# ==== Windows (PowerShell, elevated) ====
#   icacls "$env:USERPROFILE\\.claude" /deny "$($env:USERNAME):(WD,AD)"
#   icacls "$env:USERPROFILE\\.vscode" /deny "$($env:USERNAME):(WD,AD)"
# Reversible with /remove:d "$env:USERNAME".
"""

_HARDEN_PERSISTENCE_DIRS_LOCKED = """\
# Lock down LaunchAgent / systemd-user directories to prevent silent
# persistence writes by future worm variants.

# ==== macOS ====
# Snapshot the legitimate state first:
mkdir -p ~/.config/digger
ls -la ~/Library/LaunchAgents > ~/.config/digger/launchagents.snapshot
# Drop write permission on the directory:
chmod 500 ~/Library/LaunchAgents
echo "macOS: ~/Library/LaunchAgents is now r-x only"
# Unset for legitimate installer use:
#   chmod 700 ~/Library/LaunchAgents

# ==== Linux ====
mkdir -p ~/.config/digger
ls -la ~/.config/systemd/user > ~/.config/digger/systemd-user.snapshot
chmod 500 ~/.config/systemd/user
echo "Linux: ~/.config/systemd/user is now r-x only"
# Unset for legitimate installer use:
#   chmod 700 ~/.config/systemd/user
"""

_HARDEN_HOSTS_BLOCK = """\
# Block known Shai-Hulud / Mini Shai-Hulud / TrapDoor / Nightmare-Eclipse
# C2 + exfil hosts at the system hosts file.
# Reversible: edit /etc/hosts and remove lines between digger markers.

HOSTS=(
    'git-tanstack.com'
    'filev2.getsession.org'
    'seed1.getsession.org'
    'seed2.getsession.org'
    'seed3.getsession.org'
    'webhook.site'
    'ddjidd564.github.io'
    'staybud.dpdns.org'
)
sudo tee -a /etc/hosts <<'HOSTS_EOF'

# digger shai-hulud-blocker begin
HOSTS_EOF
for h in "${HOSTS[@]}"; do
    grep -qxF "0.0.0.0 $h" /etc/hosts || echo "0.0.0.0 $h" | sudo tee -a /etc/hosts >/dev/null
done
echo "# digger shai-hulud-blocker end" | sudo tee -a /etc/hosts >/dev/null

# Optional firewall (Linux nftables):
#   sudo nft add rule inet filter output ip daddr { 78.29.48.29, 212.232.23.69, 179.43.140.214, 83.142.209.194 } reject
# Optional firewall (macOS pf):
#   echo 'block out quick to {78.29.48.29 212.232.23.69 179.43.140.214 83.142.209.194}' \\
#       | sudo pfctl -ef -
# Optional firewall (Windows netsh):
#   netsh advfirewall firewall add rule name="digger-shaihulud-block" dir=out action=block remoteip=78.29.48.29,212.232.23.69,179.43.140.214,83.142.209.194
"""

_HARDEN_PRIVESC_AUDIT = """\
# Privilege-escalation surface audit. Detection-only — apply changes
# yourself only after reviewing.

# 1. NOPASSWD entries in sudoers (these let a user become root with
#    no challenge — perfect for a worm with shell access):
sudo grep -nR 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null

# 2. Membership in admin groups:
groups "$USER"
getent group wheel 2>/dev/null
getent group sudo  2>/dev/null
getent group admin 2>/dev/null

# 3. File capabilities (cap_setuid / cap_sys_admin on user binaries
#    are dangerous):
sudo getcap -r / 2>/dev/null | grep -v -E 'ping|tracepath|systemd-resolve' || true

# 4. SUID/SGID binaries outside /usr (anything in $HOME / /tmp /
#    /opt is suspect):
sudo find /home /Users /tmp /opt -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null

# To harden NOPASSWD:
#   sudo visudo  # remove the NOPASSWD line, save
# To remove user from sudo:
#   sudo gpasswd -d "$USER" sudo
"""

_HARDEN_GITHUB_TOKENS = """\
# GitHub token least-privilege hardening. Apply via GitHub UI; the
# commands here generate the gh CLI calls.

# 1. List your active PATs and OAuth grants:
gh auth status
gh api /user | jq '.login'
gh api /authorizations 2>/dev/null

# 2. For every repo you maintain, set Actions default permissions to
#    read-only (workflow can opt back into write with explicit
#    `permissions:` block):
for repo in $(gh repo list --json nameWithOwner -q '.[].nameWithOwner'); do
    gh api -X PUT "/repos/$repo/actions/permissions/workflow" \\
        -f default_workflow_permissions=read \\
        -F can_approve_pull_request_reviews=false 2>/dev/null \\
        && echo "hardened: $repo"
done

# 3. Require approval for first-time contributors org-wide:
#    Settings → Actions → "Require approval for all outside collaborators"
#    (no gh CLI equivalent yet — apply via web UI)

# 4. Audit npm publish tokens at npmjs.com:
#    https://www.npmjs.com/settings/<you>/tokens
#    Delete any "publish" token you don't actively use.

# 5. Audit OAuth app authorizations:
#    https://github.com/settings/applications
#    Revoke any app you don't recognize.
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


# Pre-redact once at import — these blocks never change per-finding.
_HARDEN_BLOCKS = {
    "disarm_first":           _redact_block(_HARDEN_DISARM_FIRST),
    "npm_ignore_scripts":     _redact_block(_HARDEN_NPM_IGNORE_SCRIPTS),
    "ide_dirs_immutable":     _redact_block(_HARDEN_IDE_DIRS_IMMUTABLE),
    "persistence_dirs_locked": _redact_block(_HARDEN_PERSISTENCE_DIRS_LOCKED),
    "hosts_block":            _redact_block(_HARDEN_HOSTS_BLOCK),
    "privesc_audit":          _redact_block(_HARDEN_PRIVESC_AUDIT),
    "github_tokens":          _redact_block(_HARDEN_GITHUB_TOKENS),
}


def _basename(path: str) -> str:
    if not path:
        return ""
    if "/" in path:
        path = path.rsplit("/", 1)[1]
    if "\\" in path:
        path = path.rsplit("\\", 1)[1]
    return path


class ShaiHuludBlockerDetector(Detector):
    name = "shai_hulud_blocker"
    description = (
        "Active hardening against Shai-Hulud + Mini Shai-Hulud "
        "destructive abilities and the wider npm/PyPI worm class. "
        "Inventories the worm's attack surface (gh-token-monitor "
        "persistence, npm lifecycle scripts, IDE-config writable "
        "directories, LaunchAgent/systemd-user writable surface, "
        "C2 hosts in DNS, NOPASSWD sudoers, file capabilities, SUID "
        "binaries in user space) and emits opt-in hardening commands. "
        "Includes a CRITICAL DISARM-FIRST sequence for the rm-rf-on-"
        "token-revoke payload. Observation-only; user runs the "
        "commands themselves (same pattern as firewall_audit)."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Shai-Hulud-family hardening surface present",
            "id": "digger-shai-hulud-blocker-template",
            "description": (
                "Reports inventory of Shai-Hulud / Mini Shai-Hulud "
                "attack surface for sovereignty hardening: gh-token-"
                "monitor service, npm config ignore-scripts state, "
                ".claude/.vscode write surface, ~/Library/LaunchAgents "
                "+ ~/.config/systemd/user contents, NOPASSWD sudoers, "
                "world-writable file caps, SUID-in-HOME."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_persistence": {
                    "TargetFilename|endswith": [
                        "/gh-token-monitor.plist",
                        "/gh-token-monitor.service",
                    ],
                },
                "selection_ide_dirs": {
                    "TargetFilename|contains": [
                        "/.claude/", "/.vscode/",
                    ],
                },
                "condition": "1 of selection_*",
            },
            "level": "informational",
            "tags": [
                "attack.t1543", "attack.t1195.002", "attack.persistence",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- H1 — gh-token-monitor persistence (DISARM FIRST) ---- #
        for art in store.iter_artifacts(collector="recent_files"):
            d = art["data"] or {}
            entries = d.get("entries") or ([d] if d.get("path") else [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path") or ""
                base = _basename(path).lower()
                if base in {"gh-token-monitor.plist", "gh-token-monitor.service"}:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            "Shai-Hulud destruction primitive present: "
                            "gh-token-monitor — DISARM FIRST before "
                            "any token rotation"
                        ),
                        summary=(
                            f"Persistence file ``{path}`` matches the "
                            "Shai-Hulud / Mini Shai-Hulud gh-token-"
                            "monitor pattern. This service polls "
                            "GitHub every 60s for token revocation "
                            "and triggers ``rm -rf ~/`` when "
                            "revoked. The hardening_commands block "
                            "is a DISARM-FIRST sequence that kills "
                            "the process, unloads / disables the "
                            "service, and removes the file. Run it "
                            "before rotating any GitHub token."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "destruction_primitive_present",
                            "primitive": "gh-token-monitor",
                            "path": path,
                            "hardening_commands": _HARDEN_BLOCKS["disarm_first"],
                            "reversible": False,
                            # The persistence removal is *not* reversible
                            # by design — that's the whole point.
                        },
                        mitre="T1485",  # destructive payload (T1543 also)
                    )

        # ---- H2 — npm install-scripts hardening advisory ---- #
        # Trigger if ANY npm project artifact exists; the hardening
        # block sets ignore-scripts globally + per-project.
        npm_present = False
        for _ in store.iter_artifacts(collector="npm_packages"):
            npm_present = True
            break
        if npm_present:
            yield Finding(
                detector=self.name,
                severity="info",
                title=(
                    "npm install-scripts are the Shai-Hulud entry "
                    "point — hardening commands available"
                ),
                summary=(
                    "npm projects were observed on this host. Both "
                    "Shai-Hulud variants enter via the preinstall "
                    "lifecycle script in a malicious dependency. "
                    "Globally disabling lifecycle-script execution "
                    "(``npm config set ignore-scripts true``) neuters "
                    "this entry point. The hardening_commands block "
                    "applies it globally and to every detected "
                    "project's .npmrc. Reversible per-package via "
                    "``--ignore-scripts=false --foreground-scripts``."
                ),
                artifact_refs=[],
                evidence={
                    "kind": "npm_lifecycle_scripts_hardening",
                    "primitive": "npm preinstall/postinstall",
                    "hardening_commands": _HARDEN_BLOCKS["npm_ignore_scripts"],
                    "reversible": True,
                },
                mitre="T1195.002",
            )

        # ---- H3 — .claude / .vscode write-surface hardening ---- #
        # Trigger once per case if any artifact mentions either path.
        ide_emitted = False
        for art in store.iter_artifacts():
            if ide_emitted:
                break
            d = art.get("data") or {}
            try:
                import json as _json
                text = _json.dumps(d, default=str).lower()
            except Exception:
                continue
            if "/.claude/" in text or "/.vscode/" in text:
                ide_emitted = True
                yield Finding(
                    detector=self.name,
                    severity="info",
                    title=(
                        "IDE-config directories writable — Shai-Hulud "
                        "self-propagation surface hardening available"
                    ),
                    summary=(
                        "``.claude/`` or ``.vscode/`` directory "
                        "observed. Mini Shai-Hulud propagates by "
                        "committing poisoned configs into these "
                        "directories via GitHub GraphQL. Hardening: "
                        "make the directories immutable (chflags uchg "
                        "on macOS, chattr +i on Linux, icacls deny on "
                        "Windows). Reversible — unset the flag for "
                        "legitimate edits, then re-apply."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "ide_dirs_writable",
                        "primitive": ".claude / .vscode poisoning",
                        "hardening_commands": _HARDEN_BLOCKS["ide_dirs_immutable"],
                        "reversible": True,
                    },
                    mitre="T1195.002",
                )

        # ---- H4 — LaunchAgents / systemd-user write-surface ---- #
        # Always emit one hardening advisory per case — these
        # directories are the persistence-drop locations.
        yield Finding(
            detector=self.name,
            severity="info",
            title=(
                "User-persistence directories writable — hardening "
                "available"
            ),
            summary=(
                "~/Library/LaunchAgents (macOS) and ~/.config/systemd/"
                "user (Linux) are the canonical drop locations for "
                "the gh-token-monitor persistence used by Shai-Hulud "
                "and Mini Shai-Hulud. The hardening_commands block "
                "snapshots the legitimate state and chmod 500s the "
                "directories. Reversible — chmod 700 for legitimate "
                "installer use."
            ),
            artifact_refs=[],
            evidence={
                "kind": "persistence_dirs_writable",
                "primitive": "user-persistence drop",
                "hardening_commands": _HARDEN_BLOCKS["persistence_dirs_locked"],
                "reversible": True,
            },
            mitre="T1543",
        )

        # ---- H5 — privesc surface audit ---- #
        # Always emit once per case — privesc surface needs review.
        yield Finding(
            detector=self.name,
            severity="info",
            title=(
                "Privilege-escalation surface audit commands "
                "available"
            ),
            summary=(
                "A successful Shai-Hulud foothold tries to escalate "
                "from user to root via NOPASSWD sudoers, wheel/sudo "
                "group membership, file capabilities, or SUID "
                "binaries dropped into $HOME / /tmp / /opt. The "
                "hardening_commands block runs the audit — review "
                "the output, then prune NOPASSWD lines via "
                "``sudo visudo`` and remove unexpected SUID/caps. "
                "(Detection-only; commands here read, they do not "
                "modify.)"
            ),
            artifact_refs=[],
            evidence={
                "kind": "privesc_audit",
                "primitive": "NOPASSWD sudoers + caps + SUID-in-HOME",
                "hardening_commands": _HARDEN_BLOCKS["privesc_audit"],
                "reversible": True,  # the audit doesn't change anything
            },
            mitre="T1548",
        )

        # ---- H6 — hosts-file block of known C2 ---- #
        yield Finding(
            detector=self.name,
            severity="info",
            title=(
                "Hosts-file block for Shai-Hulud / TrapDoor / "
                "Nightmare-Eclipse C2 available"
            ),
            summary=(
                "Hardening_commands block appends a hosts-file block "
                "for the union of known C2 + exfil hosts across "
                "Shai-Hulud (webhook.site), Mini Shai-Hulud (git-"
                "tanstack.com, filev2 + seed1-3.getsession.org), "
                "TrapDoor (ddjidd564.github.io), and Nightmare-"
                "Eclipse (staybud.dpdns.org). Includes commented "
                "firewall snippets for nftables (Linux), pf (macOS), "
                "and netsh advfirewall (Windows). Reversible — edit "
                "/etc/hosts and remove the digger-block section."
            ),
            artifact_refs=[],
            evidence={
                "kind": "c2_hosts_block",
                "primitive": "outbound C2 to known worm infra",
                "hardening_commands": _HARDEN_BLOCKS["hosts_block"],
                "reversible": True,
            },
            mitre="T1071",
        )

        # ---- H7 — GitHub Actions / token least-privilege ---- #
        yield Finding(
            detector=self.name,
            severity="info",
            title=(
                "GitHub Actions / token least-privilege hardening "
                "available"
            ),
            summary=(
                "Both Shai-Hulud variants harvest GITHUB_TOKEN and "
                "use it for self-propagation. Setting default "
                "workflow permissions to read-only org-wide "
                "neuters the propagation primitive. The "
                "hardening_commands block uses the gh CLI to apply "
                "this per-repo + emits the manual web-UI steps for "
                "org-level + npm publish-token audit + OAuth app "
                "review."
            ),
            artifact_refs=[],
            evidence={
                "kind": "github_token_hardening",
                "primitive": "GITHUB_TOKEN write permissions",
                "hardening_commands": _HARDEN_BLOCKS["github_tokens"],
                "reversible": True,
            },
            mitre="T1098",
        )

        # ---- H8 — Session messenger client presence ---- #
        for art in store.iter_artifacts():
            d = art.get("data") or {}
            try:
                import json as _json
                text = _json.dumps(d, default=str).lower()
            except Exception:
                continue
            if ("/.config/session" in text or
                    "/application support/session" in text or
                    "/appdata/roaming/session" in text):
                yield Finding(
                    detector=self.name,
                    severity="low",
                    title=(
                        "Session messenger client install detected — "
                        "Mini Shai-Hulud uses Session for C2"
                    ),
                    summary=(
                        f"Artifact from collector {art.get('collector')} "
                        "references a Session messenger config "
                        "directory. Mini Shai-Hulud uses the Session "
                        "messenger network (seed1-3 + filev2.get"
                        "session.org) for decentralized C2. A "
                        "legitimate Session user knows this is "
                        "here; if you are not a Session user, "
                        "investigate. Removing the install:\n\n"
                        "  macOS: rm -rf ~/Library/Application\\ "
                        "Support/Session\n"
                        "  Linux: rm -rf ~/.config/Session\n"
                        "  Windows: rmdir /s /q "
                        "%APPDATA%\\Session"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "session_messenger_present",
                        "primitive": "Session network for stealth C2",
                        "collector": art.get("collector"),
                        "reversible": True,
                    },
                    mitre="T1071",
                )
                break
