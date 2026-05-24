"""Counter-exfiltration: detect data leaving the host.

Observational. The 11th detector in the Decepticon countermeasure
suite — defensive mirror of the "Exfiltration" phase. Mines process
command lines for the canonical patterns that move sensitive bytes
off the host.

Signals:

  X1  Archive-then-exfil pipes
      ``tar czf - <path> | curl -T - <url>``,
      ``zip -r - <path> | curl ...``, ``7z a -so | nc ...``.
      The pipe operator + archiver + network client is the unifying
      shape; we match it without trying to enumerate every variant.

  X2  Cloud-bucket exfil
      ``aws s3 cp``, ``gsutil cp``, ``gsutil rsync``, ``az storage
      blob upload``, ``azcopy copy``, ``rclone copy``, ``rclone sync``
      with non-empty source. We can't tell "our buckets" from "attacker
      buckets" — so we flag *all* outbound transfers and let the
      operator triage. Severity is medium for general transfers and
      high when the source path is a sensitive target (E6 below).

  X3  Web-service exfil (paste / file-drop / webhook)
      Outbound to paste-bin services (pastebin.com / hastebin.com /
      ix.io / 0x0.st / transfer.sh / file.io / anonfiles.com /
      bashupload.com), webhook hosts (hooks.slack.com / discord.com/
      api/webhooks / api.telegram.org/bot / webhook.site), GitHub gist
      creation (``gh gist create`` or POST to api.github.com/gists).
      Maps to T1567 family.

  X4  Protocol-tunneling tools
      Process names or cmdline references to ``dnscat2``, ``iodine``,
      ``dnsteal``, ``dns2tcp``, ``chisel``, ``ngrok``, ``frp``,
      ``stunnel``, ``cloudflared tunnel``, ``localtunnel``,
      ``serveo``. These are dual-use — devs run ngrok legitimately —
      so severity is high (not critical), with a self-attribution
      hint when run from a user's own bin.

  X5  Sensitive-target read-and-POST oneliners
      ``base64 ~/.ssh/id_rsa | curl ...``, ``cat /etc/shadow | nc
      ...``, ``curl -F file=@/etc/passwd``, PowerShell
      ``Invoke-WebRequest -Method POST -InFile``. The discriminator
      is "sensitive path in the same cmdline as a network upload
      primitive". Fires critical.

  X6  DNS-tunneling cmdline shape
      Very long base32/hex labels with many ``.`` separators in a
      single cmdline argument suggests an exfil channel. We bound
      this conservatively to avoid false positives on legitimate
      long FQDNs.

MITRE: T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over
Alternative Protocol), T1567 (Exfiltration Over Web Service),
T1567.001 (Code Repository), T1567.002 (Cloud Storage), T1572
(Protocol Tunneling).
"""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- X1 — archive-then-exfil pipe ---- #
_ARCHIVE_THEN_EXFIL = re.compile(
    r"(?:\b(?:tar|zip|gzip|bzip2|xz|7z|7za|7zz)\b[^|]*\|"  # archiver then pipe
    r"[^|]*\b(?:curl|wget|nc|ncat|socat|http|httpie)\b)",
    re.I,
)

# ---- X2 — cloud-bucket exfil clients ---- #
_CLOUD_EXFIL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\baws\s+s3\s+(?:cp|sync|mv)\s+\S+", re.I),
     "aws s3 cp/sync/mv to bucket",
     "T1567.002"),
    (re.compile(r"\bgsutil\s+(?:cp|rsync|mv)\s+\S+", re.I),
     "gsutil cp/rsync/mv to GCS bucket",
     "T1567.002"),
    (re.compile(r"\baz\s+storage\s+blob\s+(?:upload|copy)\b", re.I),
     "az storage blob upload to Azure",
     "T1567.002"),
    (re.compile(r"\bazcopy\s+(?:copy|cp|sync)\b", re.I),
     "azcopy to Azure storage",
     "T1567.002"),
    (re.compile(r"\brclone\s+(?:copy|sync|move|copyto)\s+\S+", re.I),
     "rclone copy/sync to remote",
     "T1567.002"),
    (re.compile(r"\bb2\s+(?:upload-file|upload_file)\b", re.I),
     "Backblaze b2 upload",
     "T1567.002"),
    (re.compile(r"\bmc\s+(?:cp|mirror)\s+\S+", re.I),
     "MinIO mc cp/mirror",
     "T1567.002"),
]

# ---- X3 — paste / file-drop / webhook domains ---- #
_WEB_EXFIL_DOMAINS = [
    # Paste-bins / anonymous file drops
    ("pastebin.com",     "pastebin.com",     "paste-bin"),
    ("hastebin.com",     "hastebin.com",     "paste-bin"),
    ("ghostbin.com",     "ghostbin.com",     "paste-bin"),
    ("ix.io",            "ix.io",            "paste-bin"),
    ("0x0.st",           "0x0.st",           "anonymous file-drop"),
    ("transfer.sh",      "transfer.sh",      "anonymous file-drop"),
    ("file.io",          "file.io",          "anonymous file-drop"),
    ("anonfiles.com",    "anonfiles.com",    "anonymous file-drop"),
    ("bashupload.com",   "bashupload.com",   "anonymous file-drop"),
    ("oshi.at",          "oshi.at",          "anonymous file-drop"),
    ("uguu.se",          "uguu.se",          "anonymous file-drop"),
    ("filebin.net",      "filebin.net",      "anonymous file-drop"),
    ("catbox.moe",       "catbox.moe",       "anonymous file-drop"),
    # Webhooks
    ("hooks.slack.com",          "hooks.slack.com",          "Slack webhook"),
    ("discord.com/api/webhooks", "discord.com/api/webhooks", "Discord webhook"),
    ("discordapp.com/api/webhooks", "discordapp.com/api/webhooks",
     "Discord webhook"),
    ("api.telegram.org/bot",     "api.telegram.org/bot",     "Telegram bot"),
    ("webhook.site",             "webhook.site",             "webhook capture"),
    ("requestbin.com",           "requestbin.com",           "webhook capture"),
    ("ngrok-free.app",           "ngrok-free.app",           "ngrok tunnel"),
    # Code-repo gist exfil (T1567.001)
    ("api.github.com/gists",     "api.github.com/gists",     "GitHub gist API"),
    ("gist.githubusercontent.com", "gist.githubusercontent.com",
     "GitHub gist raw"),
]

# ---- X4 — protocol-tunneling tools ---- #
_TUNNEL_TOOLS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"\bdnscat2?\b", re.I),
     "dnscat2 — DNS C2 tunnel", "high", "T1572"),
    (re.compile(r"\biodine(?:d)?\b", re.I),
     "iodine — DNS-over-IP tunnel", "high", "T1572"),
    (re.compile(r"\bdns2tcp(?:c|d)?\b", re.I),
     "dns2tcp — DNS tunnel", "high", "T1572"),
    (re.compile(r"\bdnsteal\b", re.I),
     "dnsteal — exfil via DNS queries", "critical", "T1041"),
    (re.compile(r"\bchisel\b\s+(?:client|server)?", re.I),
     "chisel — HTTP-tunneled TCP/UDP", "high", "T1572"),
    (re.compile(r"\bngrok\s+(?:http|tcp|tls|start)\b", re.I),
     "ngrok — inbound tunnel", "high", "T1572"),
    (re.compile(r"\bfrpc?\b\s+(?:-c|run)", re.I),
     "frp — fast reverse-proxy tunnel", "high", "T1572"),
    (re.compile(r"\bcloudflared\s+tunnel\b", re.I),
     "cloudflared tunnel", "high", "T1572"),
    (re.compile(r"\blt\s+--port\b|\blocaltunnel\b", re.I),
     "localtunnel", "high", "T1572"),
    (re.compile(r"\bssh\b[^|]*\s+(?:-R|-D|-L)\s*\d+:", re.I),
     "ssh -R/-D/-L port-forward",
     "medium", "T1572"),
    (re.compile(r"\bstunnel(?:4)?\b\s+\S+\.conf", re.I),
     "stunnel — TLS-wrapped tunnel", "medium", "T1572"),
    (re.compile(r"\bsocat\b\s+TCP[46]?-LISTEN", re.I),
     "socat TCP-LISTEN listener (potential tunnel endpoint)",
     "medium", "T1572"),
    (re.compile(r"\bserveo\.net\b|\bssh\b\s+\S+@serveo\.net\b", re.I),
     "serveo.net SSH tunnel", "high", "T1572"),
]

# ---- X5 — sensitive-path → network-upload primitive ---- #
_SENSITIVE_PATHS = re.compile(
    r"(?:"
    r"/etc/(?:shadow|passwd|sudoers|krb5\.keytab)|"
    r"~?/\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)|"
    r"~?/\.aws/credentials|~?/\.aws/config|"
    r"~?/\.azure/[^ ]*\.json|"
    r"~?/\.gcp/[^ ]*\.json|~?/\.config/gcloud/|"
    r"~?/\.kube/config|/etc/kubernetes/admin\.conf|"
    r"~?/\.docker/config\.json|"
    r"~?/\.npmrc|~?/\.pypirc|~?/\.netrc|"
    r"~?/\.gnupg/|/etc/shadow-|"
    r"/var/lib/sss/secrets/|"
    r"~?/\.config/git/credentials|"
    r"~?/\.subversion/auth/|"
    r"/Library/Keychains/|~?/Library/Keychains/|"
    r"/Users/[^/]+/Library/Application\\?\s?Support/Google/Chrome/Default/Login\s*Data|"
    r"~?/\.mozilla/firefox/[^/]+/(?:logins\.json|key4\.db|cookies\.sqlite)"
    r")",
    re.I,
)
_NET_UPLOAD_PRIMITIVE = re.compile(
    r"(?:"
    r"\bcurl\b[^|]*\s(?:-T|--upload-file|-F|--form|-d|--data(?:-binary|-raw)?|"
    r"-X\s*POST|-X\s*PUT)\b|"
    r"\bwget\b[^|]*\s(?:--post-file|--post-data|--body-file|--body-data)\b|"
    r"\bnc\b\s|\bncat\b\s|\bsocat\b\s|\bhttp\b\s|\bhttpie\b\s|"
    r"Invoke-WebRequest\s+[^|]*-Method\s+(?:POST|PUT)|"
    r"Invoke-RestMethod\s+[^|]*-Method\s+(?:POST|PUT)|"
    r"\bbash\s+-c\b[^|]*>\s*/dev/tcp/"
    r")",
    re.I,
)

# ---- X6 — DNS tunneling: very long base32/hex labels in a cmdline ---- #
# Conservative: require TWO adjacent labels each 40+ base32-only
# characters inside the same FQDN. Real FQDNs are bounded by RFC at 63
# chars/label, and English words don't run pure base32 — two adjacent
# 40+ base32 labels is dispositive of tunnel encoding. Case-sensitive
# on purpose: avoids matching ordinary lowercase words via re.I.
_DNS_TUNNEL_LABEL = re.compile(
    r"\b[A-Z2-7]{40,63}\.[A-Z2-7]{40,63}\b"
)


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


def _looks_like_self_clone(exe: str) -> bool:
    """Heuristic: dev users running ngrok / socat from their own bin
    rather than an attacker-dropped binary. Used to soften severity."""
    if not exe:
        return False
    e = exe.lower()
    for hint in (
        "/.cargo/", "/.local/", "/.npm/", "/.pyenv/", "/.rbenv/",
        "/.nodebrew/", "/.asdf/", "/homebrew/",
        "/opt/homebrew/", "/usr/local/bin/", "/snap/",
    ):
        if hint in e:
            return True
    return False


class ExfiltrationDetector(Detector):
    name = "exfiltration"
    description = (
        "Counter-exfiltration: archive-then-exfil pipes, cloud-bucket cp, "
        "paste-bin / webhook / gist uploads, DNS / chisel / ngrok / frp "
        "tunnels, sensitive-target read-and-POST patterns."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Exfiltration tradecraft: archive-pipe / cloud-bucket / paste-bin / tunnel",
            "id": "digger-exfiltration-template",
            "description": (
                "A process invokes any of the canonical exfiltration "
                "primitives: archive piped to a network client (tar | "
                "curl / zip | nc), cloud-bucket cp/sync (aws s3 / "
                "gsutil / azcopy / rclone), upload to paste-bin / "
                "anonymous file-drop / Slack-Discord-Telegram webhook "
                "/ GitHub gist, or process names matching DNS / TCP / "
                "HTTP tunneling tools (dnscat2 / iodine / chisel / "
                "ngrok / frp / cloudflared)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_archive_pipe_exfil": {
                    "CommandLine|re": (
                        r"(?:\b(?:tar|zip|7z|gzip|xz)\b[^|]*\|"
                        r"[^|]*\b(?:curl|wget|nc|ncat|socat)\b)"
                    ),
                },
                "selection_cloud_bucket": {
                    "CommandLine|re": (
                        r"(?:aws\s+s3\s+(?:cp|sync|mv)|"
                        r"gsutil\s+(?:cp|rsync|mv)|"
                        r"az\s+storage\s+blob\s+upload|"
                        r"azcopy\s+(?:copy|sync)|"
                        r"rclone\s+(?:copy|sync|move))\s+\S+"
                    ),
                },
                "selection_webservice": {
                    "CommandLine|contains": [
                        "pastebin.com", "hastebin.com", "ix.io", "0x0.st",
                        "transfer.sh", "file.io", "anonfiles.com",
                        "bashupload.com", "hooks.slack.com",
                        "discord.com/api/webhooks", "api.telegram.org/bot",
                        "webhook.site", "api.github.com/gists",
                    ],
                },
                "selection_tunnel_tool": {
                    "Image|endswith": [
                        "/dnscat2", "/iodine", "/dns2tcp", "/dnsteal",
                        "/chisel", "/ngrok", "/frp", "/frpc",
                        "/cloudflared", "/stunnel", "/stunnel4",
                    ],
                },
                "condition": "1 of selection_*",
            },
            "level": "high",
            "tags": [
                "attack.t1041",
                "attack.t1048",
                "attack.t1567",
                "attack.t1567.001",
                "attack.t1567.002",
                "attack.t1572",
                "attack.exfiltration",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        seen: set[tuple[int, str]] = set()
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            pid = d.get("pid")
            name = (d.get("name") or "").lower()
            exe = d.get("exe") or ""
            base = (_basename(exe) or name).lower()
            cmd = _cmdline_str(d.get("cmdline"))
            if not cmd:
                continue
            self_clone = _looks_like_self_clone(exe)

            # ---- X1 archive | net-client pipe ---- #
            if _ARCHIVE_THEN_EXFIL.search(cmd):
                key = (pid, "archive_pipe")
                if key not in seen:
                    seen.add(key)
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=(
                            f"Exfiltration pipe: archive | network client "
                            f"in pid {pid} ({base})"
                        ),
                        summary=(
                            f"Process {base} (pid {pid}) command line "
                            "matches the archive-then-exfil shape — a "
                            "compressor (tar / zip / 7z / gzip / xz) piped "
                            "into a network client (curl / wget / nc / "
                            "socat). Verify what was archived and where "
                            "it went. "
                            f"\n\nCmdline: {cmd[:300]}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "archive_pipe",
                            "pid": pid,
                            "name": base,
                            "username": d.get("username"),
                            "cmdline": cmd[:400],
                        },
                        mitre="T1041",
                    )

            # ---- X2 cloud-bucket exfil ---- #
            for rx, label, mitre in _CLOUD_EXFIL_PATTERNS:
                m = rx.search(cmd)
                if not m:
                    continue
                # Severity bump if a sensitive-path is the source.
                has_sensitive = _SENSITIVE_PATHS.search(cmd) is not None
                key = (pid, f"cloud:{label}")
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    detector=self.name,
                    severity="high" if has_sensitive else "medium",
                    title=(
                        f"Cloud-bucket exfil pattern: {label} in pid {pid}"
                    ),
                    summary=(
                        f"Process {base} (pid {pid}) invoked: {label}. "
                        + ("The source path contains a sensitive target "
                           "(credentials / keys / kubeconfig). " if has_sensitive
                           else "")
                        + "Cloud-bucket cp/sync is the textbook "
                        "exfiltration path on instances with cloud "
                        "metadata-server access. Verify the destination "
                        "bucket is one you own.\n\nCmdline: " + cmd[:300]
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "cloud_bucket_exfil",
                        "pid": pid,
                        "name": base,
                        "username": d.get("username"),
                        "pattern": label,
                        "sensitive_source": has_sensitive,
                        "cmdline": cmd[:400],
                    },
                    mitre=mitre,
                )
                break  # one cloud-bucket finding per process is enough

            # ---- X3 web-service exfil (paste / webhook / gist) ---- #
            cmd_low = cmd.lower()
            for needle, domain, kind_label in _WEB_EXFIL_DOMAINS:
                if needle.lower() not in cmd_low:
                    continue
                key = (pid, f"web:{domain}")
                if key in seen:
                    continue
                seen.add(key)
                # GitHub gist hits map to T1567.001 (code repo);
                # everything else is T1567 (web service).
                mitre = (
                    "T1567.001" if "github.com" in domain
                    else "T1567"
                )
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=(
                        f"Web-service exfil destination ({kind_label}) in "
                        f"pid {pid} ({base})"
                    ),
                    summary=(
                        f"Process {base} (pid {pid}) command line "
                        f"references ``{domain}`` ({kind_label}). "
                        "Paste-bins, anonymous file-drops, chat webhooks, "
                        "and gists are the textbook exfil destinations "
                        "because they bypass corporate proxy "
                        f"allow-lists.\n\nCmdline: {cmd[:300]}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "web_service_exfil",
                        "pid": pid,
                        "name": base,
                        "username": d.get("username"),
                        "domain": domain,
                        "destination_kind": kind_label,
                        "cmdline": cmd[:400],
                    },
                    mitre=mitre,
                )
                break

            # ---- X4 tunneling tools ---- #
            for rx, label, sev, mitre in _TUNNEL_TOOLS:
                if not rx.search(cmd):
                    continue
                # Soften from "high" to "medium" when the binary is in a
                # user-local install path — devs run ngrok / chisel /
                # cloudflared legitimately.
                if sev == "high" and self_clone:
                    sev = "medium"
                key = (pid, f"tunnel:{label}")
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=(
                        f"Protocol-tunneling tool: {label} in pid {pid} "
                        f"({base})"
                    ),
                    summary=(
                        f"Process {base} (pid {pid}) command line "
                        f"matches: {label}. Protocol tunnels bypass "
                        "egress controls and are a common exfiltration "
                        "channel. "
                        + ("Binary path looks like a user-local install "
                           "(developer ngrok / chisel use is normal); "
                           "severity downgraded. " if self_clone else "")
                        + f"\n\nCmdline: {cmd[:300]}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "protocol_tunnel",
                        "pid": pid,
                        "name": base,
                        "exe": exe,
                        "username": d.get("username"),
                        "pattern": label,
                        "self_clone_hint": self_clone,
                        "cmdline": cmd[:400],
                    },
                    mitre=mitre,
                )
                break

            # ---- X5 sensitive-target read-and-POST ---- #
            if _SENSITIVE_PATHS.search(cmd) and _NET_UPLOAD_PRIMITIVE.search(cmd):
                key = (pid, "sensitive_post")
                if key not in seen:
                    seen.add(key)
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=(
                            f"Sensitive-path exfil: read + network-POST in "
                            f"pid {pid} ({base})"
                        ),
                        summary=(
                            f"Process {base} (pid {pid}) command line "
                            "names a sensitive file (SSH key / AWS creds "
                            "/ kubeconfig / shadow / Keychain / browser "
                            "login DB) AND a network-upload primitive "
                            "(curl -T/-F / -d, wget --post-file, nc, "
                            "Invoke-WebRequest -Method POST, bash > "
                            "/dev/tcp/). This is the dispositive shape "
                            "of credential exfiltration."
                            f"\n\nCmdline: {cmd[:300]}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "sensitive_post",
                            "pid": pid,
                            "name": base,
                            "username": d.get("username"),
                            "cmdline": cmd[:400],
                        },
                        mitre="T1041",
                    )

            # ---- X6 DNS-tunnel anomalous-label shape ---- #
            if _DNS_TUNNEL_LABEL.search(cmd):
                key = (pid, "dns_tunnel_shape")
                if key not in seen:
                    seen.add(key)
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=(
                            f"DNS-tunnel-shaped label in cmdline (pid {pid}, "
                            f"{base})"
                        ),
                        summary=(
                            f"Process {base} (pid {pid}) command line "
                            "contains a domain with very long base32/hex "
                            "labels (40+ chars per label, multiple labels) "
                            "— consistent with DNS-tunnel exfiltration "
                            "encoding."
                            f"\n\nCmdline: {cmd[:300]}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "dns_tunnel_shape",
                            "pid": pid,
                            "name": base,
                            "username": d.get("username"),
                            "cmdline": cmd[:400],
                        },
                        mitre="T1048.003",
                    )
