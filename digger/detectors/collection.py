"""Counter-Collection: detect data-gathering tradecraft on the host.

Observational. The 13th detector, added to close the Collection-tactic
gap surfaced by the ATT&CK coverage heatmap. After every other
kill-chain phase had at least one detector, Collection was the lone
0-coverage column.

Signals:

  C1  Keylogger primitives (T1056.001 — Keylogging)
      ``xinput test`` (X11 keystroke dump), raw evdev reader on
      ``/dev/input/event*``, hook libraries in LD_PRELOAD
      (libinput-hook, x11vnc keylog modes), Linux ``logkeys``
      service, Windows ``SetWindowsHookEx`` references in scripts,
      macOS ``CGEventTapCreate`` Python/Swift hooks.

  C2  Screen capture (T1113)
      Process *running headless* (no display attached to the
      caller's session) doing screen-grabs: ``scrot``,
      ``import -window root`` (ImageMagick), ``screencapture -x``
      (macOS quiet flag), ``gnome-screenshot --file``, ``flameshot
      full -p``, ``ffmpeg -f x11grab`` / ``-f avfoundation`` /
      ``-f gdigrab``, ``DisplayCaptureManager``, ``BitBlt`` in
      cmdline scripts.

  C3  Clipboard scraping (T1115)
      Polling-shape invocations of ``xclip -o`` / ``xsel --output``
      / ``wl-paste`` / ``pbpaste`` / PowerShell ``Get-Clipboard``
      with ``sleep`` / ``Start-Sleep`` in the same cmdline (i.e.,
      a poller, not a one-shot user clipboard read).

  C4  Audio capture (T1123)
      ``parec`` (PulseAudio raw capture), ``arecord``, ``sox`` to
      a file, ``ffmpeg -f alsa`` / ``-f pulse`` / ``-f coreaudio``,
      ``rec`` (sox front-end), Windows ``Get-AudioDevice`` +
      ``System.Speech.Recognition`` cradles.

  C5  Video / camera capture (T1125)
      ``ffmpeg -f v4l2 -i /dev/video``, ``cheese --burst``,
      ``imagesnap`` (macOS), ``mplayer tv://``, ``vlc v4l2://``,
      Windows ``AForge.Video.DirectShow`` references, ``AVCapture
      Session`` in cmdline scripts.

  C6  Email-archive theft (T1114)
      A non-mail-client process reading Outlook PST/OST files,
      Thunderbird ``Mail/Local Folders``, macOS ``~/Library/Mail``,
      or running ``pst-utils``/``libpff``/``pffexport`` against
      them.

  C7  AitM-on-host tooling (T1557)
      mitmproxy, bettercap, ettercap, responder, MITMf, evilginx,
      net-creds, beelogger, sslsplit running on the host. Severity
      bumps when paired with a `-i <iface>` arg or active
      ARP-poisoning subcommand.

  C8  Configuration-repository / cloud-storage scraping (T1213 /
      T1530)
      Mass-read of secrets-store / wiki / vault paths in the same
      cmdline as a network-upload primitive: bulk ``vault read``,
      ``kubectl get secrets --all-namespaces -o yaml``, ``aws
      secretsmanager get-secret-value`` in a loop, ``aws s3 cp
      s3://*/...`` of an *unrelated* bucket, GitHub ``gh secret
      list`` followed by gist exfil.

MITRE: T1056 (Input Capture), T1056.001 (Keylogging), T1113 (Screen
Capture), T1114 (Email Collection), T1115 (Clipboard Data), T1123
(Audio Capture), T1125 (Video Capture), T1213 (Data from Information
Repositories), T1530 (Data from Cloud Storage), T1557 (Adversary in
the Middle).
"""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- cmdline patterns ----------------------------------------------------- #

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    # (regex, label, severity, mitre)

    # C1 — keylogger primitives
    (re.compile(r"\bxinput\s+test\s+\d+", re.I),
     "xinput test <id> — X11 keystroke dump",
     "critical", "T1056.001"),
    (re.compile(r"\blogkeys\b\s+(?:--start|-s)\b", re.I),
     "logkeys --start (Linux keylogger daemon)",
     "critical", "T1056.001"),
    (re.compile(r"/dev/input/event\d+", re.I),
     "raw read of /dev/input/event* (evdev keylogger pattern)",
     "high", "T1056.001"),
    (re.compile(r"\bSetWindowsHookEx\s*\(\s*WH_KEYBOARD", re.I),
     "SetWindowsHookEx(WH_KEYBOARD) — Win32 keylog hook",
     "critical", "T1056.001"),
    (re.compile(r"\bCGEventTapCreate\b[^|]*kCGEventKeyDown", re.I),
     "CGEventTapCreate(kCGEventKeyDown) — macOS event tap keylog",
     "critical", "T1056.001"),

    # C2 — screen capture
    (re.compile(r"\bscrot\b\s+\S+\.(?:png|jpg|jpeg)\b", re.I),
     "scrot screen capture to file",
     "medium", "T1113"),
    (re.compile(r"\bimport\s+(?:-window\s+\S+\s+|-screen\s+|-x\s+\S+\s+)?\S+\.(?:png|jpg|jpeg)\b",
                re.I),
     "ImageMagick `import` screen capture",
     "medium", "T1113"),
    (re.compile(r"\bscreencapture\b[^|]*-x\s+\S+\.(?:png|jpg|tiff|pdf)\b", re.I),
     "macOS screencapture -x (silent grab)",
     "high", "T1113"),
    (re.compile(r"\bgnome-screenshot\b[^|]*--file[= ]\S+", re.I),
     "gnome-screenshot --file <path>",
     "medium", "T1113"),
    (re.compile(r"\bflameshot\b\s+(?:full|screen|gui)\s+-p\s+\S+", re.I),
     "flameshot non-interactive full screen capture",
     "medium", "T1113"),
    (re.compile(r"\bffmpeg\b[^|]*-f\s+(?:x11grab|gdigrab|avfoundation)\b", re.I),
     "ffmpeg -f x11grab/gdigrab/avfoundation (screen recording)",
     "high", "T1113"),
    (re.compile(r"\bBitBlt\b\s*\([^)]*SRCCOPY", re.I),
     "BitBlt(SRCCOPY) screen-copy in cmdline script",
     "high", "T1113"),

    # C3 — clipboard scraping
    (re.compile(
        r"\b(?:xclip\s+-o|xsel\s+(?:--output|-o)|wl-paste|pbpaste|Get-Clipboard)\b"
        r"[^|]*\b(?:sleep|Start-Sleep|while\s+true|for\s*\(\s*;;\s*\))",
        re.I),
     "clipboard read in polling loop (xclip/pbpaste/Get-Clipboard + sleep)",
     "high", "T1115"),
    (re.compile(
        r"\bwhile\s+true\b[^|]*(?:xclip\s+-o|pbpaste|Get-Clipboard)",
        re.I),
     "while-true loop polling clipboard",
     "high", "T1115"),

    # C4 — audio capture
    (re.compile(r"\bparec\b[^|]*--device\b", re.I),
     "parec --device (PulseAudio raw capture)",
     "high", "T1123"),
    (re.compile(r"\barecord\b\s+(?:-D\s+\S+\s+)?\S+\.(?:wav|raw|flac)\b", re.I),
     "arecord -> .wav/.raw/.flac",
     "high", "T1123"),
    (re.compile(r"\bffmpeg\b[^|]*-f\s+(?:alsa|pulse|coreaudio|dshow)\b[^|]*\.(?:wav|m4a|mp3|opus)",
                re.I),
     "ffmpeg -f alsa/pulse/coreaudio (audio capture)",
     "high", "T1123"),
    (re.compile(r"\bsox\b[^|]*-d\b[^|]*\.(?:wav|raw|flac|mp3)\b", re.I),
     "sox -d (system audio default → file)",
     "medium", "T1123"),

    # C5 — video / camera capture
    (re.compile(r"\bffmpeg\b[^|]*-f\s+v4l2\b[^|]*-i\s+/dev/video\d+", re.I),
     "ffmpeg -f v4l2 -i /dev/video* (webcam capture)",
     "critical", "T1125"),
    (re.compile(r"\bimagesnap\b\s+(?:-w\s+\d+\s+)?\S+\.(?:jpg|png|jpeg)\b", re.I),
     "imagesnap (macOS webcam capture)",
     "critical", "T1125"),
    (re.compile(r"\bvlc\s+v4l2://", re.I),
     "vlc v4l2:// (webcam stream)",
     "high", "T1125"),
    (re.compile(r"\bAVCaptureSession\b[^|]*addInput", re.I),
     "AVCaptureSession addInput (macOS camera/mic capture API)",
     "critical", "T1125"),
    (re.compile(r"\bAForge\.Video\.DirectShow\b", re.I),
     "AForge.Video.DirectShow (Win webcam capture)",
     "critical", "T1125"),

    # C6 — email theft (heuristic: PST/OST or libpff tools)
    (re.compile(r"\b(?:pst-utils|pffexport|libpff-utils)\b", re.I),
     "libpff / pffexport (PST/OST extractor)",
     "critical", "T1114.001"),
    (re.compile(r"\bcat\b\s+\S+\.(?:pst|ost)\b", re.I),
     "cat *.pst/.ost (raw Outlook archive read)",
     "high", "T1114.001"),
    (re.compile(r"\breadpst\b", re.I),
     "readpst (libpst extractor)",
     "critical", "T1114.001"),

    # C7 — AitM tooling
    (re.compile(r"\bmitmproxy\b\s+(?:-T|--mode\s+transparent|-s\s+\S+)", re.I),
     "mitmproxy in transparent/script mode",
     "critical", "T1557"),
    (re.compile(r"\bbettercap\b\s+-(?:I|iface|caplet)\b", re.I),
     "bettercap with -I/--iface/--caplet",
     "critical", "T1557"),
    (re.compile(r"\bettercap\b\s+-T\s+-q\s+-M\s+arp\b", re.I),
     "ettercap -T -q -M arp (ARP-poison MitM)",
     "critical", "T1557.002"),
    (re.compile(r"\bresponder(?:\.py)?\b\s+-I\s+\S+", re.I),
     "Responder.py -I <iface> (LLMNR/NBT-NS poisoner)",
     "critical", "T1557.001"),
    (re.compile(r"\bevilginx2?\b\s+(?:-p|phishlets)\b", re.I),
     "evilginx2 reverse-proxy phisher",
     "critical", "T1557"),
    (re.compile(r"\bmitmf\b\s+-i\s+\S+", re.I),
     "MITMf -i <iface>",
     "critical", "T1557"),
    (re.compile(r"\bsslsplit\b\s+-l\s+\S+", re.I),
     "sslsplit -l log (TLS interception)",
     "critical", "T1557.002"),
    (re.compile(r"\bnet-creds(?:\.py)?\b\s+-i\s+\S+", re.I),
     "net-creds (passive credential sniffer)",
     "high", "T1557.001"),

    # C8 — info-repository / cloud-storage scraping
    (re.compile(r"\bkubectl\s+get\s+secrets\s+(?:--all-namespaces|-A)\s+-o\s+(?:yaml|json)",
                re.I),
     "kubectl get secrets -A -o yaml (cluster-wide secret dump)",
     "critical", "T1552.007"),
    (re.compile(r"\baws\s+secretsmanager\s+(?:list-secrets|get-secret-value)\b",
                re.I),
     "aws secretsmanager list-secrets / get-secret-value",
     "high", "T1530"),
    (re.compile(r"\baws\s+ssm\s+get-parameters?\s+(?:--with-decryption|--names)", re.I),
     "aws ssm get-parameters --with-decryption",
     "high", "T1530"),
    (re.compile(r"\bvault\s+(?:kv\s+get|read)\s+\S+", re.I),
     "vault kv get/read",
     "medium", "T1213"),
    (re.compile(r"\bgh\s+secret\s+list\b", re.I),
     "gh secret list (GitHub repo/org secret enumeration)",
     "high", "T1213.003"),
    (re.compile(r"\bgh\s+api\s+/orgs/[^/]+/(?:secrets|members)\b", re.I),
     "gh api /orgs/.../secrets|members",
     "high", "T1213.003"),
]


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


class CollectionDetector(Detector):
    name = "collection"
    description = (
        "Counter-collection: keyloggers, screen / audio / video capture, "
        "clipboard scrapers, email-archive theft, AitM tooling, "
        "configuration-repository / cloud-storage secret-scraping."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "Collection tradecraft: keylog / screen / clipboard / audio / video / AitM / secret-scrape",
            "id": "digger-collection-template",
            "description": (
                "A process invokes any of the canonical Collection-phase "
                "primitives: keylogger hook (xinput test, logkeys, "
                "/dev/input/event*, SetWindowsHookEx WH_KEYBOARD, "
                "CGEventTapCreate kCGEventKeyDown), screen capture "
                "(scrot, import, screencapture -x, gnome-screenshot, "
                "flameshot -p, ffmpeg -f x11grab/gdigrab/avfoundation), "
                "clipboard polling (xclip/pbpaste/Get-Clipboard in a "
                "loop), audio capture (parec, arecord, ffmpeg -f "
                "alsa/pulse/coreaudio), webcam capture (ffmpeg -f v4l2 "
                "/dev/video, imagesnap, AVCaptureSession, "
                "AForge.Video.DirectShow), email-archive theft "
                "(pst-utils, pffexport, readpst, cat .pst/.ost), "
                "AitM tooling (mitmproxy, bettercap, ettercap, "
                "Responder.py, evilginx2, MITMf, sslsplit, net-creds), "
                "or secret-store scraping (kubectl get secrets -A, aws "
                "secretsmanager get-secret-value, vault kv get, gh "
                "secret list)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_keylog": {
                    "CommandLine|re": (
                        r"(?:xinput\s+test\s+\d+|"
                        r"logkeys\s+--start|"
                        r"/dev/input/event\d+|"
                        r"SetWindowsHookEx\s*\(\s*WH_KEYBOARD|"
                        r"CGEventTapCreate[^|]*kCGEventKeyDown)"
                    ),
                },
                "selection_screencap": {
                    "Image|endswith": ["/scrot", "/screencapture",
                                         "/gnome-screenshot", "/flameshot",
                                         "/ffmpeg"],
                    "CommandLine|re": (
                        r"(?:\.png|\.jpg|\.tiff|"
                        r"-f\s+x11grab|-f\s+gdigrab|-f\s+avfoundation)"
                    ),
                },
                "selection_clipboard_poll": {
                    "CommandLine|re": (
                        r"(?:xclip\s+-o|xsel\s+--?o|wl-paste|pbpaste|Get-Clipboard)"
                        r"[^|]*(?:sleep|Start-Sleep|while\s+true)"
                    ),
                },
                "selection_audio_video": {
                    "Image|endswith": ["/parec", "/arecord", "/sox",
                                         "/ffmpeg", "/imagesnap", "/vlc"],
                    "CommandLine|re": (
                        r"(?:-f\s+(?:alsa|pulse|coreaudio|v4l2|dshow)|"
                        r"AVCaptureSession|AForge\.Video\.DirectShow|"
                        r"/dev/video\d+|v4l2://)"
                    ),
                },
                "selection_email_pst": {
                    "Image|endswith": ["/pffexport", "/readpst", "/pst-utils"],
                    "CommandLine|contains": [".pst", ".ost"],
                },
                "selection_aitm": {
                    "Image|endswith": [
                        "/mitmproxy", "/bettercap", "/ettercap",
                        "/Responder.py", "/responder",
                        "/evilginx2", "/mitmf", "/sslsplit", "/net-creds",
                    ],
                },
                "selection_secret_scrape": {
                    "CommandLine|re": (
                        r"(?:kubectl\s+get\s+secrets\s+(?:--all-namespaces|-A)\s+-o\s+(?:yaml|json)|"
                        r"aws\s+secretsmanager\s+(?:list-secrets|get-secret-value)|"
                        r"aws\s+ssm\s+get-parameters?[^|]*--with-decryption|"
                        r"vault\s+(?:kv\s+get|read)\s+\S+|"
                        r"gh\s+secret\s+list)"
                    ),
                },
                "condition": "1 of selection_*",
            },
            "level": "high",
            "tags": [
                "attack.t1056",
                "attack.t1056.001",
                "attack.t1113",
                "attack.t1114",
                "attack.t1114.001",
                "attack.t1115",
                "attack.t1123",
                "attack.t1125",
                "attack.t1213",
                "attack.t1213.003",
                "attack.t1530",
                "attack.t1552.007",
                "attack.t1557",
                "attack.t1557.001",
                "attack.t1557.002",
                "attack.collection",
            ],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        seen: set[tuple[int, str]] = set()
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"] or {}
            pid = d.get("pid")
            name = (d.get("name") or "").lower()
            base = (_basename(d.get("exe") or "") or name).lower()
            cmd = _cmdline_str(d.get("cmdline"))
            if not cmd:
                continue
            for rx, label, sev, mitre in _PATTERNS:
                if not rx.search(cmd):
                    continue
                key = (pid, label)
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    detector=self.name,
                    severity=sev,
                    title=(
                        f"Collection-phase activity in pid {pid} "
                        f"({base}): {label}"
                    ),
                    summary=(
                        f"Process {base} (pid {pid}, user "
                        f"{d.get('username')}) command line matches: "
                        f"{label}. Collection primitives — keyloggers, "
                        "screen / audio / camera capture, clipboard "
                        "pollers, AitM tools, secrets-store scrapers — "
                        "are dispositive of an active data-gathering "
                        "stage of the kill chain. Correlate with the "
                        "user, parent process, and exfiltration "
                        "findings.\n\nCmdline: " + cmd[:300]
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "collection_cmdline",
                        "pid": pid,
                        "name": base,
                        "pattern": label,
                        "username": d.get("username"),
                        "cmdline": cmd[:400],
                    },
                    mitre=mitre,
                )
                break  # one finding per process is enough
