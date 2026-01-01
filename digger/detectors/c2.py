"""C2-framework signature detector.

Reads `digger/rules/c2/c2_signatures.yaml` and matches against:
  - browser history URLs
  - established network connections (remote address combined with live
    threat-intel feeds — ThreatFox / URLhaus / MalwareBazaar)
  - process command lines
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_intel, load_yaml
from digger.detectors.base import Detector


def _live_bad_indicators() -> dict[str, set[str]]:
    """Pull live IOCs from cached feeds. Returns dict by kind."""
    out = {"ipv4": set(), "domain": set(), "url": set(), "sha256": set(), "md5": set()}
    tf = load_intel("threatfox_recent") or {}
    for e in tf.get("entries", []) or []:
        ioc_type = (e.get("ioc_type") or "").lower()
        val = (e.get("ioc") or e.get("value") or "").lower()
        if not val:
            continue
        if "ip:port" in ioc_type or ioc_type == "ip":
            out["ipv4"].add(val.split(":")[0])
        elif "domain" in ioc_type:
            out["domain"].add(val)
        elif "url" in ioc_type:
            out["url"].add(val)
        elif "sha256" in ioc_type:
            out["sha256"].add(val)
        elif "md5" in ioc_type:
            out["md5"].add(val)
    urlhaus = load_intel("urlhaus_recent") or {}
    for e in urlhaus.get("entries", []) or []:
        u = (e.get("url") or "").lower()
        if u:
            out["url"].add(u)
    mb = load_intel("malwarebazaar_recent") or {}
    for e in mb.get("entries", []) or []:
        if e.get("sha256"):
            out["sha256"].add(e["sha256"].lower())
        if e.get("md5"):
            out["md5"].add(e["md5"].lower())
    return out


_MICROSOFT_AS_HINT = (
    "13.107.", "20.", "40.", "52.", "104.", "131.107.",   # azure / o365 ranges
    "131.253.", "157.55.", "204.79.", "207.46.",
)


def _looks_like_microsoft(ip: str) -> bool:
    """Coarse Microsoft-CDN heuristic: avoid false-positives on legitimate
    svchost talking to Azure/O365. Not authoritative; just a noise reducer."""
    return any(ip.startswith(p) for p in _MICROSOFT_AS_HINT)


class C2Detector(Detector):
    name = "c2"
    description = "C2 framework signatures (Cobalt Strike, Sliver, Mythic, Brute Ratel, Havoc, Nighthawk, Merlin, Covenant, Empire, Metasploit, RAT families) + named-pipe / TLS-fingerprint / injection-landing-pad signals."

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        rules = load_yaml("c2/c2_signatures.yaml") or {}
        frameworks = rules.get("frameworks", [])
        live = _live_bad_indicators()

        # Signature matches against processes (cmdline + named-pipes + open files)
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"]
            cmd = " ".join(d.get("cmdline") or [])
            open_files = d.get("open_files") or []
            # Treat any \\.\pipe\... reference (in cmdline or open_files) as
            # a single searchable blob for the pipe_patterns matchers.
            pipe_blob = cmd + "\n" + "\n".join(str(p) for p in open_files)
            files_blob = "\n".join(str(p) for p in open_files)

            for fw in frameworks:
                # proc_patterns vs cmdline
                fired_proc = False
                for pat in fw.get("proc_patterns", []):
                    if re.search(pat, cmd, re.I):
                        yield Finding(
                            detector=self.name,
                            severity=fw.get("severity", "high"),
                            title=f"{fw['name']} proc signature: pid {d.get('pid')}",
                            summary=(
                                f"Process command line for {d.get('name')} matches "
                                f"{fw['name']} signature pattern `{pat}`. Cmdline: {cmd[:300]}"
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={"framework": fw["name"], "pattern": pat, "cmdline": cmd[:400],
                                      "kind": "proc_pattern"},
                            mitre="T1071.001",
                        )
                        fired_proc = True
                        break
                # pipe_patterns vs cmdline+open_files
                if not fired_proc:
                    for pat in fw.get("pipe_patterns", []):
                        if re.search(pat, pipe_blob, re.I):
                            yield Finding(
                                detector=self.name,
                                severity=fw.get("severity", "high"),
                                title=f"{fw['name']} named-pipe signature: pid {d.get('pid')}",
                                summary=(
                                    f"Process {d.get('name')} references a named pipe "
                                    f"matching {fw['name']} pattern `{pat}`. Named pipes "
                                    "are a common C2 inter-process channel; default-config "
                                    "beacons use predictable pipe names."
                                ),
                                artifact_refs=[art["artifact_uuid"]],
                                evidence={"framework": fw["name"], "pattern": pat,
                                          "kind": "pipe_pattern"},
                                mitre="T1071.001",
                            )
                            break
                # file_patterns vs open_files
                for pat in fw.get("file_patterns", []):
                    if re.search(pat, files_blob, re.I):
                        yield Finding(
                            detector=self.name,
                            severity=fw.get("severity", "high"),
                            title=f"{fw['name']} file path signature: pid {d.get('pid')}",
                            summary=(
                                f"Process {d.get('name')} has an open file path matching "
                                f"{fw['name']} pattern `{pat}`."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={"framework": fw["name"], "pattern": pat,
                                      "kind": "file_pattern"},
                            mitre="T1071.001",
                        )
                        break

            # ---- Process-injection landing-pad heuristic ----
            # If this is a Windows host process commonly chosen as an
            # injection target, AND it has an outbound connection to a
            # non-Microsoft address, that's a strong "beacon in a borrowed
            # body" signal.
            pname = (d.get("name") or "").lower()
            injection_targets = set()
            for fw in frameworks:
                injection_targets.update(
                    (n or "").lower() for n in (fw.get("injection_target_names") or [])
                )
            if pname in injection_targets:
                for conn in (d.get("connections") or []):
                    raddr = conn.get("raddr")
                    if not raddr or not isinstance(raddr, (list, tuple)):
                        continue
                    rip = raddr[0] if raddr else None
                    if not rip:
                        continue
                    if (conn.get("status") or "") != "ESTABLISHED":
                        continue
                    # Skip loopback + Microsoft-ish destinations
                    if rip.startswith("127.") or rip.startswith("::1") or _looks_like_microsoft(rip):
                        continue
                    yield Finding(
                        detector=self.name,
                        severity="high",
                        title=f"Injection landing pad: {pname} (pid {d.get('pid')}) talking to {rip}",
                        summary=(
                            f"Windows host process {pname} is commonly used as an "
                            "injection target by C2 frameworks. It has an established "
                            f"outbound connection to {rip}, which is not in a recognized "
                            "Microsoft / O365 range. Combined with any memory_anomaly "
                            "RWX / anonymous-exec finding on the same pid, this is the "
                            "canonical beacon-injection signature."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "injection_landing_pad",
                            "process": pname,
                            "pid": d.get("pid"),
                            "remote_ip": rip,
                            "remote_port": raddr[1] if len(raddr) > 1 else None,
                        },
                        mitre="T1055",
                    )
                    break  # one beacon per process is enough

        for art in store.iter_artifacts(collector="browsers"):
            for entry in art["data"].get("entries") or []:
                url = (entry.get("url") if isinstance(entry, dict) else None) or ""
                for fw in frameworks:
                    for pat in fw.get("uri_patterns", []):
                        if re.search(pat, url, re.I):
                            yield Finding(
                                detector=self.name,
                                severity=fw.get("severity", "high"),
                                title=f"{fw['name']} URI pattern in browser history",
                                summary=f"URL {url} matches {fw['name']} pattern `{pat}`.",
                                artifact_refs=[art["artifact_uuid"]],
                                evidence={"framework": fw["name"], "pattern": pat, "url": url},
                                mitre="T1071.001",
                            )

        # Live intel — match against established connections
        for art in store.iter_artifacts(collector="network"):
            raddr = art["data"].get("raddr")
            if raddr and len(raddr) >= 1:
                ip = raddr[0]
                if ip in live["ipv4"]:
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"Live ThreatFox IP match: {ip}",
                        summary=(
                            f"Established connection to {ip}:{raddr[1] if len(raddr)>1 else '?'} "
                            "matches live ThreatFox abuse-tracker indicator. Treat as confirmed "
                            "command-and-control infrastructure."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"ip": ip, "raddr": raddr},
                        mitre="T1071",
                    )

        # SHA-256 of running exes vs MalwareBazaar
        for art in store.iter_artifacts(collector="processes"):
            h = (art["data"].get("exe_sha256") or "").lower()
            if h and h in live["sha256"]:
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=f"MalwareBazaar SHA-256 match: pid {art['data'].get('pid')}",
                    summary=(
                        f"Running process executable hash {h} appears in MalwareBazaar — this "
                        "is a publicly known malware sample. Isolate the host."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={"sha256": h, "process": art["data"]},
                    mitre="T1204.002",
                )
