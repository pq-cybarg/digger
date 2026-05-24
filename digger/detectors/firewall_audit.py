"""Audit collected firewall artifacts and emit findings with remediation.

Reads artifacts produced by ``macos.firewall``, ``linux.firewall``, and
``windows.firewall`` collectors, runs them through the parsers + auditor
in :mod:`digger.firewall`, and emits one Finding per audit check that
trips. Remediation commands ride along on the Finding's ``evidence.remedy``
field; they are never executed by digger itself.
"""

from __future__ import annotations

from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector
from digger.firewall import FirewallBackend
from digger.firewall.audit import audit, audit_macos_appfw
from digger.firewall.parsers import (
    parse_firewalld, parse_iptables, parse_nftables, parse_pf,
    parse_ufw, parse_wfp,
)


class FirewallAuditDetector(Detector):
    name = "firewall_audit"
    description = "Audit pf / nftables / iptables / ufw / firewalld / WFP for unsafe defaults."

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # Collect per-backend artifacts. Multiple backends may be present.
        pf_info = ""
        pf_rules = ""
        nft = ""
        ipt_v4 = ""
        ufw = ""
        fwd = ""
        wfp_profiles = ""
        wfp_rules = ""
        appfw_global = ""
        appfw_stealth = ""
        appfw_block_all = ""

        for art in store.iter_artifacts(category="security_posture"):
            data = art["data"]
            subj = art["subject"]
            backend = data.get("backend") or ""
            raw = data.get("raw") or ""
            if subj == "pf-info":
                pf_info = raw
            elif subj == "pf-rules":
                pf_rules = raw
            elif subj == "nftables-ruleset":
                nft = raw
            elif subj in ("iptables-save",):
                ipt_v4 = raw
            elif subj == "ufw-status":
                ufw = raw
            elif subj == "firewalld-zones":
                fwd = raw
            elif subj == "appfw-state":
                appfw_global = data.get("global_state") or ""
                appfw_stealth = data.get("stealth_mode") or ""
                appfw_block_all = data.get("block_all") or ""
            elif subj == "profiles" and backend == "":  # windows
                wfp_profiles = raw
            elif subj == "rules" and backend == "":     # windows
                wfp_rules = raw

        # Run audits for whichever backends produced data.
        states: list = []
        if pf_rules or pf_info:
            states.append(parse_pf(pf_rules, pf_info))
        if nft:
            states.append(parse_nftables(nft))
        if ipt_v4:
            states.append(parse_iptables(ipt_v4))
        if ufw:
            states.append(parse_ufw(ufw))
        if fwd:
            states.append(parse_firewalld(fwd))
        if wfp_profiles or wfp_rules:
            states.append(parse_wfp(wfp_profiles, wfp_rules))

        backends_seen = {s.backend for s in states}
        if len(backends_seen) > 2:
            # Configuration-drift advisory: multiple backends configured
            yield Finding(
                detector=self.name,
                severity="medium",
                title=f"Multiple firewall backends configured: {sorted(b.value for b in backends_seen)}",
                summary=(
                    "More than two firewall backends produced rules on this host. "
                    "Rule precedence is non-obvious when, e.g., nftables and iptables "
                    "coexist. Consolidate on one backend to make audits tractable."
                ),
                artifact_refs=[],
                evidence={"backends": sorted(b.value for b in backends_seen)},
                mitre="T1562.004",
            )

        for state in states:
            for af in audit(state):
                yield Finding(
                    detector=self.name,
                    severity=af.severity,
                    title=af.title,
                    summary=af.summary,
                    artifact_refs=[],
                    evidence={
                        "check_id": af.check_id,
                        "backend": af.backend,
                        "affected_rules": af.affected,
                        "remedy": {
                            "description": af.remedy.description,
                            "rationale": af.remedy.rationale,
                            "requires_root": af.remedy.requires_root,
                            "backend": af.remedy.backend,
                            "commands": [
                                {"command": cmd, "destructive": dangerous}
                                for cmd, dangerous in af.remedy.annotated()
                            ],
                        },
                    },
                    mitre="T1562.004",
                )

        # macOS Application Firewall is independent of pf; audit it too.
        if appfw_global:
            for af in audit_macos_appfw(appfw_global, appfw_stealth, appfw_block_all):
                yield Finding(
                    detector=self.name,
                    severity=af.severity,
                    title=af.title,
                    summary=af.summary,
                    artifact_refs=[],
                    evidence={
                        "check_id": af.check_id,
                        "backend": af.backend,
                        "remedy": {
                            "description": af.remedy.description,
                            "rationale": af.remedy.rationale,
                            "backend": af.remedy.backend,
                            "commands": [
                                {"command": cmd, "destructive": dangerous}
                                for cmd, dangerous in af.remedy.annotated()
                            ],
                        },
                    },
                    mitre="T1562.004",
                )
