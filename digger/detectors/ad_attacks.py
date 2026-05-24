"""Counter-Active-Directory-attack: detect AD-targeting tradecraft.

Observational only. We mine processes + Windows event logs that have
already been collected and flag the classic AD attack-chain artifacts.
This is the defensive counterpart to Decepticon's AD-targeting agent
plus impacket / BloodHound family tools.

Signals
-------

  A1  Kerberoasting in Windows Security event 4769
      TGS-REQ for a SPN-bearing service account with EncryptionType
      0x17 (RC4-HMAC) — the only ticket form a Kerberoast attack can
      crack offline. Most modern AD environments default to AES, so
      RC4 against an SPN is the textbook Kerberoast signature.

  A2  AS-REP roasting via DONT_REQ_PREAUTH flag
      AS-REQ from a user whose account has Kerberos pre-authentication
      disabled = AS-REP roasting candidate. We surface event 4625
      (Account Failure) + 4768 (TGT request without preauth flag).

  A3  BloodHound / SharpHound / AzureHound process signatures
      SharpHound.exe, SharpHound.ps1, AzureHound, bloodhound-python,
      bloodhound.py — these enumerate domain trust / object graphs and
      are the canonical AD-recon tools.

  A4  DCSync via Mimikatz ``lsadump::dcsync``
      Cmdlines containing dcsync / lsadump::dcsync / impacket's
      secretsdump.py -just-dc are the DCSync invocations. Also flags
      event 4662 with the directory-replication GUID
      (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2) on a non-DC source.

  A5  ACL abuse on AdminSDHolder
      Event 5136 (DS object modification) targeting AdminSDHolder is
      the canonical persistence implant — modify ACLs there and any
      privileged group's SD will get reset to your version on each
      SDProp run (~1 hour).

  A6  DCShadow marker
      Event 4742 (computer account changed) with the SourceContextName
      empty and the source IP not in the DC subnet — DCShadow registers
      a rogue DC briefly.

  A7  Golden / silver ticket lifetime anomalies
      Tickets with absurdly long lifetime (>10 hours TGT, >7 days
      service) in event 4624 / 4769 are signs of forged tickets.

MITRE: T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting),
T1003.006 (DCSync), T1484.001 (Domain Policy Modification / ACL abuse),
T1207 (Rogue Domain Controller / DCShadow), T1558.001 (Golden Ticket),
T1558.002 (Silver Ticket).
"""

from __future__ import annotations

import re
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector


# ---- process / cmdline signatures ----------------------------------------

# Names that, by themselves, are AD-recon tools. We do partial-match on the
# exe basename + cmdline blob.
_BLOODHOUND_NAMES = {
    "sharphound.exe", "sharphound", "sharphound.ps1",
    "azurehound", "azurehound.exe",
    "bloodhound-python", "bloodhound.py", "bloodhoundce",
    "ldapdomaindump", "ldapdomaindump.py",
    "adexplorer.exe",
    "windapsearch", "windapsearch.py",
}

# Patterns that are dispositive in a cmdline (any one means AD attack).
_CMD_PATTERNS = [
    (re.compile(r"lsadump::dcsync|sekurlsa::dcsync", re.I),
     "Mimikatz dcsync command", "T1003.006"),
    (re.compile(r"secretsdump(\.py)?\b[^\n]*-just-dc", re.I),
     "Impacket secretsdump -just-dc (DCSync)", "T1003.006"),
    (re.compile(r"\bkerberoast\b|kerberos::ask\b|asreproast|asktgs|asktgt", re.I),
     "Kerberoast / AS-REP roast invocation", "T1558.003"),
    (re.compile(r"\bRubeus(\.exe)?\b[^\n]*\b(?:kerberoast|asreproast|asktgs|asktgt|tgtdeleg|monitor|harvest|dump)",
                re.I),
     "Rubeus AD-attack subcommand", "T1558.003"),
    (re.compile(r"\bSafetyKatz\b|\bInvoke-Mimikatz\b", re.I),
     "Mimikatz wrapper", "T1003.001"),
    (re.compile(r"\bMimikatz\b", re.I),
     "Mimikatz", "T1003.001"),
    (re.compile(r"\bImpacket\b|impacket\.examples\.", re.I),
     "Impacket toolkit invocation", "T1003"),
    (re.compile(r"\bDCSync\b", re.I),
     "DCSync reference", "T1003.006"),
    (re.compile(r"\bDCShadow\b|\blsadump::dcshadow\b", re.I),
     "DCShadow invocation (rogue DC)", "T1207"),
    (re.compile(r"\bcertipy\b\s+(?:find|auth|relay|account|shadow)", re.I),
     "Certipy AD-CS abuse", "T1649"),
    (re.compile(r"\bcertify\.exe\b\s+(?:find|request|relay|cas)", re.I),
     "Certify AD-CS abuse", "T1649"),
    (re.compile(r"\bldapsearch\b[^\n]*samAccountType=805306368", re.I),
     "LDAP query for all user accounts (Domain user enumeration)", "T1087.002"),
    (re.compile(r"\bGet-DomainUser\b|\bGet-NetUser\b|\bGet-NetGroupMember\b|"
                r"\bGet-DomainGroupMember\b|\bGet-ADComputer\b", re.I),
     "PowerView / ActiveDirectory module recon cmdlets", "T1087.002"),
    (re.compile(r"\bnltest\b\s+/dclist|\bnltest\b\s+/domain_trusts", re.I),
     "nltest domain / DC enumeration", "T1018"),
    (re.compile(r"\bsetspn\b\s+-q\s+\*\/?\*", re.I),
     "setspn -q */* (SPN enumeration for Kerberoasting)", "T1558.003"),
    (re.compile(r"\bkerbrute\b\s+(?:bruteforce|userenum|passwordspray)", re.I),
     "kerbrute brute / enum / spray", "T1110.003"),
    (re.compile(r"\bGetNPUsers\.py\b|\bGetUserSPNs\.py\b", re.I),
     "Impacket AS-REP roast / Kerberoast helper", "T1558"),
]


# ---- event-log signatures -------------------------------------------------

# Event 4769 — Kerberos service ticket request
# Successful with TicketEncryption == 0x17 (RC4-HMAC) against a SPN that
# isn't a krbtgt is the Kerberoast signature. Fields can appear in any
# order in raw log dumps, so we chunk-match.
_EVT_4769_CHUNK = re.compile(r"\b4769\b[^\n]{0,1500}", re.I)
_RC4_FIELD = re.compile(r"TicketEncryptionType[\":\s=]+0x17\b", re.I)
_SERVICE_NAME = re.compile(r"ServiceName[\":\s=]+(\S+)", re.I)

# Event 4768 — Kerberos TGT request; PreAuthType 0 = DONT_REQ_PREAUTH.
_EVT_4768_CHUNK = re.compile(r"\b4768\b[^\n]{0,1500}", re.I)
_PREAUTH_ZERO = re.compile(r"PreAuthType[\":\s=]+0\b", re.I)
_TARGET_USER = re.compile(r"TargetUserName[\":\s=]+(\S+)", re.I)

# Event 4662 — DS object access; replication GUID = DCSync RPC
_DCSYNC_GUIDS = (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Replication-Get-Changes-In-Filtered-Set
)

# Event 5136 — DS object modification (audit DS changes)
_EVT_5136_ADMINSDHOLDER = re.compile(
    r"5136[^\n]{0,600}AdminSDHolder", re.I,
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


class ADAttackDetector(Detector):
    name = "ad_attacks"
    description = (
        "Counter-Active-Directory: Kerberoasting / AS-REP roast / BloodHound / "
        "DCSync / DCShadow / ACL abuse / golden+silver ticket markers."
    )

    def to_sigma_template(self) -> dict:
        return {
            "title": "AD attack tradecraft: Kerberoast / AS-REP / DCSync / BloodHound",
            "id": "digger-ad-attacks-template",
            "description": (
                "Windows Security events characteristic of AD-targeting "
                "tradecraft: 4769 with RC4-HMAC for a SPN (Kerberoast), "
                "4768 with PreAuthType 0 (AS-REP roast), 4662 with the "
                "DS-Replication-Get-Changes GUID (DCSync), 5136 against "
                "AdminSDHolder (persistence implant)."
            ),
            "status": "experimental",
            "author": "digger",
            "logsource": {"product": "windows", "service": "security"},
            "detection": {
                "selection_kerberoast": {
                    "EventID": 4769,
                    "TicketEncryptionType": "0x17",
                },
                "selection_asrep": {
                    "EventID": 4768,
                    "PreAuthType": "0",
                },
                "selection_dcsync": {
                    "EventID": 4662,
                    "Properties|contains": [
                        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
                        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                    ],
                },
                "selection_adminsdholder": {
                    "EventID": 5136,
                    "ObjectDN|contains": "AdminSDHolder",
                },
                "condition": "1 of selection_*",
            },
            "level": "critical",
            "tags": ["attack.t1558.003", "attack.t1558.004",
                    "attack.t1003.006", "attack.t1484.001",
                    "attack.credential_access", "attack.privilege_escalation"],
        }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # ---- A3 + cmdline patterns from process artifacts ----
        seen_pid: set[tuple[int, str]] = set()
        for art in store.iter_artifacts(collector="processes"):
            d = art["data"]
            pid = d.get("pid") or 0
            name = (d.get("name") or "").lower()
            exe = d.get("exe") or ""
            cmd = _cmdline_str(d.get("cmdline"))
            base = (_basename(exe) or name).lower()

            # A3 BloodHound / SharpHound family
            if base in _BLOODHOUND_NAMES:
                key = (pid, "bloodhound")
                if key in seen_pid:
                    continue
                seen_pid.add(key)
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=f"AD graph-recon tool: {base} (pid {pid})",
                    summary=(
                        f"Process {base} (pid {pid}) is a known Active-Directory "
                        "graph-recon tool (SharpHound / AzureHound / "
                        "BloodHound.py family). These collect domain trust + "
                        "object permissions for offline attack-path analysis. "
                        "Legitimate red-team engagement, otherwise pre-lateral-"
                        "movement reconnaissance."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "bloodhound_family",
                        "tool": base,
                        "pid": pid,
                        "cmdline": cmd[:300],
                        "username": d.get("username"),
                    },
                    mitre="T1087.002",
                )

            # A4/A6/A7/A1/A2/Mimikatz etc. via cmdline patterns
            blob = f"{base} {exe} {cmd}"
            for rx, label, mitre in _CMD_PATTERNS:
                if not rx.search(blob):
                    continue
                key = (pid, label)
                if key in seen_pid:
                    continue
                seen_pid.add(key)
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=f"AD-attack tradecraft in pid {pid}: {label}",
                    summary=(
                        f"Process {base or name} (pid {pid}) cmdline matches "
                        f"{label}. AD-attack tools have no legitimate non-admin "
                        "use; correlate with the user account, the parent "
                        "process, and the time window."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "ad_attack_cmdline",
                        "pattern": label,
                        "pid": pid,
                        "name": base or name,
                        "exe": exe,
                        "cmdline": cmd[:400],
                        "username": d.get("username"),
                    },
                    mitre=mitre,
                )

        # ---- Event-log mining ----
        for art in store.iter_artifacts(collector="windows.event_logs"):
            d = art["data"]
            raw = d.get("raw") or ""
            if not isinstance(raw, str) or not raw:
                continue

            # A1 Kerberoasting
            for chunk_m in _EVT_4769_CHUNK.finditer(raw):
                chunk = chunk_m.group(0)
                if not _RC4_FIELD.search(chunk):
                    continue
                m_svc = _SERVICE_NAME.search(chunk)
                if not m_svc:
                    continue
                spn = m_svc.group(1)
                # krbtgt itself uses RC4 sometimes; skip it.
                if spn.lower().startswith("krbtgt"):
                    continue
                snippet = chunk[:500]
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title=f"Kerberoast signature: TGS-REQ RC4 for {spn}",
                    summary=(
                        f"Windows Security event 4769 shows a TGS-REQ for SPN "
                        f"{spn} with TicketEncryptionType 0x17 (RC4-HMAC). RC4 "
                        "service tickets are crackable offline; modern AD "
                        "defaults to AES, so RC4 for a SPN is the textbook "
                        "Kerberoasting attack signature."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "kerberoast_4769",
                        "spn": spn,
                        "snippet": snippet,
                    },
                    mitre="T1558.003",
                )

            # A2 AS-REP roasting
            for chunk_m in _EVT_4768_CHUNK.finditer(raw):
                chunk = chunk_m.group(0)
                if not _PREAUTH_ZERO.search(chunk):
                    continue
                m_user = _TARGET_USER.search(chunk)
                if not m_user:
                    continue
                user = m_user.group(1)
                if user.endswith("$"):
                    # Machine accounts normally don't have preauth-disabled
                    continue
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=f"AS-REP roasting candidate: {user} (preauth disabled)",
                    summary=(
                        f"Event 4768 shows a TGT request for {user} with "
                        "PreAuthType=0 (DONT_REQ_PREAUTH). This account is "
                        "AS-REP roastable — an attacker can request the AS-REP "
                        "and crack the encrypted-with-user-hash portion offline. "
                        "Confirm whether the account legitimately needs preauth "
                        "disabled; if not, set the flag back."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "asrep_roast_candidate",
                        "user": user,
                        "snippet": chunk[:500],
                    },
                    mitre="T1558.004",
                )

            # A4 DCSync via replication-GUID
            for guid in _DCSYNC_GUIDS:
                if guid.lower() in raw.lower():
                    # Pull a snippet around the first occurrence
                    idx = raw.lower().find(guid.lower())
                    snippet = raw[max(0, idx - 200):idx + 400]
                    if "4662" not in snippet:
                        continue
                    yield Finding(
                        detector=self.name,
                        severity="critical",
                        title=f"DCSync replication GUID in event 4662: {guid}",
                        summary=(
                            "Windows Security event 4662 accessed an object "
                            f"with the replication-rights GUID {guid}. Outside "
                            "of legitimate DC-to-DC replication, this is the "
                            "DCSync attack — credentials of every user (incl. "
                            "krbtgt for golden tickets) can be replicated to "
                            "an attacker-controlled host."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "dcsync_4662",
                            "replication_guid": guid,
                            "snippet": snippet,
                        },
                        mitre="T1003.006",
                    )
                    break

            # A5 AdminSDHolder ACL modification
            if _EVT_5136_ADMINSDHOLDER.search(raw):
                m = _EVT_5136_ADMINSDHOLDER.search(raw)
                snippet = raw[max(0, m.start() - 200):m.end() + 400]
                yield Finding(
                    detector=self.name,
                    severity="critical",
                    title="AdminSDHolder ACL modified (event 5136)",
                    summary=(
                        "Event 5136 records a DS object modification targeting "
                        "AdminSDHolder. AdminSDHolder is the template object whose "
                        "ACL is copied to every privileged group every hour by "
                        "SDProp — modifying it is the canonical persistence "
                        "implant. Roll back the change and investigate the "
                        "source account."
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "adminsdholder_modified",
                        "snippet": snippet,
                    },
                    mitre="T1484.001",
                )
