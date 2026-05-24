"""PII redaction / pseudonymization for shareable case copies.

Forensic cases collect a lot of identifying information by design:
usernames, hostnames, home-directory paths, IP addresses, MAC addresses,
email addresses, AWS account IDs, etc. When sharing a case externally
(to a vendor, ISAC, or partner CSIRT) you typically want most of that
identity stripped while preserving the *structural* truth — same
username appears in the same pseudonym across every artifact, the
relationship between two paths is preserved, the hash chain is valid
under the redacted content.

The redactor:
  1. Builds a consistent pseudonymization map: USER1, USER2, … ;
     HOST1; PRIV-IP1; EMAIL1; PATH1; etc.
  2. Walks every artifact's data dict, applies replacements in a
     value-preserving manner (strings → strings, lists → lists).
  3. Writes a fresh case directory with the redacted artifacts plus
     a regenerated hash chain.
  4. Saves the pseudonymization map separately so the original
     custodian can de-redact if needed.

What it does NOT do: redact embedded raw blobs (file contents, EVTX
payloads). Those are treated as opaque and dropped unless explicitly
allowed by policy.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from digger.core.evidence import Artifact, EvidenceStore, Finding


# ---- patterns ---- #

_PATTERNS = [
    # (name, regex, prefix used in the pseudonym)
    ("email",     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "EMAIL"),
    ("mac",       re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b"), "MAC"),
    # IPv4 / IPv6 are handled specially via ipaddress to distinguish
    # private vs global. Public IPs are usually intel-relevant and may
    # be kept; private IPs are identifying.
    ("ipv4",      re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "PRIV-IP"),
    ("ipv6",      re.compile(r"\b[0-9a-fA-F:]{2,}:[0-9a-fA-F:]+\b"), "IPV6"),
    # Home directories — capture the user component
    ("user_home_mac",   re.compile(r"/Users/([^/\s]+)"), "USER"),
    ("user_home_lin",   re.compile(r"/home/([^/\s]+)"),  "USER"),
    ("user_home_win",   re.compile(r"[Cc]:\\\\Users\\\\([^\\\s]+)"), "USER"),
    # AWS / GCP IDs
    ("aws_account",     re.compile(r"\b\d{12}\b"), "AWS-ACCT"),
    # Generic UUIDs (case IDs etc. that aren't part of artifact identity)
]


@dataclass
class RedactionPolicy:
    """How aggressive to be."""
    redact_emails: bool = True
    redact_macs: bool = True
    redact_private_ips: bool = True
    redact_public_ips: bool = False              # public IPs are often intel-relevant
    redact_usernames: bool = True
    redact_hostnames: bool = True
    redact_aws_account_ids: bool = True
    drop_raw_blobs: bool = True                  # drop fields named raw/contents/tail
    raw_blob_field_names: tuple[str, ...] = ("raw", "contents", "tail", "first_n", "lines")
    drop_env_values: bool = True                 # env values often have user PATH etc.
    salt: bytes = b""                            # randomize per case if needed
    pseudonym_format: str = "{prefix}{n:03d}"    # e.g. USER001


REDACTION_DEFAULT_POLICY = RedactionPolicy()


# ---- engine ---- #


@dataclass
class _Pseudonymizer:
    """Stable mapping from real values to pseudonyms across a case."""
    policy: RedactionPolicy
    map_by_kind: dict[str, dict[str, str]] = field(default_factory=dict)

    def _next(self, kind: str, prefix: str) -> str:
        kind_map = self.map_by_kind.setdefault(kind, {})
        n = len(kind_map) + 1
        return self.policy.pseudonym_format.format(prefix=prefix, n=n)

    def pseudonym(self, kind: str, prefix: str, real_value: str) -> str:
        kind_map = self.map_by_kind.setdefault(kind, {})
        if real_value in kind_map:
            return kind_map[real_value]
        ps = self._next(kind, prefix)
        kind_map[real_value] = ps
        return ps

    def all_mappings(self) -> dict[str, dict[str, str]]:
        return {k: dict(v) for k, v in self.map_by_kind.items()}


def _redact_string(s: str, policy: RedactionPolicy, ps: _Pseudonymizer) -> str:
    if not s:
        return s
    out = s

    if policy.redact_emails:
        def _e(m):
            return ps.pseudonym("email", "EMAIL", m.group(0))
        out = _PATTERNS[0][1].sub(_e, out)

    if policy.redact_macs:
        def _m(m):
            return ps.pseudonym("mac", "MAC", m.group(0))
        out = _PATTERNS[1][1].sub(_m, out)

    # IPv4 — distinguish private from global
    def _ip4(m):
        v = m.group(0)
        try:
            ip = ipaddress.IPv4Address(v)
        except ValueError:
            return v
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return v   # keep
        if ip.is_global:
            if policy.redact_public_ips:
                return ps.pseudonym("ipv4_pub", "PUB-IP", v)
            return v
        if policy.redact_private_ips:
            return ps.pseudonym("ipv4_priv", "PRIV-IP", v)
        return v
    out = _PATTERNS[2][1].sub(_ip4, out)

    if policy.redact_usernames:
        for name in ("user_home_mac", "user_home_lin", "user_home_win"):
            pat = next(p for n, p, _ in _PATTERNS if n == name)
            def _u(m):
                user = m.group(1)
                ps_name = ps.pseudonym("username", "USER", user)
                return m.group(0).replace(user, ps_name)
            out = pat.sub(_u, out)

    if policy.redact_aws_account_ids:
        def _a(m):
            return ps.pseudonym("aws_acct", "AWS-ACCT", m.group(0))
        out = _PATTERNS[5][1].sub(_a, out)

    return out


def _redact_value(v: Any, policy: RedactionPolicy, ps: _Pseudonymizer, key_path: tuple[str, ...] = ()) -> Any:
    if isinstance(v, str):
        return _redact_string(v, policy, ps)
    if isinstance(v, list):
        return [_redact_value(x, policy, ps, key_path) for x in v]
    if isinstance(v, dict):
        out = {}
        for k, sub in v.items():
            kl = k.lower() if isinstance(k, str) else k
            if policy.drop_raw_blobs and kl in policy.raw_blob_field_names:
                out[k] = "<redacted: raw blob dropped by policy>"
                continue
            if policy.drop_env_values and (
                "env" in (key_path[-1] if key_path else "")
                or kl == "values"
            ):
                # Keep keys, mask values
                if isinstance(sub, dict):
                    out[k] = {kk: "<redacted>" for kk in sub.keys()}
                    continue
            out[k] = _redact_value(sub, policy, ps, key_path + (k,))
        return out
    return v


def _redact_hostname(host: str, ps: _Pseudonymizer) -> str:
    if not host:
        return host
    return ps.pseudonym("hostname", "HOST", host)


def _redact_meta_host(host: dict, policy: RedactionPolicy, ps: _Pseudonymizer) -> dict:
    if not isinstance(host, dict):
        return host
    out = dict(host)
    if policy.redact_hostnames:
        for k in ("node", "fqdn"):
            if out.get(k):
                out[k] = _redact_hostname(out[k], ps)
    return out


def redact_case(
    case_dir: str | Path,
    out_dir: str | Path,
    policy: Optional[RedactionPolicy] = None,
) -> dict:
    """Produce a redacted copy of ``case_dir`` at ``out_dir``.

    Returns a result dict containing the pseudonymization map and counts.
    Writes:
      <out_dir>/evidence.db                  redacted case
      <out_dir>/redaction_map.json           reversible mapping (KEEP SECURE)
      <out_dir>/redaction_summary.json       counts + policy
    """
    policy = policy or REDACTION_DEFAULT_POLICY
    case_dir = Path(case_dir).expanduser().resolve()
    out_dir = Path(out_dir).expanduser().resolve()
    if out_dir == case_dir:
        raise ValueError("out_dir must differ from case_dir")
    out_dir.mkdir(parents=True, exist_ok=True)

    src = EvidenceStore(case_dir)
    dst = EvidenceStore(out_dir)
    ps = _Pseudonymizer(policy=policy)

    # 1. Copy + redact case_meta
    for key in ("case_id", "host", "classification", "tlp",
                "collection_started", "collection_finished",
                "ai_case_summary", "ai_triage_run"):
        val = src.get_meta(key)
        if val is None:
            continue
        if key == "host":
            val = _redact_meta_host(val, policy, ps)
        else:
            val = _redact_value(val, policy, ps, key_path=(key,))
        dst.set_meta(key, val)
    policy_dict = {
        "redact_emails":          policy.redact_emails,
        "redact_macs":            policy.redact_macs,
        "redact_private_ips":     policy.redact_private_ips,
        "redact_public_ips":      policy.redact_public_ips,
        "redact_usernames":       policy.redact_usernames,
        "redact_hostnames":       policy.redact_hostnames,
        "redact_aws_account_ids": policy.redact_aws_account_ids,
        "drop_raw_blobs":         policy.drop_raw_blobs,
        "drop_env_values":        policy.drop_env_values,
    }
    dst.set_meta("redacted", True)
    dst.set_meta("redaction_policy", policy_dict)

    # 2. Redact and re-insert artifacts (re-derives hash chain).
    n_arts = 0
    for art in src.iter_artifacts():
        new_subject = _redact_string(art["subject"], policy, ps)
        new_data    = _redact_value(art["data"], policy, ps, key_path=(art["collector"],))
        dst.add_artifact(Artifact(
            collector=art["collector"],
            category=art["category"],
            subject=new_subject,
            data=new_data,
            ts=art["ts"],
        ))
        n_arts += 1

    # 3. Redact and re-insert findings.
    n_fnd = 0
    for f in src.iter_findings():
        new_title    = _redact_string(f["title"],   policy, ps)
        new_summary  = _redact_string(f["summary"], policy, ps)
        new_evidence = _redact_value(f.get("evidence") or {}, policy, ps, key_path=("evidence",))
        dst.add_finding(Finding(
            detector=f["detector"],
            severity=f["severity"],
            title=new_title,
            summary=new_summary,
            artifact_refs=[],          # original UUIDs aren't meaningful in the new store
            evidence=new_evidence,
            mitre=f["mitre"],
        ))
        n_fnd += 1

    src.close()
    dst.close()

    # 4. Write the mapping + summary sidecars
    mapping = ps.all_mappings()
    (out_dir / "redaction_map.json").write_text(
        json.dumps(mapping, indent=2, default=str), encoding="utf-8"
    )
    summary = {
        "source_case":  str(case_dir),
        "out_dir":      str(out_dir),
        "artifacts_redacted": n_arts,
        "findings_redacted":  n_fnd,
        "counts_by_kind":     {k: len(v) for k, v in mapping.items()},
        "policy":             policy_dict,
    }
    (out_dir / "redaction_summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )
    return summary
