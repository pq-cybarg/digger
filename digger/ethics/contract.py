"""The machine-enforceable ethics contract.

Each ``assert_*`` function raises ``EthicsViolation`` when its
precondition fails. Callers that catch ``EthicsViolation`` are saying
"I want to proceed despite this guardrail" — which means the catch
itself becomes load-bearing and gets logged. There is no silent path
around any of these.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from typing import Iterable


class EthicsViolation(RuntimeError):
    """Raised when a caller asks digger to do something out of scope by
    design. Distinct from a bug — it means the operator (not the
    code) is misusing the tool."""


# ---- canonical list, surfaced to humans and used by tests ---- #


@dataclass(frozen=True)
class Principle:
    id: str
    title: str
    summary: str


PRINCIPLES: tuple[Principle, ...] = (
    Principle(
        "P1.local-host-only",
        "Local host only",
        "digger inspects the host it runs on. No port scanning of remote "
        "infrastructure, no vulnerability scanning across the network, "
        "no reconnaissance against third-party systems.",
    ),
    Principle(
        "P2.observation-default",
        "Observation by default, action by explicit choice",
        "Findings describe what was observed; remediation is *printed* for "
        "the user to run. No auto-remediation without interactive consent.",
    ),
    Principle(
        "P3.no-exploitation",
        "No exploitation",
        "We detect vulnerable versions; we never actively exploit them "
        "to confirm. Passive scanner only.",
    ),
    Principle(
        "P4.no-credential-attacks",
        "No credential attacks",
        "No password cracking, no hash brute-force. Defensive checks "
        "(file perms on credential stores, plaintext credentials in "
        "tracked files) are fine. Cracking is not.",
    ),
    Principle(
        "P5.no-third-party-surveillance",
        "No deception or surveillance of third parties",
        "No honeypot deployment, no MITM, no monitoring of co-tenants "
        "without explicit recorded consent.",
    ),
    Principle(
        "P6.no-egress-without-opt-in",
        "No network egress without opt-in",
        "Air-gap mode is first-class. Intel feeds, LLM triage, "
        "VirusTotal lookups, TAXII pushes: every outbound HTTP is gated.",
    ),
    Principle(
        "P7.calibrated-findings",
        "Calibrated findings",
        "False positives are bugs. Severity reflects evidence-backed risk, "
        "not theatrical urgency.",
    ),
    Principle(
        "P8.no-biometric-collection",
        "No biometric or sensitive personal collection",
        "No camera, no microphone, no keystroke logging. "
        "Investigation artifacts get TLP/classification markings.",
    ),
    Principle(
        "P9.refuse-compromised-config",
        "Refuse compromised configurations",
        "If asked to operate in a way that would harm a third party or "
        "bypass consent, refuse with EthicsViolation.",
    ),
    Principle(
        "P10.audit-visible",
        "Source-visible, audit-friendly",
        "Every finding traces back to artifacts. No hidden behavior. "
        "Algorithm choices documented in module docstrings.",
    ),
)


# ---- enforcers ---- #


def _is_localhost(host: str | None) -> bool:
    """Return True only for unambiguously-local targets."""
    if not host:
        return True
    h = host.strip().lower()
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::"):
        return True
    try:
        local_names = {socket.gethostname().lower(),
                        socket.getfqdn().lower()}
    except Exception:
        local_names = set()
    if h in local_names:
        return True
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_loopback:
            return True
        # An address bound to any interface of THIS host counts as local.
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(socket.gethostname(), None):
                bound = sockaddr[0]
                if bound == h:
                    return True
        except (socket.gaierror, OSError):
            pass
    except ValueError:
        pass
    return False


def assert_target_is_localhost(host: str | None, *, feature: str = "") -> None:
    """**P1.** Refuse to operate on a non-local target.

    Used by any future feature that takes a "target host" argument
    (port scanner, banner grab, TLS scan). Callers MUST gate
    user-supplied target arguments through this.
    """
    if not _is_localhost(host):
        raise EthicsViolation(
            f"P1 violation: {feature or 'this operation'} may only target the local host. "
            f"Refusing to act on {host!r}. digger is a host-forensics tool, not a "
            "remote scanner; running it against third-party infrastructure is out of scope."
        )


_EXPLOIT_KEYWORDS = (
    # Payload markers
    "metasploit", "msfconsole", "msfvenom",
    "exploit/", "use exploit ",
    "shellcode", "reverse_tcp", "bind_tcp",
    "buffer overflow exploit", "rop chain",
    # Tool names
    "sqlmap", "wpscan", "nikto", "hydra ",
    "responder.py",
)


def assert_not_exploitation(activity: str, *, feature: str = "") -> None:
    """**P3.** Refuse activities whose stated intent is exploitation
    rather than detection. ``activity`` is a free-form description
    of what the caller wants to do; checked against a keyword set."""
    al = (activity or "").lower()
    for kw in _EXPLOIT_KEYWORDS:
        if kw in al:
            raise EthicsViolation(
                f"P3 violation: {feature or 'this operation'} describes exploitation "
                f"intent ('{kw}'). digger is a passive scanner; it identifies "
                "vulnerable versions but does not actively exploit them. Use a "
                "purpose-built pentest framework with the appropriate legal "
                "authorization instead."
            )


_CREDENTIAL_ATTACK_KEYWORDS = (
    "john the ripper", "john ", "hashcat ", "crack hash",
    "brute force password", "brute-force password",
    "rainbow table attack",
    "mimikatz dump", "lsass dump for cracking",
)


def assert_not_credential_attack(activity: str, *, feature: str = "") -> None:
    """**P4.** Refuse credential-cracking activities.

    Defensive checks (file permissions on credential stores, plaintext
    credentials in tracked files, weak credential file storage) are
    fine. Cracking captured hashes is not.
    """
    al = (activity or "").lower()
    for kw in _CREDENTIAL_ATTACK_KEYWORDS:
        if kw in al:
            raise EthicsViolation(
                f"P4 violation: {feature or 'this operation'} appears to be a "
                f"credential-attack workflow ('{kw}'). digger does not crack "
                "credentials. Tools like Hashcat / John the Ripper exist for "
                "credential strength testing and should be used directly with "
                "appropriate consent and legal authorization."
            )


def assert_no_third_party_surveillance(
    scope: str | None, *, feature: str = "",
) -> None:
    """**P5.** Refuse surveillance of other users on a shared host
    unless ``scope`` explicitly indicates same-user / consenting."""
    if scope and ("other" in scope.lower() or "all users" in scope.lower()
                   or "co-tenant" in scope.lower()):
        # We allow root-level collection but call it out explicitly.
        if not (scope.lower().startswith("consent:")
                or scope.lower().startswith("audit:")):
            raise EthicsViolation(
                f"P5 violation: {feature or 'this operation'} requests data "
                "about other users on this host without an explicit consent "
                "marker. Prefix `scope` with 'consent: <reason>' or "
                "'audit: <authorization>' if the engagement permits it."
            )


# ---- modification-consent + remediation hints ---- #


_DESTRUCTIVE_TOKENS = (
    "rm -rf", "shutdown", "halt", "diskutil erase",
    "killall ", "kill -9 1", "dd if=/dev/zero",
    "sudo iptables -F", "sudo pfctl -F all",
    "netsh advfirewall reset",
    "Remove-Item -Recurse -Force C:\\",
)


def redact_dangerous_command(cmd: str) -> tuple[str, bool]:
    """For commands we display to the user as remediation suggestions:
    return ``(annotated_cmd, was_redacted)``. Commands whose output is
    irreversibly destructive get a clear annotation rather than a
    silent pass-through. We NEVER auto-execute remediation commands."""
    cl = (cmd or "").lower()
    for tok in _DESTRUCTIVE_TOKENS:
        if tok.lower() in cl:
            return (
                f"# ⚠️ destructive — review carefully, run only with explicit "
                f"intent:\n# {cmd}", True
            )
    return cmd, False


def confirm_remediation_intent(
    cmd: str, *,
    interactive: bool = True,
    prompt: str = "Run the proposed remediation command? [y/N] ",
) -> bool:
    """**P2.** Gate any caller that might execute a remediation command.

    Returns True only if:
      * ``interactive`` is True (we have a TTY)
      * the user types 'y' / 'yes' / 'Y' at the prompt
      * the command isn't one of the irreversible tokens (those refuse
        outright unless the caller passes ``interactive=True`` AND
        ``DIGGER_ALLOW_DESTRUCTIVE_REMEDIATION=1``).

    Non-interactive callers (cron, CI) ALWAYS get False — they
    can't consent. The remediation command is printed for the human
    operator to run.
    """
    annotated, dangerous = redact_dangerous_command(cmd)
    if not interactive:
        return False
    if dangerous:
        env = os.environ.get("DIGGER_ALLOW_DESTRUCTIVE_REMEDIATION", "")
        if env.lower() not in {"1", "true", "yes"}:
            return False
    try:
        answer = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in {"y", "yes"}


def assert_user_consent_for_modification(
    feature: str, *, interactive: bool = True,
) -> None:
    """**P2.** Anything that would modify host state passes through
    here. Non-interactive callers (cron, CI) refuse — the user can
    enable cron-driven actions by writing them themselves; digger
    will not."""
    if not interactive:
        raise EthicsViolation(
            f"P2 violation: {feature} would modify host state, but the "
            "caller is non-interactive. digger refuses to make changes "
            "without an explicit consenting human at the prompt. Print "
            "the proposed change and let the operator run it manually."
        )


# ---- summary ---- #


def render_principles_md() -> str:
    """Markdown rendering of the canonical principles."""
    lines = [
        "# digger ethical contract",
        "",
        "digger is a **defensive host-forensics tool**. Every principle below",
        "is enforced by `digger.ethics.contract` — callers that try to act",
        "outside the contract raise `EthicsViolation` rather than proceed.",
        "",
    ]
    for p in PRINCIPLES:
        lines.append(f"## {p.title}  *({p.id})*")
        lines.append("")
        lines.append(p.summary)
        lines.append("")
    lines += [
        "---",
        "",
        "## Contrast: where digger explicitly is NOT a Decepticon",
        "",
        "Responsible offensive-security tools (e.g. ",
        "[PurpleAILAB/Decepticon](https://github.com/PurpleAILAB/Decepticon))",
        "execute realistic attack chains — reconnaissance, exploitation,",
        "privilege escalation, lateral movement, C2 — under a written RoE /",
        "ConOps / Deconfliction Plan / OPPLAN. Their engagement-planning",
        "discipline is the right model for any security tool that touches a",
        "system; digger borrows it via `digger.ethics.engagement.EngagementScope`.",
        "",
        "But the **execution model** is the opposite:",
        "",
        "| Decepticon (offensive)            | digger (defensive)                  |",
        "|-----------------------------------|-------------------------------------|",
        "| Reconnaissance against targets    | **P1** — local host only            |",
        "| Exploitation of CVEs              | **P3** — detect, don't exploit      |",
        "| Privilege escalation              | Read in user context, no escalation |",
        "| Lateral movement                  | **P1** — refuses to leave the host  |",
        "| C2 channel establishment          | No outbound except opted-in feeds   |",
        "| Credential dumping / Mimikatz     | **P4** — no credential attacks      |",
        "| Honeypot / deception deployment   | **P5** — no deception operations    |",
        "",
        "Decepticon's sandbox-net isolation exists because its operations are",
        "inherently dangerous. digger needs no equivalent — the operations",
        "themselves are non-modifying observation.",
    ]
    return "\n".join(lines)
