"""Programmatic ethical contract for digger.

This module is **load-bearing**, not decorative. Other modules in the
codebase call into the guardrails here before doing anything that
could violate the contract. Violations raise ``EthicsViolation``,
which is intentionally distinct from a programming bug — it means a
caller asked digger to do something that is out of scope by design.

The full contract is mirrored in ``ETHICS.md`` at the repo root and
in ``docs/ethics.html`` for human readers. This file is the
machine-enforceable version.

Core principles, by section:

  1. **Local host only.** digger inspects the host it runs on. Period.
     No port scanning of remote infrastructure. No vulnerability
     scanning across the network. No reconnaissance against
     third-party systems.
     → ``assert_target_is_localhost(host)``

  2. **Observation by default, action only on explicit user choice.**
     Findings describe what was observed; remediation commands are
     *printed* for the user to run themselves. No auto-remediation
     without an interactive confirmation. Anything that modifies host
     state goes through ``assert_user_consent_for_modification()``.

  3. **No exploitation.** We detect vulnerable versions; we do not
     actively exploit them to "confirm." Passive scanner only.
     → ``assert_not_exploitation(activity)``

  4. **No credential attacks.** No password cracking, no hash brute-
     force, no John-the-Ripper-style offensive credential work.
     Defensive checks (file permissions on credential stores, plaintext
     credentials in tracked files) are fine. Cracking is not.
     → ``assert_not_credential_attack(activity)``

  5. **No deception or surveillance of third parties.** No honeypot
     deployment, no man-in-the-middle, no monitoring of co-tenants on
     multi-user systems without explicit, recorded consent.
     → ``assert_no_third_party_surveillance(scope)``

  6. **No network egress without opt-in.** Air-gap mode is a first-
     class feature. Intel feeds, LLM triage, VirusTotal lookups,
     TAXII pushes: every outbound HTTP path is gated by an explicit
     user action.
     → see ``digger.opsec.airgap``

  7. **Calibrated findings.** False positives are bugs. Severity
     reflects evidence-backed risk, not theatrical urgency. The
     finding schema requires source/info reliability, estimative
     probability, analytic confidence — every emitted finding has to
     defend its severity grade.

  8. **No biometric or sensitive personal collection without consent.**
     No camera capture, no microphone, no keystroke logging. Browser
     history is collected because it's an investigation primitive,
     and the TLP/classification markings exist to keep it under
     control.

  9. **Refuse compromised configurations.** If asked to operate in a
     way that would harm a third party or bypass consent, refuse.
     → modules raise ``EthicsViolation`` rather than proceed.

 10. **Source-visible, audit-friendly.** Every finding traces back to
     artifacts, every artifact to a documented collector. No hidden
     behavior. Algorithm choices live in the docstrings of the
     modules that implement them.

A test in ``tests/test_ethics.py`` asserts that the principles
enumerated above are exposed via the public API so future refactors
don't quietly weaken them.
"""

from digger.ethics.contract import (
    EthicsViolation,
    PRINCIPLES,
    assert_target_is_localhost,
    assert_not_exploitation,
    assert_not_credential_attack,
    assert_no_third_party_surveillance,
    assert_user_consent_for_modification,
    confirm_remediation_intent,
    redact_dangerous_command,
)
from digger.ethics.engagement import (
    EngagementScope,
    from_local_defaults,
    record_scope,
    load_scope,
)

__all__ = [
    "EthicsViolation",
    "PRINCIPLES",
    "assert_target_is_localhost",
    "assert_not_exploitation",
    "assert_not_credential_attack",
    "assert_no_third_party_surveillance",
    "assert_user_consent_for_modification",
    "confirm_remediation_intent",
    "redact_dangerous_command",
    # engagement-scope (defensive RoE — inspired by responsible
    # offensive tooling like PurpleAILAB/Decepticon's RoE/OPPLAN model)
    "EngagementScope",
    "from_local_defaults",
    "record_scope",
    "load_scope",
]
