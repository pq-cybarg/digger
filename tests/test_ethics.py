"""Ethical contract — these are load-bearing tests.

A regression here means a guardrail got removed silently.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from digger.ethics import (
    EngagementScope, EthicsViolation, PRINCIPLES,
    assert_no_third_party_surveillance,
    assert_not_credential_attack,
    assert_not_exploitation,
    assert_target_is_localhost,
    confirm_remediation_intent,
    from_local_defaults,
    load_scope,
    record_scope,
    redact_dangerous_command,
)


# ---- principles registry ---- #


def test_canonical_principles_present():
    """If someone deletes a principle, this test breaks."""
    ids = {p.id for p in PRINCIPLES}
    required = {
        "P1.local-host-only",
        "P2.observation-default",
        "P3.no-exploitation",
        "P4.no-credential-attacks",
        "P5.no-third-party-surveillance",
        "P6.no-egress-without-opt-in",
        "P7.calibrated-findings",
    }
    missing = required - ids
    assert not missing, f"missing principles: {missing}"


# ---- P1: localhost only ---- #


def test_localhost_addresses_accepted():
    for addr in ("localhost", "127.0.0.1", "::1", None, ""):
        assert_target_is_localhost(addr, feature="test")  # must not raise


def test_remote_address_refused():
    with pytest.raises(EthicsViolation, match="local host"):
        assert_target_is_localhost("8.8.8.8", feature="test-portscan")


def test_remote_hostname_refused():
    with pytest.raises(EthicsViolation):
        assert_target_is_localhost("github.com", feature="test")


# ---- P3: no exploitation ---- #


def test_exploitation_intent_refused():
    for activity in [
        "use exploit/multi/handler",
        "deploy metasploit module against host",
        "msfvenom -p windows/shell_reverse_tcp",
        "run sqlmap against /api/users",
    ]:
        with pytest.raises(EthicsViolation, match="exploitation"):
            assert_not_exploitation(activity, feature="test")


def test_detection_phrasing_allowed():
    # These are legitimate defensive uses
    for activity in [
        "scan installed software for known CVEs",
        "identify running services and match versions",
        "compute SHA-256 of process executable",
    ]:
        assert_not_exploitation(activity, feature="test")  # must not raise


# ---- P4: no credential attacks ---- #


def test_credential_cracking_refused():
    for activity in [
        "run john the ripper against captured hashes",
        "use hashcat with rockyou.txt",
        "brute force password on smb share",
        "rainbow table attack on ntds.dit",
    ]:
        with pytest.raises(EthicsViolation, match="credential"):
            assert_not_credential_attack(activity, feature="test")


def test_defensive_credential_checks_allowed():
    for activity in [
        "check permissions on ~/.ssh/id_rsa",
        "detect plaintext credentials in env vars",
        "find AWS_SECRET_ACCESS_KEY in tracked files",
    ]:
        assert_not_credential_attack(activity, feature="test")


# ---- P5: no third-party surveillance ---- #


def test_other_users_scope_refused():
    with pytest.raises(EthicsViolation, match="P5"):
        assert_no_third_party_surveillance("all users on host")


def test_consent_marked_scope_allowed():
    assert_no_third_party_surveillance("consent: IR engagement for other user accounts per contract X")
    assert_no_third_party_surveillance("audit: root-level fleet scan authorized by ticket #1234")


# ---- P2: remediation gating ---- #


def test_destructive_commands_redacted():
    cmd = "sudo rm -rf /Library/PrivilegedHelperTools/foo"
    annotated, dangerous = redact_dangerous_command(cmd)
    assert dangerous
    assert "destructive" in annotated.lower()
    assert cmd in annotated  # original is preserved, just annotated


def test_non_interactive_remediation_refused():
    # Even safe commands refuse in non-interactive mode
    assert confirm_remediation_intent("ls -la", interactive=False) is False


# ---- engagement scope ---- #


def test_local_default_scope_validates():
    scope = from_local_defaults()
    assert scope.investigator_name
    assert socket.gethostname() in scope.target_hosts


def test_remote_target_in_scope_refused_without_flag():
    scope = EngagementScope(
        investigator_name="alice",
        target_hosts=["some-other-host.example.com"],
        cross_host_allowed=False,
    )
    with pytest.raises(EthicsViolation, match="cross_host_allowed"):
        scope.validate()


def test_remote_target_allowed_with_explicit_flag():
    scope = EngagementScope(
        investigator_name="alice",
        target_hosts=["some-other-host.example.com"],
        cross_host_allowed=True,
        deconfliction_notes=["aggregating signed bundles from fleet hosts"],
    )
    scope.validate()  # must not raise


def test_unknown_data_category_refused():
    scope = EngagementScope(
        investigator_name="alice",
        data_categories=["processes", "wiretap_neighbors"],
    )
    with pytest.raises(EthicsViolation, match="data categories"):
        scope.validate()


def test_scope_roundtrips_through_disk(tmp_path: Path):
    scope = from_local_defaults(
        investigator_name="analyst",
        legal_authority="self (own machine)",
        notes=["Testing memory anomaly investigation."],
    )
    record_scope(tmp_path, scope)
    again = load_scope(tmp_path)
    assert again is not None
    assert again.investigator_name == "analyst"
    assert again.legal_authority == "self (own machine)"


def test_missing_investigator_refused():
    scope = EngagementScope(investigator_name="")
    with pytest.raises(EthicsViolation, match="investigator_name"):
        scope.validate()


def test_insane_retention_refused():
    scope = EngagementScope(investigator_name="x", retention_days=5000)
    with pytest.raises(EthicsViolation, match="retention"):
        scope.validate()
