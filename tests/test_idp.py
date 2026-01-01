"""Identity-provider ingester + IdpSecurityDetector tests."""

from __future__ import annotations

import json

import pytest

from digger.core.evidence import EvidenceStore
from digger.detectors.idp_security import (
    IMPOSSIBLE_TRAVEL_WINDOW_S,
    MFA_FATIGUE_MIN_DENIES,
    MFA_FATIGUE_WINDOW_S,
    SPRAY_MIN_FAILURES,
    SPRAY_WINDOW_S,
    IdpSecurityDetector,
    _idp_event_records,
)
from digger.idp import (
    IdpError,
    IdpEvent,
    IdpIngestSummary,
    ingest_file,
    parse_entra_event,
    parse_okta_event,
    parse_workspace_event,
)
from digger.idp.parser import (
    _normalize_entra_event_type,
    _normalize_okta_event_type,
    _normalize_workspace_event_type,
    _parse_iso,
)


# ---- timestamp parsing ---- #


def test_parse_iso_handles_microseconds():
    ts = _parse_iso("2026-05-25T12:00:00.123Z")
    assert ts is not None
    assert ts > 1.7e9 and ts < 2.0e9


def test_parse_iso_no_fractional():
    ts = _parse_iso("2026-05-25T12:00:00Z")
    assert ts is not None


def test_parse_iso_none_or_invalid():
    assert _parse_iso(None) is None
    assert _parse_iso("") is None
    assert _parse_iso("not a date") is None


# ---- okta parser ---- #


def _okta_event(et: str, actor: str = "alice@example.com",
                outcome: str = "SUCCESS",
                ip: str = "1.2.3.4", country: str = "US",
                city: str = "NYC", ts: str = "2026-05-25T12:00:00Z",
                target: str = "okta-org") -> dict:
    return {
        "eventType": et,
        "outcome": {"result": outcome},
        "actor": {"alternateId": actor, "displayName": actor},
        "client": {
            "ipAddress": ip,
            "geographicalContext": {"country": country, "city": city},
            "userAgent": {"rawUserAgent": "Mozilla/5.0"},
        },
        "published": ts,
        "displayMessage": f"event: {et}",
        "target": [{"alternateId": target, "type": "AppInstance"}],
        "uuid": "u-1",
    }


def test_parse_okta_event_basic_auth():
    ev = parse_okta_event(_okta_event("user.authentication.auth"))
    assert ev is not None
    assert ev.provider == "okta"
    assert ev.event_type == "auth"
    assert ev.outcome == "success"
    assert ev.actor == "alice@example.com"
    assert ev.country == "US"
    assert ev.target == "okta-org"
    assert ev.raw_event_type == "user.authentication.auth"


def test_parse_okta_event_mfa_denied():
    ev = parse_okta_event(_okta_event(
        "user.mfa.deny_push", outcome="FAILURE",
    ))
    assert ev is not None
    assert ev.event_type == "mfa_denied"


def test_parse_okta_event_oauth_grant():
    ev = parse_okta_event(_okta_event(
        "application.user_membership.add",
    ))
    assert ev is not None
    assert ev.event_type == "oauth_grant"


def test_parse_okta_event_admin_grant():
    ev = parse_okta_event(_okta_event(
        "user.account.privilege.grant",
    ))
    assert ev is not None
    assert ev.event_type == "admin_grant"


def test_parse_okta_event_federation_change():
    ev = parse_okta_event(_okta_event(
        "system.idp.federation.update",
    ))
    assert ev is not None
    assert ev.event_type == "federation_change"


def test_parse_okta_event_returns_none_for_missing_event_type():
    assert parse_okta_event({"actor": {"alternateId": "x"}}) is None


def test_parse_okta_event_returns_none_for_non_dict():
    assert parse_okta_event(None) is None
    assert parse_okta_event("string") is None


def test_normalize_okta_event_type_unknown_passes_through():
    assert _normalize_okta_event_type("user.lifecycle.UNKNOWN_X") == \
        "user.lifecycle.unknown_x"


# ---- entra parser ---- #


def _entra_event(op: str = "Sign-in activity",
                 upn: str = "alice@contoso.com",
                 ip: str = "5.6.7.8", country: str = "DE",
                 city: str = "Berlin",
                 ts: str = "2026-05-25T12:00:00Z",
                 outcome_success: bool = True) -> dict:
    return {
        "operationName": op,
        "userPrincipalName": upn,
        "ipAddress": ip,
        "location": {"countryOrRegion": country, "city": city},
        "createdDateTime": ts,
        "status": {"errorCode": 0 if outcome_success else 50126,
                   "additionalDetails": "ok"},
        "appDisplayName": "Outlook",
        "id": "e-1",
        "correlationId": "c-1",
        "userAgent": "Mozilla/5.0",
        "targetResources": [{"displayName": "Outlook",
                              "userPrincipalName": upn}],
    }


def test_parse_entra_event_basic():
    ev = parse_entra_event(_entra_event())
    assert ev is not None
    assert ev.provider == "entra"
    assert ev.event_type == "auth"
    assert ev.outcome == "success"
    assert ev.actor == "alice@contoso.com"
    assert ev.country == "DE"


def test_parse_entra_event_failure():
    ev = parse_entra_event(_entra_event(outcome_success=False))
    assert ev is not None
    assert ev.outcome == "failure"


def test_parse_entra_event_audit_log_uses_initiated_by():
    ev = parse_entra_event({
        "activityDisplayName": "Add member to role",
        "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com"}},
        "createdDateTime": "2026-05-25T12:00:00Z",
        "targetResources": [{"displayName": "Global Administrator"}],
    })
    assert ev is not None
    assert ev.event_type == "admin_grant"
    assert ev.actor == "admin@contoso.com"


def test_parse_entra_event_federation_change():
    ev = parse_entra_event({
        "operationName": "Add identity provider",
        "userPrincipalName": "admin@contoso.com",
        "createdDateTime": "2026-05-25T12:00:00Z",
        "status": {"errorCode": 0},
    })
    assert ev is not None
    assert ev.event_type == "federation_change"


def test_parse_entra_event_oauth_grant():
    ev = parse_entra_event({
        "operationName": "Consent to application",
        "userPrincipalName": "alice@contoso.com",
        "createdDateTime": "2026-05-25T12:00:00Z",
        "status": {"errorCode": 0},
    })
    assert ev is not None
    assert ev.event_type == "oauth_grant"


def test_parse_entra_event_returns_none_for_no_op_name():
    assert parse_entra_event({"userPrincipalName": "x"}) is None


def test_normalize_entra_event_type_password_reset():
    assert _normalize_entra_event_type("self-service password reset") == \
        "password_reset"


# ---- workspace parser ---- #


def _workspace_event(name: str = "login_success",
                     evt_type: str = "login",
                     actor: str = "alice@google.com",
                     ip: str = "9.10.11.12",
                     ts: str = "2026-05-25T12:00:00Z",
                     params: list | None = None) -> dict:
    return {
        "id": {"time": ts, "uniqueQualifier": "q",
               "applicationName": "login"},
        "actor": {"email": actor, "callerType": "USER"},
        "ipAddress": ip,
        "events": [{"type": evt_type, "name": name,
                    "parameters": params or []}],
    }


def test_parse_workspace_event_basic_login():
    ev = parse_workspace_event(_workspace_event())
    assert ev is not None
    assert ev.provider == "workspace"
    assert ev.event_type == "auth"
    assert ev.outcome == "success"
    assert ev.actor == "alice@google.com"


def test_parse_workspace_event_login_failure():
    ev = parse_workspace_event(_workspace_event(name="login_failure"))
    assert ev is not None
    assert ev.event_type == "auth_failure"
    assert ev.outcome == "failure"


def test_parse_workspace_event_2sv():
    ev = parse_workspace_event(_workspace_event(
        name="2sv_disable", evt_type="account",
    ))
    assert ev is not None
    assert ev.event_type == "mfa_auth"


def test_parse_workspace_event_admin_role_assignment():
    ev = parse_workspace_event(_workspace_event(
        name="role_assignment", evt_type="admin",
    ))
    assert ev is not None
    assert ev.event_type == "admin_grant"


def test_parse_workspace_event_returns_none_without_events():
    assert parse_workspace_event({"id": {"time": "x"},
                                   "actor": {"email": "a"}}) is None


def test_normalize_workspace_event_type_suspicious():
    assert _normalize_workspace_event_type("login", "suspicious_login",
                                            []) == "suspicious_activity"


# ---- ingest_file ---- #


def test_ingest_file_rejects_unknown_provider(tmp_path):
    p = tmp_path / "log.json"
    p.write_text("{}")
    store = EvidenceStore(tmp_path / "case")
    try:
        with pytest.raises(IdpError):
            ingest_file(str(p), store, provider="paypal")
    finally:
        store.close()


def test_ingest_file_rejects_missing_file(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        with pytest.raises(IdpError):
            ingest_file(str(tmp_path / "nonexistent.json"),
                        store, provider="okta")
    finally:
        store.close()


def test_ingest_file_ndjson_basic(tmp_path):
    p = tmp_path / "log.ndjson"
    lines = [
        json.dumps(_okta_event("user.authentication.auth")),
        json.dumps(_okta_event("user.mfa.deny_push", outcome="FAILURE")),
        "",  # blank line
    ]
    p.write_text("\n".join(lines) + "\n")
    store = EvidenceStore(tmp_path / "case")
    try:
        summary = ingest_file(str(p), store, provider="okta")
        assert summary.events_emitted == 2
        assert summary.events_total == 3   # 2 events + 1 blank
        assert summary.events_skipped == 1
        assert summary.by_event_type["auth"] == 1
        assert summary.by_event_type["mfa_denied"] == 1
        arts = list(store.iter_artifacts(category="identity"))
        assert len(arts) == 2
        assert arts[0]["collector"] == "idp.okta"
    finally:
        store.close()


def test_ingest_file_json_array(tmp_path):
    p = tmp_path / "log.json"
    p.write_text(json.dumps([
        _okta_event("user.authentication.auth"),
        _okta_event("user.session.start"),
    ]))
    store = EvidenceStore(tmp_path / "case")
    try:
        summary = ingest_file(str(p), store, provider="okta")
        assert summary.events_emitted == 2
    finally:
        store.close()


def test_ingest_file_actor_filter(tmp_path):
    p = tmp_path / "log.ndjson"
    p.write_text("\n".join([
        json.dumps(_okta_event("user.authentication.auth",
                                actor="alice@example.com")),
        json.dumps(_okta_event("user.authentication.auth",
                                actor="bob@example.com")),
    ]) + "\n")
    store = EvidenceStore(tmp_path / "case")
    try:
        summary = ingest_file(str(p), store, provider="okta",
                              actors=["alice@example.com"])
        assert summary.events_emitted == 1
        assert summary.events_skipped == 1
    finally:
        store.close()


def test_ingest_file_time_filters(tmp_path):
    p = tmp_path / "log.ndjson"
    p.write_text("\n".join([
        json.dumps(_okta_event("user.authentication.auth",
                                ts="2026-05-25T12:00:00Z")),
        json.dumps(_okta_event("user.authentication.auth",
                                ts="2026-05-25T14:00:00Z")),
    ]) + "\n")
    store = EvidenceStore(tmp_path / "case")
    try:
        after = _parse_iso("2026-05-25T13:00:00Z")
        summary = ingest_file(str(p), store, provider="okta",
                              after_ts=after)
        assert summary.events_emitted == 1
        assert summary.events_skipped == 1
    finally:
        store.close()


def test_ingest_file_limit(tmp_path):
    p = tmp_path / "log.ndjson"
    p.write_text("\n".join([
        json.dumps(_okta_event("user.authentication.auth"))
        for _ in range(10)
    ]) + "\n")
    store = EvidenceStore(tmp_path / "case")
    try:
        summary = ingest_file(str(p), store, provider="okta", limit=3)
        assert summary.events_emitted == 3
    finally:
        store.close()


def test_ingest_file_skips_malformed_ndjson_lines(tmp_path):
    p = tmp_path / "log.ndjson"
    p.write_text("\n".join([
        json.dumps(_okta_event("user.authentication.auth")),
        "not json at all",
        json.dumps(_okta_event("user.authentication.auth")),
    ]) + "\n")
    store = EvidenceStore(tmp_path / "case")
    try:
        summary = ingest_file(str(p), store, provider="okta")
        assert summary.events_emitted == 2
        assert summary.events_skipped == 1
    finally:
        store.close()


def test_ingest_file_entra_alias_azure(tmp_path):
    p = tmp_path / "log.ndjson"
    p.write_text(json.dumps(_entra_event()) + "\n")
    store = EvidenceStore(tmp_path / "case")
    try:
        summary = ingest_file(str(p), store, provider="azure")
        assert summary.events_emitted == 1
        assert summary.provider == "azure"
    finally:
        store.close()


def test_ingest_file_workspace_alias_google(tmp_path):
    p = tmp_path / "log.ndjson"
    p.write_text(json.dumps(_workspace_event()) + "\n")
    store = EvidenceStore(tmp_path / "case")
    try:
        summary = ingest_file(str(p), store, provider="google")
        assert summary.events_emitted == 1
    finally:
        store.close()


# ---- detector: helper ---- #


def _seed_event(store: EvidenceStore, **kwargs) -> str:
    """Insert one IdP-shaped Artifact directly."""
    from digger.core.evidence import Artifact
    data = {
        "provider": "okta",
        "event_type": "auth",
        "raw_event_type": "user.authentication.auth",
        "actor": "alice@example.com",
        "outcome": "success",
        "src_ip": "1.2.3.4",
        "country": "US",
        "city": "NYC",
        "user_agent": "",
        "target": "",
        "ts": 1_700_000_000.0,
        "raw": {},
    }
    data.update(kwargs)
    art = Artifact(
        collector=f"idp.{data['provider']}",
        category="identity",
        subject=f"idp:{data['provider']}:{data['event_type']}:t:{data['actor']}",
        data=data,
    )
    return store.add_artifact(art)


def test_idp_event_records_sorts_by_ts(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_event(store, ts=200.0)
        _seed_event(store, ts=100.0)
        _seed_event(store, ts=300.0)
        recs = _idp_event_records(store)
        assert [r["ts"] for r in recs] == [100.0, 200.0, 300.0]
    finally:
        store.close()


def test_idp_event_records_skips_artifacts_without_actor(tmp_path):
    from digger.core.evidence import Artifact
    store = EvidenceStore(tmp_path / "case")
    try:
        store.add_artifact(Artifact(
            collector="idp.okta", category="identity",
            subject="bad", data={"foo": "bar"},
        ))
        recs = _idp_event_records(store)
        assert recs == []
    finally:
        store.close()


# ---- detector: I2 OAuth grant ---- #


def test_detector_i2_oauth_grant(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_event(store, event_type="oauth_grant",
                    raw_event_type="app.oauth2.client.create",
                    target="EvilApp")
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "oauth_grant"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1098.001"
        assert "EvilApp" in f[0].title
    finally:
        store.close()


# ---- detector: I3 admin grant ---- #


def test_detector_i3_admin_grant(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_event(store, event_type="admin_grant",
                    raw_event_type="user.account.privilege.grant",
                    target="bob@example.com")
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "admin_grant"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].mitre == "T1098"
    finally:
        store.close()


# ---- detector: I6 federation change ---- #


def test_detector_i6_federation_change(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_event(store, event_type="federation_change",
                    raw_event_type="system.idp.federation.update")
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "federation_change"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].mitre == "T1556.007"
    finally:
        store.close()


# ---- detector: I1 MFA fatigue ---- #


def test_detector_i1_mfa_fatigue_threshold(tmp_path):
    """Exactly N denies within the window must trigger."""
    store = EvidenceStore(tmp_path / "case")
    try:
        for i in range(MFA_FATIGUE_MIN_DENIES):
            _seed_event(store, event_type="mfa_denied",
                        outcome="failure",
                        ts=1_700_000_000.0 + i * 10)
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "mfa_fatigue"]
        assert len(f) == 1
        assert f[0].severity == "high"
        assert f[0].evidence["deny_count"] == MFA_FATIGUE_MIN_DENIES
        assert f[0].mitre == "T1621"
    finally:
        store.close()


def test_detector_i1_mfa_fatigue_followup_success_critical(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        for i in range(MFA_FATIGUE_MIN_DENIES):
            _seed_event(store, event_type="mfa_denied",
                        outcome="failure",
                        ts=1_700_000_000.0 + i * 10)
        # Followup success within 30 min
        _seed_event(store, event_type="mfa_auth",
                    outcome="success",
                    ts=1_700_000_000.0 + 200)
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "mfa_fatigue"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].evidence["followup_success"] is True
    finally:
        store.close()


def test_detector_i1_mfa_fatigue_below_threshold(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        for i in range(MFA_FATIGUE_MIN_DENIES - 1):
            _seed_event(store, event_type="mfa_denied",
                        outcome="failure",
                        ts=1_700_000_000.0 + i * 10)
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "mfa_fatigue"]
    finally:
        store.close()


def test_detector_i1_mfa_fatigue_outside_window(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        for i in range(MFA_FATIGUE_MIN_DENIES):
            _seed_event(store, event_type="mfa_denied",
                        outcome="failure",
                        # Each one separated by > window
                        ts=1_700_000_000.0 + i * (MFA_FATIGUE_WINDOW_S + 60))
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "mfa_fatigue"]
    finally:
        store.close()


def test_detector_i1_mfa_fatigue_one_finding_per_actor(tmp_path):
    """Even with many denies, only one finding per actor."""
    store = EvidenceStore(tmp_path / "case")
    try:
        for i in range(MFA_FATIGUE_MIN_DENIES * 3):
            _seed_event(store, event_type="mfa_denied",
                        outcome="failure",
                        ts=1_700_000_000.0 + i * 10)
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        mfa = [x for x in findings
               if x.evidence.get("kind") == "mfa_fatigue"]
        assert len(mfa) == 1
    finally:
        store.close()


# ---- detector: I4 impossible travel ---- #


def test_detector_i4_impossible_travel(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_event(store, event_type="auth", outcome="success",
                    country="US", src_ip="1.2.3.4",
                    ts=1_700_000_000.0)
        _seed_event(store, event_type="auth", outcome="success",
                    country="RU", src_ip="5.6.7.8",
                    ts=1_700_000_000.0 + 600)   # 10 min later
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "impossible_travel"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].mitre == "T1078.004"
        assert f[0].evidence["country_a"] == "US"
        assert f[0].evidence["country_b"] == "RU"
    finally:
        store.close()


def test_detector_i4_impossible_travel_outside_window(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_event(store, event_type="auth", outcome="success",
                    country="US", ts=1_700_000_000.0)
        _seed_event(store, event_type="auth", outcome="success",
                    country="RU",
                    ts=1_700_000_000.0
                       + IMPOSSIBLE_TRAVEL_WINDOW_S + 60)
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "impossible_travel"]
    finally:
        store.close()


def test_detector_i4_impossible_travel_same_country_no_finding(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        _seed_event(store, event_type="auth", outcome="success",
                    country="US", ts=1_700_000_000.0)
        _seed_event(store, event_type="auth", outcome="success",
                    country="US", ts=1_700_000_000.0 + 60)
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "impossible_travel"]
    finally:
        store.close()


# ---- detector: I5 password spray ---- #


def test_detector_i5_password_spray(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        for i in range(SPRAY_MIN_FAILURES):
            _seed_event(store, event_type="auth_failure",
                        outcome="failure",
                        src_ip="9.9.9.9",
                        actor=f"user{i}@example.com",
                        ts=1_700_000_000.0 + i * 5)
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        f = [x for x in findings
             if x.evidence.get("kind") == "password_spray"]
        assert len(f) == 1
        assert f[0].severity == "critical"
        assert f[0].mitre == "T1110.003"
        assert f[0].evidence["src_ip"] == "9.9.9.9"
    finally:
        store.close()


def test_detector_i5_spray_not_enough_distinct_actors(tmp_path):
    """Enough failures, but all from the same actor → not a spray."""
    store = EvidenceStore(tmp_path / "case")
    try:
        for i in range(SPRAY_MIN_FAILURES + 5):
            _seed_event(store, event_type="auth_failure",
                        outcome="failure",
                        src_ip="9.9.9.9",
                        actor="alice@example.com",
                        ts=1_700_000_000.0 + i * 5)
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "password_spray"]
    finally:
        store.close()


def test_detector_i5_spray_below_failure_threshold(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        for i in range(SPRAY_MIN_FAILURES - 1):
            _seed_event(store, event_type="auth_failure",
                        outcome="failure",
                        src_ip="9.9.9.9",
                        actor=f"user{i}@example.com",
                        ts=1_700_000_000.0 + i * 5)
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "password_spray"]
    finally:
        store.close()


def test_detector_i5_spray_outside_window(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        for i in range(SPRAY_MIN_FAILURES):
            _seed_event(store, event_type="auth_failure",
                        outcome="failure",
                        src_ip="9.9.9.9",
                        actor=f"user{i}@example.com",
                        # spread over way more than the window
                        ts=1_700_000_000.0
                           + i * (SPRAY_WINDOW_S + 60))
        det = IdpSecurityDetector()
        findings = list(det.detect(store))
        assert not [x for x in findings
                    if x.evidence.get("kind") == "password_spray"]
    finally:
        store.close()


# ---- detector: registration / sigma template ---- #


def test_detector_registered_in_all_detectors():
    from digger.detectors import all_detectors
    names = {d.name for d in all_detectors()}
    assert "idp_security" in names


def test_detector_sigma_template_has_tags():
    det = IdpSecurityDetector()
    tpl = det.to_sigma_template()
    assert tpl["id"] == "digger-idp-security-template"
    assert "attack.t1621" in tpl["tags"]
    assert "attack.t1110.003" in tpl["tags"]
    assert tpl["logsource"]["product"] == "identity_provider"


def test_detector_returns_no_findings_on_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "case")
    try:
        det = IdpSecurityDetector()
        assert list(det.detect(store)) == []
    finally:
        store.close()


# ---- IdpEvent + summary dataclasses ---- #


def test_idp_event_dataclass_shape():
    ev = IdpEvent(
        provider="okta", event_type="auth", actor="a@b",
        outcome="success", src_ip="1.2.3.4", country="US",
        city="NYC", user_agent="ua", target="",
        raw_event_type="x", ts=1.0,
    )
    assert ev.provider == "okta"
    assert ev.raw == {}


def test_idp_ingest_summary_defaults():
    s = IdpIngestSummary(source="x", provider="okta")
    assert s.events_emitted == 0
    assert s.by_event_type == {}
    assert s.elapsed_s == 0.0
