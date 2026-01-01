"""Identity-provider audit-log parser.

Three provider shapes supported. Normalize into a shared ``IdpEvent``
dataclass so the detector can run one rule set across all of them.

Per-provider input shapes
-------------------------

Okta System Log API:
  {
    "eventType": "user.authentication.auth_via_mfa",
    "outcome": {"result": "SUCCESS"},
    "actor": {"alternateId": "alice@example.com", ...},
    "client": {"ipAddress": "1.2.3.4",
               "geographicalContext": {"country": "US", "city": "NYC"}},
    "published": "2026-05-25T12:00:00.000Z",
    "displayMessage": "Authentication of user via MFA",
    "target": [{"alternateId": ..., "type": ...}, ...],
    "uuid": "..."
  }

Microsoft Entra (Azure AD) Sign-In + Audit logs:
  {
    "operationName": "Sign-in activity",
    "userPrincipalName": "alice@example.com",
    "ipAddress": "1.2.3.4",
    "location": {"countryOrRegion": "US", "city": "NYC"},
    "createdDateTime": "2026-05-25T12:00:00Z",
    "status": {"errorCode": 0, "additionalDetails": ...},
    "appDisplayName": "...",
    "id": "..."
  }
  + audit logs use ``activityDisplayName``, ``targetResources``, etc.

Google Workspace (Admin SDK Reports API):
  {
    "id": {"time": "2026-05-25T12:00:00.000Z", "uniqueQualifier": "...",
           "applicationName": "login"},
    "actor": {"email": "alice@example.com", "callerType": "USER"},
    "events": [{"type": "login", "name": "login_success",
                "parameters": [{"name": "login_type", "value": "password"},
                               {"name": "is_suspicious", "boolValue": true}]}],
    "ipAddress": "1.2.3.4"
  }
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class IdpError(RuntimeError):
    """Raised on missing-file / parse failure."""


# ---- safety caps ---- #


_MAX_LOG_BYTES = 4 * 1024 * 1024 * 1024     # 4 GiB
_MAX_FIELD_LEN = 8192


def _truncate(v: Any) -> Any:
    if isinstance(v, str) and len(v) > _MAX_FIELD_LEN:
        return v[:_MAX_FIELD_LEN] + " …<truncated>…"
    return v


# ---- normalized event shape ---- #


@dataclass
class IdpEvent:
    """Provider-agnostic event shape consumed by the detector."""
    provider: str        # "okta" / "entra" / "workspace"
    event_type: str      # provider-normalized event name
    actor: str           # email / UPN of the actor
    outcome: str         # "success" / "failure" / ""
    src_ip: str          # source IP
    country: str         # GeoIP country (best-effort)
    city: str            # GeoIP city (best-effort)
    user_agent: str      # if present
    target: str          # target resource name (app / user / role)
    raw_event_type: str  # untouched original event type
    ts: float | None     # epoch seconds
    raw: dict[str, Any] = field(default_factory=dict)


# ---- timestamp parsers ---- #


def _parse_iso(ts_str: str | None) -> float | None:
    if not ts_str:
        return None
    try:
        s = str(ts_str).rstrip("Z")
        if "." in s:
            base, frac = s.split(".", 1)
            frac = (frac + "000000")[:6]
            s = f"{base}.{frac}+00:00"
        else:
            s = f"{s}+00:00"
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, OSError, OverflowError):
        return None


# ---- per-provider parsers ---- #


def parse_okta_event(raw: dict[str, Any]) -> IdpEvent | None:
    if not isinstance(raw, dict):
        return None
    et = raw.get("eventType")
    if not et:
        return None
    actor = (raw.get("actor") or {}).get("alternateId", "") or \
        (raw.get("actor") or {}).get("displayName", "")
    client = raw.get("client") or {}
    geo = client.get("geographicalContext") or {}
    outcome = ((raw.get("outcome") or {}).get("result") or "").lower()
    target_list = raw.get("target") or []
    target_name = ""
    if target_list and isinstance(target_list, list):
        first = target_list[0]
        if isinstance(first, dict):
            target_name = first.get("alternateId") or \
                first.get("displayName") or ""
    return IdpEvent(
        provider="okta",
        event_type=_normalize_okta_event_type(et),
        actor=str(actor)[:200],
        outcome=outcome if outcome in ("success", "failure") else outcome,
        src_ip=str(client.get("ipAddress") or "")[:64],
        country=str(geo.get("country") or "")[:64],
        city=str(geo.get("city") or "")[:64],
        user_agent=str((client.get("userAgent") or {}).get("rawUserAgent")
                       or "")[:256],
        target=str(target_name)[:256],
        raw_event_type=str(et)[:200],
        ts=_parse_iso(raw.get("published")),
        raw={"display_message": _truncate(raw.get("displayMessage") or ""),
             "uuid": raw.get("uuid"),
             "session_id": (client.get("session") or {}).get("id"),
             "outcome_reason": (raw.get("outcome") or {}).get("reason"),
             "target_full": target_list[:5] if target_list else []},
    )


def _normalize_okta_event_type(et: str) -> str:
    """Map Okta's event types to digger-internal categories.
    Detector keys off these."""
    et = et.lower()
    if "auth_via_mfa" in et:
        return "mfa_auth"
    if "mfa.deny_push" in et or "mfa.user.user_rejects_push" in et \
            or "mfa.deny" in et:
        return "mfa_denied"
    if et.startswith("user.session.start"):
        return "session_start"
    if et.startswith("user.session.end"):
        return "session_end"
    if "authentication.auth_via_inline_mfa" in et or \
            "authentication.sso" in et or \
            "authentication.auth_via_social" in et or \
            "user.authentication.auth" in et:
        return "auth"
    if "application.user_membership.add" in et or \
            "application.lifecycle.create" in et or \
            "oauth2_token" in et or "app.oauth2.client" in et:
        return "oauth_grant"
    if "user.account.privilege.grant" in et or \
            "group.privilege.grant" in et or \
            "user.account.report_suspicious" in et:
        return "admin_grant"
    if "policy.lifecycle" in et:
        return "policy_change"
    if "federation" in et:
        return "federation_change"
    return et


def parse_entra_event(raw: dict[str, Any]) -> IdpEvent | None:
    if not isinstance(raw, dict):
        return None
    # Sign-in logs have userPrincipalName; audit logs have
    # initiatedBy.user.userPrincipalName.
    upn = raw.get("userPrincipalName") or ""
    if not upn:
        upn = ((raw.get("initiatedBy") or {}).get("user")
               or {}).get("userPrincipalName", "")
    op_name = raw.get("operationName") or raw.get("activityDisplayName") or ""
    if not op_name:
        return None
    status = raw.get("status") or {}
    err = status.get("errorCode") if isinstance(status, dict) else None
    outcome = "success" if err == 0 else "failure" if err else ""
    if not outcome and raw.get("result"):
        outcome = "success" if raw["result"] == "success" else "failure"
    loc = raw.get("location") or {}
    target_resources = raw.get("targetResources") or []
    target_name = ""
    if target_resources and isinstance(target_resources, list):
        first = target_resources[0]
        if isinstance(first, dict):
            target_name = first.get("displayName") or \
                first.get("userPrincipalName") or ""
    return IdpEvent(
        provider="entra",
        event_type=_normalize_entra_event_type(op_name),
        actor=str(upn)[:200],
        outcome=outcome,
        src_ip=str(raw.get("ipAddress") or "")[:64],
        country=str(loc.get("countryOrRegion") or "")[:64],
        city=str(loc.get("city") or "")[:64],
        user_agent=str(raw.get("userAgent") or "")[:256],
        target=str(target_name)[:256],
        raw_event_type=str(op_name)[:200],
        ts=_parse_iso(raw.get("createdDateTime")
                       or raw.get("activityDateTime")),
        raw={"app": raw.get("appDisplayName"),
             "correlation_id": raw.get("correlationId"),
             "risk_level": raw.get("riskLevelAggregated"),
             "conditional_access": raw.get("conditionalAccessStatus"),
             "auth_methods_used":
                 raw.get("authenticationMethodsUsed") or [],
             "additional_details":
                 _truncate(json.dumps(status.get("additionalDetails")
                                       if isinstance(status, dict) else None,
                                       default=str)),
             "target_full": target_resources[:5] if target_resources else []},
    )


def _normalize_entra_event_type(op: str) -> str:
    op = op.lower()
    if op == "sign-in activity" or op.startswith("sign-in"):
        return "auth"
    if "add member to role" in op or "add owner" in op or \
            "add app role assignment" in op:
        return "admin_grant"
    if "consent to application" in op or "add oauth2permission" in op or \
            "add service principal" in op:
        return "oauth_grant"
    if "update policy" in op or "delete policy" in op or \
            "add policy" in op:
        return "policy_change"
    if "federation" in op or "add identity provider" in op or \
            "set domain authentication" in op:
        return "federation_change"
    if "mfa" in op or "strong authentication" in op:
        return "mfa_change"
    if "password reset" in op or "self-service password" in op:
        return "password_reset"
    return op


def parse_workspace_event(raw: dict[str, Any]) -> IdpEvent | None:
    if not isinstance(raw, dict):
        return None
    id_block = raw.get("id") or {}
    ts_str = id_block.get("time")
    actor_block = raw.get("actor") or {}
    actor = actor_block.get("email") or actor_block.get("profileId") or ""
    events = raw.get("events") or []
    if not events or not isinstance(events, list):
        return None
    first_evt = events[0] if isinstance(events[0], dict) else {}
    evt_type = first_evt.get("type") or ""
    evt_name = first_evt.get("name") or ""
    params = first_evt.get("parameters") or []
    is_suspicious = any(
        p.get("name") == "is_suspicious" and p.get("boolValue") is True
        for p in params if isinstance(p, dict)
    )
    # Workspace doesn't carry success/failure as a single field —
    # infer from event name (login_success / login_failure /
    # login_challenge / etc.).
    outcome = ""
    if "success" in evt_name or evt_name == "login":
        outcome = "success"
    elif "failure" in evt_name:
        outcome = "failure"
    # Target = first user_email parameter if present
    target_name = ""
    for p in params:
        if isinstance(p, dict) and p.get("name") in (
            "user_email", "target_user_email", "user",
        ):
            target_name = p.get("value") or ""
            break
    return IdpEvent(
        provider="workspace",
        event_type=_normalize_workspace_event_type(
            evt_type, evt_name, params,
        ),
        actor=str(actor)[:200],
        outcome=outcome,
        src_ip=str(raw.get("ipAddress") or "")[:64],
        country="",
        city="",
        user_agent="",
        target=str(target_name)[:256],
        raw_event_type=f"{evt_type}.{evt_name}"[:200],
        ts=_parse_iso(ts_str),
        raw={"params": params[:20],
             "is_suspicious": is_suspicious,
             "application_name": id_block.get("applicationName"),
             "unique_qualifier": id_block.get("uniqueQualifier")},
    )


def _normalize_workspace_event_type(
    evt_type: str, evt_name: str, params: list,
) -> str:
    et = (evt_type or "").lower()
    en = (evt_name or "").lower()
    if en == "login_success" or en == "login":
        return "auth"
    if en == "login_failure" or en == "login_challenge":
        return "auth_failure"
    if "login_verification" in en or "2sv_" in en:
        return "mfa_auth"
    if et == "admin" or "role_assignment" in en or \
            "_admin_grant" in en or "create_role" in en:
        return "admin_grant"
    if "authorize_third_party_app" in en or \
            "issue_authorization_code" in en:
        return "oauth_grant"
    if "suspicious" in en:
        return "suspicious_activity"
    return f"{et}.{en}" if et and en else (en or et)


# ---- summary ---- #


@dataclass
class IdpIngestSummary:
    source: str
    provider: str
    events_total: int = 0
    events_emitted: int = 0
    events_skipped: int = 0
    by_event_type: dict[str, int] = field(default_factory=dict)
    elapsed_s: float = 0.0


# ---- top-level ingest ---- #


_PARSERS = {
    "okta":      parse_okta_event,
    "entra":     parse_entra_event,
    "azure":     parse_entra_event,
    "workspace": parse_workspace_event,
    "google":    parse_workspace_event,
}


def _emit(store, ev: IdpEvent):
    """Emit one Artifact per event. Event_type drives collector
    naming so the storyline walker / query layer can slice on it."""
    from digger.core.evidence import Artifact
    iso_ts = ""
    if ev.ts:
        try:
            iso_ts = datetime.fromtimestamp(
                ev.ts, tz=timezone.utc,
            ).strftime("%Y%m%dT%H%M%S")
        except (OSError, OverflowError, ValueError):
            iso_ts = "0"
    subject = f"idp:{ev.provider}:{ev.event_type}:{iso_ts}:{ev.actor}"
    store.add_artifact(Artifact(
        collector=f"idp.{ev.provider}",
        category="identity",
        subject=subject[:380],
        data={
            "provider": ev.provider,
            "event_type": ev.event_type,
            "raw_event_type": ev.raw_event_type,
            "actor": ev.actor,
            "outcome": ev.outcome,
            "src_ip": ev.src_ip,
            "country": ev.country,
            "city": ev.city,
            "user_agent": ev.user_agent,
            "target": ev.target,
            "ts": ev.ts,
            "raw": ev.raw,
        },
    ))


def ingest_file(
    log_path: str,
    store,
    *,
    provider: str,
    after_ts: float | None = None,
    before_ts: float | None = None,
    actors: Iterable[str] | None = None,
    limit: int | None = None,
) -> IdpIngestSummary:
    """Read an NDJSON / JSON-array log file and emit one Artifact per
    event. ``provider`` must be one of okta / entra / azure /
    workspace / google."""
    if provider not in _PARSERS:
        raise IdpError(
            f"unknown provider {provider!r}. "
            f"Supported: {sorted(_PARSERS.keys())}"
        )
    p = log_path
    if not os.path.isfile(p):
        raise IdpError(f"idp log not found: {p}")
    try:
        sz = os.path.getsize(p)
    except OSError as exc:
        raise IdpError(f"stat failed: {exc}") from exc
    if sz > _MAX_LOG_BYTES:
        raise IdpError(
            f"log {p} is {sz} bytes (> {_MAX_LOG_BYTES} cap)."
        )

    parser = _PARSERS[provider]
    actor_set = {a.lower() for a in actors} if actors else None
    summary = IdpIngestSummary(source=p, provider=provider)
    started = time.time()

    with open(p, "r", encoding="utf-8", errors="replace") as fh:
        # Try to detect format: NDJSON vs JSON array.
        first_char = fh.read(1)
        fh.seek(0)
        if first_char == "[":
            try:
                blob = json.load(fh)
            except json.JSONDecodeError as exc:
                raise IdpError(f"JSON array parse failed: {exc}") from exc
            events = blob if isinstance(blob, list) else []
            for raw in events:
                _process_one(
                    raw, parser, store, summary,
                    actor_set, after_ts, before_ts, limit,
                )
                if limit is not None and summary.events_emitted >= limit:
                    break
        else:
            for line in fh:
                line = line.strip()
                if not line:
                    summary.events_total += 1
                    summary.events_skipped += 1
                    continue
                summary.events_total += 1
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    summary.events_skipped += 1
                    continue
                _process_one(
                    raw, parser, store, summary,
                    actor_set, after_ts, before_ts, limit,
                    counted=True,
                )
                if limit is not None and summary.events_emitted >= limit:
                    break

    summary.elapsed_s = time.time() - started
    return summary


def _process_one(
    raw, parser, store, summary,
    actor_set, after_ts, before_ts, limit,
    *, counted=False,
):
    """Parse + filter + emit a single raw event dict."""
    if not counted:
        summary.events_total += 1
    ev = parser(raw)
    if ev is None:
        summary.events_skipped += 1
        return
    summary.by_event_type[ev.event_type] = \
        summary.by_event_type.get(ev.event_type, 0) + 1
    if actor_set and ev.actor.lower() not in actor_set:
        summary.events_skipped += 1
        return
    if after_ts is not None and (ev.ts is None or ev.ts < after_ts):
        summary.events_skipped += 1
        return
    if before_ts is not None and (ev.ts is None or ev.ts > before_ts):
        summary.events_skipped += 1
        return
    _emit(store, ev)
    summary.events_emitted += 1
