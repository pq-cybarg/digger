"""Identity-provider observability — Okta / Entra / Workspace.

The layer above the host. Most modern breaches start with identity
compromise (MFA fatigue, OAuth consent grants, anomalous geo-velocity,
admin role grants), then pivot through cloud/CI to the host. Ingesting
the IdP audit log gives digger the upstream signal.

Public API
----------
``ingest_file(log_path, store, *, provider, ...)`` — read NDJSON log,
                                                     emit Artifacts
``IdpEvent`` — normalized event shape (provider-agnostic)
``IdpIngestSummary`` — per-ingest counts + per-event-type tally
``IdpError`` — raised on missing-file / parse failure
"""

from __future__ import annotations

from digger.idp.parser import (
    IdpError,
    IdpEvent,
    IdpIngestSummary,
    ingest_file,
    parse_entra_event,
    parse_okta_event,
    parse_workspace_event,
)

__all__ = [
    "IdpError",
    "IdpEvent",
    "IdpIngestSummary",
    "ingest_file",
    "parse_entra_event",
    "parse_okta_event",
    "parse_workspace_event",
]
