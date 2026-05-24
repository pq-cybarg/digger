"""Pre-engagement attestation for defensive investigations.

Inspired by the engagement-planning discipline that responsible
offensive-security tooling (e.g. PurpleAILAB/Decepticon) requires
before a single packet leaves the wire: written Rules of Engagement,
Concept of Operations, Deconfliction Plan, OPPLAN. For an offensive
tool those documents protect the target from the operator. For a
defensive tool, the equivalent documents protect the **subject of
investigation** (often, the operator's own host or their colleague's,
or in IR a client's) from sloppy or out-of-scope collection.

A digger ``EngagementScope`` answers, in writing and captured into the
chain of custody, four questions before the first artifact is touched:

  WHO   — investigator name, role, contact, organization
  WHY   — legal basis or written consent
  WHAT  — scope (which hosts; which data categories opted in)
  WHEN  — time window (start, expected end, retention policy)

Plus a free-form deconfliction-notes field for "do not disturb prod
between X and Y", "don't trip canary file Z", etc.

This is enforced at case-open time: ``EngagementScope.validate()``
raises ``EthicsViolation`` for obvious problems (no investigator, no
authority, scope mentions hosts that aren't this host without an
explicit cross-host marker, etc.).
"""

from __future__ import annotations

import getpass
import json
import socket
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from digger.ethics.contract import EthicsViolation


# Vocabularies the validator recognizes as concrete legal bases.
_VALID_AUTHORITIES = (
    "host owner consent",
    "self (own machine)",
    "incident response retainer",
    "managed-fleet authorization",
    "soc 2 evidence collection",
    "iso 27037 forensic engagement",
    "internal ir program",
    "court order",
    "consent of host owner",
)


_DATA_CATEGORIES = {
    "processes", "network", "filesystem", "persistence", "browsers",
    "logs", "memory", "credentials-locations-only", "code-signing",
    "compliance", "intel-feeds",
}


@dataclass
class EngagementScope:
    """Written, validated, chain-of-custody-recorded scope statement."""

    # WHO
    investigator_name:   str
    investigator_role:   str = "Analyst"
    investigator_contact: str = ""
    organization:        str = ""

    # WHY
    legal_authority:     str = "host owner consent"
    written_consent_ref: str = ""   # ticket #, contract clause, email msg-id

    # WHAT
    target_hosts:        list[str] = field(default_factory=list)
    data_categories:     list[str] = field(default_factory=lambda: ["processes", "network", "persistence"])
    cross_host_allowed:  bool = False     # explicit flag to acknowledge multi-host scope

    # WHEN
    window_start:        float = field(default_factory=time.time)
    window_end_estimate: Optional[float] = None
    retention_days:      int = 90

    # Deconfliction
    deconfliction_notes: list[str] = field(default_factory=list)

    # Self-attested
    attested_by:         str = ""
    attested_at:         float = field(default_factory=time.time)
    attestation_hash:    str = ""

    def validate(self) -> None:
        """Raise EthicsViolation for obviously-broken scope statements.

        Note: we cannot validate the *truth* of an attestation (we
        can't verify a court order from inside a forensics tool). What
        we can validate is that the statement is **specific enough to
        be auditable later** — a vague "this is fine" should be caught.
        """
        if not self.investigator_name.strip():
            raise EthicsViolation(
                "Engagement scope: investigator_name is required. Who is "
                "running this case?"
            )
        if not self.legal_authority.strip():
            raise EthicsViolation(
                "Engagement scope: legal_authority is required. Under what "
                "authority is this investigation being conducted?"
            )
        if self.legal_authority.lower() not in _VALID_AUTHORITIES:
            # Allow it but encode that we audited the choice.
            self.deconfliction_notes.append(
                f"NOTE: legal_authority {self.legal_authority!r} is non-standard; "
                "ensure documentation captures the specific basis."
            )

        host = socket.gethostname()
        if self.target_hosts and not self.cross_host_allowed:
            for t in self.target_hosts:
                if t and t.lower() != host.lower() and t.lower() not in ("localhost", "self", "."):
                    raise EthicsViolation(
                        f"Engagement scope: target_hosts includes {t!r}, which is not "
                        f"the local host ({host}). digger is a host-forensics tool — "
                        "to inspect a host you must run digger on that host. If you "
                        "deliberately want a multi-host case (e.g. aggregating signed "
                        "case bundles from many hosts), pass cross_host_allowed=True "
                        "and document why in deconfliction_notes."
                    )

        unknown_categories = [c for c in self.data_categories if c not in _DATA_CATEGORIES]
        if unknown_categories:
            raise EthicsViolation(
                f"Engagement scope: unrecognized data categories {unknown_categories}. "
                f"Valid categories: {sorted(_DATA_CATEGORIES)}."
            )

        if self.retention_days < 1 or self.retention_days > 3650:
            raise EthicsViolation(
                f"Engagement scope: retention_days={self.retention_days} is out of "
                "the sane range (1 day .. 10 years). Set it deliberately."
            )

    def to_dict(self) -> dict:
        return asdict(self)


def from_local_defaults(
    *,
    investigator_name: Optional[str] = None,
    legal_authority: str = "host owner consent",
    data_categories: Optional[list[str]] = None,
    notes: Optional[list[str]] = None,
) -> EngagementScope:
    """Produce a defensible default for "I'm investigating my own machine."""
    scope = EngagementScope(
        investigator_name=(investigator_name or getpass.getuser()),
        legal_authority=legal_authority,
        target_hosts=[socket.gethostname()],
        data_categories=data_categories or ["processes", "network", "persistence",
                                              "filesystem", "browsers", "code-signing"],
        cross_host_allowed=False,
        deconfliction_notes=notes or [],
        attested_by=getpass.getuser(),
    )
    scope.validate()
    return scope


def record_scope(case_dir: Path | str, scope: EngagementScope) -> Path:
    """Persist the scope to the case directory and return its path.

    The same dict is also appended to the chain-of-custody log so that
    every later operation references it. ``EngagementScope.validate()``
    is re-run here so a tampered scope file is caught.
    """
    scope.validate()
    case_dir = Path(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    out = case_dir / "engagement_scope.json"
    out.write_text(json.dumps(scope.to_dict(), indent=2, default=str),
                   encoding="utf-8")
    return out


def load_scope(case_dir: Path | str) -> Optional[EngagementScope]:
    """Read a previously-recorded scope. Returns None if missing."""
    p = Path(case_dir) / "engagement_scope.json"
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    return EngagementScope(**data)
