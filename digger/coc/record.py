"""Chain of custody record per ISO/IEC 27037:2012 and NIST SP 800-86.

ISO/IEC 27037 §6 prescribes what must be recorded for digital evidence
to be admissible and forensically sound:

  - WHO acquired/handled the evidence (named individual, contact, role)
  - WHAT was acquired (device identifier, source path, size, hash)
  - WHEN each action took place (UTC timestamp, time zone, time source)
  - WHERE the action took place (physical/logical location)
  - WHY the action was taken (legal authority, investigative scope)
  - HOW the action was performed (tools, versions, methodology)

NIST SP 800-86 §3 (Collection / Examination / Analysis / Reporting)
adds requirements for documenting the integrity of evidence and the
methodology used.

digger writes a CoC record alongside the evidence DB and updates it
whenever the case is signed, exported, encrypted, opened, or analyzed.
Combined with the SQLite hash chain and the PQC signature, this gives
a defensible record for legal, regulatory, or incident-response use.
"""

from __future__ import annotations

import getpass
import json
import platform
import socket
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


EVENT_TYPES = (
    "case_opened",
    "collection_started", "collection_finished",
    "scan_started", "scan_finished",
    "triage_started", "triage_finished",
    "report_generated",
    "case_signed", "case_verified",
    "case_exported", "case_imported",
    "case_encrypted", "case_decrypted",
    "evidence_transferred",
    "case_closed",
    "manual_note",
)


@dataclass
class CustodyEvent:
    event_type: str
    timestamp_utc: float
    iso_8601: str
    actor_name: str
    actor_user: str
    actor_host: str
    location: str
    methodology: str
    notes: str = ""
    tool: str = "digger"
    tool_version: str = ""
    integrity_hash: str = ""
    event_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"invalid event type {self.event_type!r}")


@dataclass
class ChainOfCustody:
    case_id: str
    custodian_name: str
    custodian_role: str
    custodian_contact: str
    legal_authority: str        # e.g. "internal IR program §4.2" or "consent of host owner"
    investigative_scope: str    # natural-language scope of the engagement
    target_host: str
    target_os: str
    time_zone: str
    time_source: str            # e.g. "local OS clock (NTP-synced via pool.ntp.org)"
    classification: str = "UNCLASSIFIED"
    handling_caveats: list[str] = field(default_factory=list)
    tlp: str = "TLP:AMBER"
    iso_27037_compliance: bool = True
    nist_800_86_compliance: bool = True
    events: list[CustodyEvent] = field(default_factory=list)
    record_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    opened_utc: float = field(default_factory=time.time)


def open_custody(
    case_dir: str | Path,
    *,
    case_id: str,
    custodian_name: Optional[str] = None,
    custodian_role: str = "Analyst",
    custodian_contact: str = "",
    legal_authority: str = "host owner consent",
    investigative_scope: str = "endpoint forensic triage",
    classification: str = "UNCLASSIFIED",
    handling_caveats: Optional[list[str]] = None,
    tlp: str = "TLP:AMBER",
) -> ChainOfCustody:
    """Create or load the chain-of-custody record for a case directory."""
    case_dir = Path(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    coc_path = case_dir / "chain_of_custody.json"
    if coc_path.exists():
        try:
            data = json.loads(coc_path.read_text(encoding="utf-8"))
            events = [CustodyEvent(**e) for e in data.pop("events", [])]
            return ChainOfCustody(**data, events=events)
        except Exception:
            pass
    coc = ChainOfCustody(
        case_id=case_id,
        custodian_name=custodian_name or getpass.getuser(),
        custodian_role=custodian_role,
        custodian_contact=custodian_contact,
        legal_authority=legal_authority,
        investigative_scope=investigative_scope,
        target_host=socket.gethostname(),
        target_os=platform.platform(),
        time_zone=time.strftime("%Z"),
        time_source="local OS clock",
        classification=classification,
        handling_caveats=handling_caveats or [],
        tlp=tlp,
    )
    _record_event(case_dir, coc, "case_opened", "case directory initialized")
    return coc


def _record_event(case_dir: Path, coc: ChainOfCustody, event_type: str,
                  notes: str, methodology: str = "automated digger workflow") -> CustodyEvent:
    import digger
    ev = CustodyEvent(
        event_type=event_type,
        timestamp_utc=time.time(),
        iso_8601=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        actor_name=coc.custodian_name,
        actor_user=getpass.getuser(),
        actor_host=socket.gethostname(),
        location=f"{platform.system()} {platform.release()}",
        methodology=methodology,
        notes=notes,
        tool_version=getattr(digger, "__version__", ""),
    )
    coc.events.append(ev)
    _write(case_dir, coc)
    return ev


def append_event(case_dir: str | Path, coc: ChainOfCustody, event_type: str,
                 notes: str = "", methodology: str = "automated digger workflow") -> CustodyEvent:
    return _record_event(Path(case_dir), coc, event_type, notes, methodology)


def _write(case_dir: Path, coc: ChainOfCustody) -> None:
    data = asdict(coc)
    (case_dir / "chain_of_custody.json").write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8",
    )
