"""Falco runtime-security bridge.

Falco (https://falco.org, CNCF-graduated) is the standard open-source
runtime-security tool for Linux. It uses eBPF (or a legacy kernel
module) to monitor syscall-level events and apply rule packs that
detect things like shell-in-container, sensitive-file reads,
outbound connections from suspicious processes, setuid bit
manipulation, and dozens more.

This bridge has two modes:

  ingest_file  Cross-platform — parses an existing Falco NDJSON event
               log file. Useful when a Falco-running Linux host has
               been acquired and its event log shipped elsewhere for
               analysis (e.g., a macOS analyst workstation).

  stream       Linux-only — pipes the live ``falco -o
               json_output=true`` output into the EvidenceStore. Pairs
               with ``digger watch`` to give continuous syscall-level
               monitoring alongside the periodic snapshot+scan.

Each Falco event becomes ``Artifact(collector="falco:<rule>",
category="runtime_alert", subject="falco:<ts>:<rule>", data={...})``.
The existing detectors / storyline / query / ELK pipeline runs over
them without any special wiring — a Falco event tagged
``mitre_credential_access`` correlates with a digger ``ssh_auth_keys``
finding on the same host via the storyline reconstructor.

Public API
----------
``discover_binary()`` — find ``falco`` in PATH
``ingest_file(log, store, ...)`` — parse a Falco NDJSON event log
``stream_events(store, ...)`` — Linux-only live-stream wrapper
"""

from __future__ import annotations

from digger.falco.runner import (
    FalcoError,
    FalcoIngestSummary,
    discover_binary,
    ingest_file,
    parse_event,
    stream_events,
)

__all__ = [
    "FalcoError",
    "FalcoIngestSummary",
    "discover_binary",
    "ingest_file",
    "parse_event",
    "stream_events",
]
