"""NATO Admiralty System (STANAG 2511 / FM 2-22.3).

A two-dimensional rating used throughout NATO, Five Eyes, and most
Western intelligence services:

  Source reliability:   A (completely reliable) through F (cannot be judged)
  Information credibility: 1 (confirmed) through 6 (cannot be judged)

A rating like 'A1' means a completely reliable source provided
information that has been independently confirmed. 'F6' is the
honest 'we genuinely don't know'.

We use this alongside ICD 203 for two distinct purposes:
  - ICD 203 grades the analyst's *judgment* (probability + confidence).
  - Admiralty grades the *inputs* the judgment is based on.

For digger findings the source is one or more collectors; the
credibility is whether the artifact corroborates other artifacts.
"""

from __future__ import annotations

SOURCE_RELIABILITY = {
    "A": "Completely reliable — no doubt of authenticity, trustworthiness, or competency; history of complete reliability.",
    "B": "Usually reliable — minor doubt of authenticity, trustworthiness, or competency; history of valid information most of the time.",
    "C": "Fairly reliable — doubt of authenticity, trustworthiness, or competency, but has provided valid information in the past.",
    "D": "Not usually reliable — significant doubt; has provided valid information in the past.",
    "E": "Unreliable — lacks authenticity, trustworthiness, or competency; history of invalid information.",
    "F": "Reliability cannot be judged.",
}

INFO_CREDIBILITY = {
    "1": "Confirmed by other sources — independently corroborated.",
    "2": "Probably true — consistent with other information about the subject.",
    "3": "Possibly true — reasonably consistent with other information.",
    "4": "Doubtful — not consistent with other information; possible.",
    "5": "Improbable — contradicted by other information.",
    "6": "Truth cannot be judged.",
}


def rate_source(letter: str) -> str:
    letter = (letter or "").upper()
    if letter in SOURCE_RELIABILITY:
        return SOURCE_RELIABILITY[letter]
    return SOURCE_RELIABILITY["F"]


def rate_info(digit: str) -> str:
    digit = str(digit)
    if digit in INFO_CREDIBILITY:
        return INFO_CREDIBILITY[digit]
    return INFO_CREDIBILITY["6"]


def derive_for_collector(collector_name: str) -> str:
    """Rough default rating for digger collectors."""
    # First-party, deterministic collectors from authoritative OS APIs.
    auth_collectors = {
        "processes", "network", "system", "windows.services",
        "windows.registry_persistence", "macos.launchd",
        "linux.systemd", "linux.cron", "users",
    }
    if collector_name in auth_collectors:
        return "A"
    return "B"
