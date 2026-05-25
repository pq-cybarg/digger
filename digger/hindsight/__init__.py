"""Opt-in deep Chromium profile parsing.

The existing ``BrowserDetector`` / ``BrowserCollector`` are counts-
only by privacy default — they tell you "this profile has 1,234
cookies and 56 saved logins" without storing any cookie value or
password. That's the right default for routine forensics and the
ethics contract.

But IR cases often need the full data: which sites the suspect
visited, when, what cookies are present that might indicate session
hijacking, whether known-compromised passwords appear in saved
logins. This module fills that gap as an EXPLICIT OPT-IN extraction
layer modeled on the Hindsight (obsidianforensics) tool.

Two-gate opt-in
---------------
The parser refuses to run unless BOTH:
  1. ``DIGGER_HINDSIGHT_OK=1`` env var
  2. The caller explicitly passes ``deep=True`` to ``run_scan()`` or
     the CLI ``--deep-browser-parse`` flag

Without both, the scan returns a "skipped — opt-in required"
artifact stub so the case record shows the operator declined.

Per-data-type selection
-----------------------
Default includes the lower-sensitivity tables:
  - history (URLs + visit count + timestamps)
  - downloads (target + source URL + bytes)
  - bookmarks (URL + name + folder)

Explicitly include via ``include=`` to also extract:
  - cookies         (encrypted_value present? Length only; not decrypted)
  - logins          (origin_url + username; password_value LENGTH only)
  - autofill        (form-field name+value pairs)
  - web_data        (credit_cards / addresses — encrypted blob lengths)

We deliberately DO NOT decrypt cookie or password blobs. The
encrypted_value column on macOS/Windows is sealed by the OS keyring
and decryption requires keychain access (which would significantly
escalate digger's permission needs). Caller can decrypt downstream
with their own keychain-aware tooling.

Public API
----------
``run_scan(case_dir, *, include, deep, profiles)``  — main entry
``parse_history(db_path)``  — read History SQLite
``parse_cookies(db_path)``  — read Cookies SQLite
``parse_logins(db_path)``   — read Login Data SQLite
``parse_downloads(db_path)`` — read History.downloads
``parse_bookmarks(path)``   — read Bookmarks JSON
``find_profiles()``         — Chromium profile-dir discovery
"""

from __future__ import annotations

from digger.hindsight.parser import (
    DEFAULT_INCLUDE,
    SUPPORTED_INCLUDE,
    HindsightError,
    find_profiles,
    parse_bookmarks,
    parse_cookies,
    parse_downloads,
    parse_history,
    parse_logins,
    run_scan,
)

__all__ = [
    "DEFAULT_INCLUDE",
    "SUPPORTED_INCLUDE",
    "HindsightError",
    "find_profiles",
    "parse_bookmarks",
    "parse_cookies",
    "parse_downloads",
    "parse_history",
    "parse_logins",
    "run_scan",
]
