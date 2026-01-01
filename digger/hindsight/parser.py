"""Hindsight Chromium-profile deep parser.

Reads each Chromium profile DB via SQLite URI mode ``mode=ro&
immutable=1`` so the parser never locks against a running browser
and never modifies the file (even by accident via journal).

Per-DB scope
------------
History DB:
  urls(id, url, title, visit_count, typed_count, last_visit_time)
  visits(id, url, visit_time, from_visit, transition)
  downloads(id, current_path, target_path, start_time, total_bytes,
             received_bytes, state, tab_url)

Cookies DB:
  cookies(creation_utc, host_key, name, value, encrypted_value,
           path, expires_utc, is_secure, is_httponly, ...)

Login Data DB:
  logins(origin_url, action_url, username_element, username_value,
          password_element, password_value, date_created,
          times_used, date_last_used)

Web Data DB:
  autofill(name, value, value_lower, date_created)
  credit_cards / addresses (encrypted blob lengths only)

Bookmarks: JSON file (not SQLite). Walks the tree.

Sensitive-value handling
------------------------
``encrypted_value`` / ``password_value`` are never returned as
plaintext. We record:
  - presence: bool
  - length: int (encrypted-blob byte length)
  - prefix_hex: first 16 bytes hex (lets caller identify the
                encryption scheme — v10/v11/dpapi-prefix)

The caller can decrypt downstream with keychain-aware tooling. The
parser itself stays scope-limited so adding Hindsight to digger
doesn't escalate digger's permission needs.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any


# ---- exception ---- #


class HindsightError(RuntimeError):
    """Raised on opt-in missing / DB-read failure."""


# ---- include set ---- #

SUPPORTED_INCLUDE = (
    "history", "downloads", "bookmarks",
    "cookies", "logins", "autofill", "web_data",
)
# Lower-sensitivity tables that run by default when opted in.
DEFAULT_INCLUDE = ("history", "downloads", "bookmarks")


# ---- opt-in gate ---- #


_OPT_ENV = "DIGGER_HINDSIGHT_OK"


def _check_opt_in(deep: bool) -> None:
    if not deep:
        raise HindsightError(
            "deep parse not requested. Pass deep=True (or "
            "--deep-browser-parse) to enable."
        )
    if os.environ.get(_OPT_ENV) != "1":
        raise HindsightError(
            f"environment opt-in missing. Set {_OPT_ENV}=1 to enable "
            "deep parsing. Combined with --deep-browser-parse this "
            "extracts URL history / cookies / login metadata from "
            "Chromium profiles — material privacy escalation vs the "
            "default counts-only browser scanner."
        )


# ---- Chromium profile discovery ---- #


def find_profiles() -> list[Path]:
    """Return every Chromium profile directory on the host.

    Mirrors the existing BrowserCollector layout: enumerates the
    well-known Chrome / Chromium / Edge / Brave / Vivaldi / Opera /
    Arc per-OS roots and yields every per-profile subdir that
    contains a ``History`` SQLite file."""
    from digger.collectors.common import browsers as _b
    out: list[Path] = []
    for prof in _b._chrome_profile_dirs():
        if prof.is_dir() and (prof / "History").is_file():
            out.append(prof)
    return out


# ---- read-only SQLite helper ---- #


def _ro_open(db_path: Path) -> sqlite3.Connection:
    """Open SQLite DB read-only + immutable so the live browser is not
    locked against, and we never accidentally write."""
    if not db_path.is_file():
        raise HindsightError(f"db not found: {db_path}")
    return sqlite3.connect(
        f"file:{db_path}?mode=ro&immutable=1",
        uri=True, timeout=10.0,
    )


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    )
    return cur.fetchone() is not None


# ---- Chrome timestamp helper ---- #


# Chrome stores timestamps as microseconds since 1601-01-01 (Windows
# FILETIME epoch). We convert to unix epoch seconds for portability.
_CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01


def _chrome_ts(microseconds: int | None) -> float | None:
    if microseconds is None or microseconds == 0:
        return None
    return (microseconds / 1_000_000.0) - _CHROME_EPOCH_OFFSET


# ---- per-DB parsers ---- #


def parse_history(db_path: Path) -> list[dict[str, Any]]:
    """Return URL visits sorted by recency. Includes (url, title,
    visit_count, last_visit_ts, typed_count)."""
    conn = _ro_open(db_path)
    try:
        if not _table_exists(conn, "urls"):
            return []
        rows = conn.execute(
            "SELECT url, title, visit_count, typed_count, last_visit_time "
            "FROM urls ORDER BY last_visit_time DESC LIMIT 50000"
        ).fetchall()
        return [
            {
                "url": r[0],
                "title": r[1],
                "visit_count": r[2],
                "typed_count": r[3],
                "last_visit_ts": _chrome_ts(r[4]),
            }
            for r in rows
        ]
    finally:
        conn.close()


def parse_downloads(db_path: Path) -> list[dict[str, Any]]:
    conn = _ro_open(db_path)
    try:
        if not _table_exists(conn, "downloads"):
            return []
        rows = conn.execute(
            "SELECT id, current_path, target_path, start_time, "
            "       total_bytes, received_bytes, state, tab_url "
            "FROM downloads ORDER BY start_time DESC LIMIT 5000"
        ).fetchall()
        return [
            {
                "id": r[0],
                "current_path": r[1],
                "target_path": r[2],
                "start_ts": _chrome_ts(r[3]),
                "total_bytes": r[4],
                "received_bytes": r[5],
                "state": r[6],
                "source_url": r[7],
            }
            for r in rows
        ]
    finally:
        conn.close()


def parse_cookies(db_path: Path) -> list[dict[str, Any]]:
    """Return one row per cookie. Records encrypted_value presence
    and length — NEVER decrypts the blob."""
    conn = _ro_open(db_path)
    try:
        if not _table_exists(conn, "cookies"):
            return []
        rows = conn.execute(
            "SELECT host_key, name, path, creation_utc, "
            "       expires_utc, is_secure, is_httponly, "
            "       length(value), length(encrypted_value), "
            "       substr(encrypted_value, 1, 16) "
            "FROM cookies ORDER BY creation_utc DESC LIMIT 50000"
        ).fetchall()
        out = []
        for r in rows:
            enc_prefix = r[9]
            out.append({
                "host": r[0],
                "name": r[1],
                "path": r[2],
                "creation_ts": _chrome_ts(r[3]),
                "expires_ts": _chrome_ts(r[4]),
                "secure": bool(r[5]),
                "httponly": bool(r[6]),
                "plaintext_value_len": r[7] or 0,
                "encrypted_value_len": r[8] or 0,
                "encrypted_prefix_hex":
                    enc_prefix.hex() if isinstance(enc_prefix, bytes) else
                    (bytes(enc_prefix).hex() if enc_prefix else ""),
            })
        return out
    finally:
        conn.close()


def parse_logins(db_path: Path) -> list[dict[str, Any]]:
    """Return saved logins. password_value LENGTH only, never plaintext."""
    conn = _ro_open(db_path)
    try:
        if not _table_exists(conn, "logins"):
            return []
        rows = conn.execute(
            "SELECT origin_url, action_url, username_element, "
            "       username_value, password_element, "
            "       length(password_value), substr(password_value, 1, 16), "
            "       date_created, times_used, date_last_used "
            "FROM logins ORDER BY date_last_used DESC LIMIT 10000"
        ).fetchall()
        out = []
        for r in rows:
            pw_prefix = r[6]
            out.append({
                "origin_url": r[0],
                "action_url": r[1],
                "username_element": r[2],
                "username_value": r[3],
                "password_element": r[4],
                "password_value_len": r[5] or 0,
                "password_prefix_hex":
                    pw_prefix.hex() if isinstance(pw_prefix, bytes) else
                    (bytes(pw_prefix).hex() if pw_prefix else ""),
                "date_created_ts": _chrome_ts(r[7]),
                "times_used": r[8],
                "date_last_used_ts": _chrome_ts(r[9]),
            })
        return out
    finally:
        conn.close()


def parse_autofill(db_path: Path) -> list[dict[str, Any]]:
    conn = _ro_open(db_path)
    try:
        if not _table_exists(conn, "autofill"):
            return []
        rows = conn.execute(
            "SELECT name, value, value_lower, date_created, count "
            "FROM autofill ORDER BY date_created DESC LIMIT 10000"
        ).fetchall()
        return [
            {
                "field_name": r[0],
                "value": r[1],
                "value_lower": r[2],
                "date_created_ts": r[3],
                "count": r[4],
            }
            for r in rows
        ]
    finally:
        conn.close()


def parse_web_data(db_path: Path) -> list[dict[str, Any]]:
    """Credit cards + addresses — only blob metadata."""
    conn = _ro_open(db_path)
    try:
        out = []
        if _table_exists(conn, "credit_cards"):
            cc_rows = conn.execute(
                "SELECT guid, name_on_card, expiration_month, "
                "       expiration_year, length(card_number_encrypted) "
                "FROM credit_cards LIMIT 1000"
            ).fetchall()
            for r in cc_rows:
                out.append({
                    "kind": "credit_card",
                    "guid": r[0],
                    "name_on_card": r[1],
                    "exp_month": r[2],
                    "exp_year": r[3],
                    "encrypted_pan_len": r[4] or 0,
                })
        if _table_exists(conn, "addresses"):
            ad_rows = conn.execute(
                "SELECT guid, length(street_address) FROM addresses LIMIT 1000"
            ).fetchall()
            for r in ad_rows:
                out.append({
                    "kind": "address",
                    "guid": r[0],
                    "street_address_len": r[1] or 0,
                })
        return out
    finally:
        conn.close()


def parse_bookmarks(bookmarks_path: Path) -> list[dict[str, Any]]:
    """Walk Chromium's Bookmarks JSON file (not SQLite)."""
    if not bookmarks_path.is_file():
        return []
    try:
        with bookmarks_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    out: list[dict[str, Any]] = []

    def walk(node: dict[str, Any], folder_path: str = "") -> None:
        ntype = node.get("type")
        name = node.get("name", "")
        if ntype == "url":
            out.append({
                "folder": folder_path,
                "name": name,
                "url": node.get("url"),
                "date_added_ts":
                    _chrome_ts(int(node["date_added"]))
                    if node.get("date_added") else None,
            })
        elif ntype == "folder":
            new_path = (folder_path + "/" + name) if folder_path else name
            for child in node.get("children", []) or []:
                walk(child, new_path)

    roots = (data.get("roots") or {})
    for root_name in ("bookmark_bar", "other", "synced"):
        root = roots.get(root_name)
        if isinstance(root, dict):
            walk(root, root_name)
    return out


# ---- top-level scan ---- #


_PARSER_BY_KIND = {
    "history":   ("History",     parse_history),
    "downloads": ("History",     parse_downloads),
    "cookies":   ("Cookies",     parse_cookies),
    "logins":    ("Login Data",  parse_logins),
    "autofill":  ("Web Data",    parse_autofill),
    "web_data":  ("Web Data",    parse_web_data),
}


def run_scan(
    store,
    *,
    deep: bool,
    include: Iterable[str] | None = None,
    profiles: Iterable[Path] | None = None,
) -> dict[str, Any]:
    """Run the deep Chromium parse and emit one Artifact per (profile,
    data-kind, row-batch). Returns a summary dict.

    Refuses to run unless ``deep=True`` AND env opt-in set. When the
    opt-in is missing, still emits a stub Artifact recording that the
    operator declined — that's part of the audit trail."""
    from digger.core.evidence import Artifact

    requested = list(include) if include is not None else list(DEFAULT_INCLUDE)
    unknown = [k for k in requested if k not in SUPPORTED_INCLUDE]
    if unknown:
        raise HindsightError(
            f"unknown include kind(s): {unknown}. "
            f"Supported: {SUPPORTED_INCLUDE}"
        )

    # The opt-in stub — emitted whether we proceed or not.
    try:
        _check_opt_in(deep)
        proceeding = True
        opt_in_reason = "two-gate opt-in satisfied"
    except HindsightError as exc:
        proceeding = False
        opt_in_reason = str(exc)

    store.add_artifact(Artifact(
        collector="hindsight",
        category="audit",
        subject="hindsight:opt_in_check",
        data={
            "deep_requested": deep,
            "env_set": os.environ.get(_OPT_ENV) == "1",
            "include": requested,
            "proceeding": proceeding,
            "reason": opt_in_reason,
            "ts": time.time(),
        },
    ))
    if not proceeding:
        return {
            "proceeded": False,
            "reason": opt_in_reason,
            "profiles": 0,
            "rows_emitted": 0,
        }

    if profiles is None:
        profile_list = find_profiles()
    else:
        profile_list = list(profiles)

    rows_emitted = 0
    for prof in profile_list:
        # Bookmarks lives as a JSON file, not in _PARSER_BY_KIND
        if "bookmarks" in requested:
            bm = parse_bookmarks(prof / "Bookmarks")
            if bm:
                store.add_artifact(Artifact(
                    collector="hindsight",
                    category="browser",
                    subject=f"hindsight:{prof.name}:bookmarks",
                    data={"profile": str(prof), "kind": "bookmarks",
                          "count": len(bm), "rows": bm},
                ))
                rows_emitted += len(bm)
        for kind in requested:
            if kind == "bookmarks":
                continue
            file_name, parser = _PARSER_BY_KIND[kind]
            db_path = prof / file_name
            if not db_path.is_file():
                continue
            try:
                rows = parser(db_path)
            except (HindsightError, sqlite3.Error) as exc:
                store.add_artifact(Artifact(
                    collector="hindsight",
                    category="browser",
                    subject=f"hindsight:{prof.name}:{kind}:error",
                    data={"profile": str(prof), "kind": kind,
                          "error": repr(exc)},
                ))
                continue
            if rows:
                store.add_artifact(Artifact(
                    collector="hindsight",
                    category="browser",
                    subject=f"hindsight:{prof.name}:{kind}",
                    data={"profile": str(prof), "kind": kind,
                          "count": len(rows), "rows": rows},
                ))
                rows_emitted += len(rows)

    return {
        "proceeded": True,
        "reason": opt_in_reason,
        "profiles": len(profile_list),
        "rows_emitted": rows_emitted,
        "include": requested,
    }
