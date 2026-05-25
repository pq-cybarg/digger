"""Hindsight opt-in deep Chromium parser tests."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys

import pytest

from digger.core.evidence import EvidenceStore
from digger.hindsight.parser import (
    DEFAULT_INCLUDE,
    SUPPORTED_INCLUDE,
    HindsightError,
    _check_opt_in,
    _chrome_ts,
    parse_bookmarks,
    parse_cookies,
    parse_downloads,
    parse_history,
    parse_logins,
    parse_web_data,
    run_scan,
)


# ---- _chrome_ts ---- #


def test_chrome_ts_none_returns_none():
    assert _chrome_ts(None) is None
    assert _chrome_ts(0) is None


def test_chrome_ts_2024_value():
    """13360716800000000 microseconds = 2024-04-04 00:00:00 UTC ish."""
    out = _chrome_ts(13360716800000000)
    # Just verify it's plausible (≈2024)
    assert 1.6e9 < out < 1.9e9


# ---- opt-in gate ---- #


def test_check_opt_in_requires_deep_flag(monkeypatch):
    monkeypatch.delenv("DIGGER_HINDSIGHT_OK", raising=False)
    with pytest.raises(HindsightError, match="deep parse not requested"):
        _check_opt_in(deep=False)


def test_check_opt_in_requires_env(monkeypatch):
    monkeypatch.delenv("DIGGER_HINDSIGHT_OK", raising=False)
    with pytest.raises(HindsightError, match="environment opt-in missing"):
        _check_opt_in(deep=True)


def test_check_opt_in_passes_with_both(monkeypatch):
    monkeypatch.setenv("DIGGER_HINDSIGHT_OK", "1")
    _check_opt_in(deep=True)  # MUST NOT raise


def test_check_opt_in_env_not_one_rejected(monkeypatch):
    """Only the literal '1' counts — 'true', 'yes', empty all fail."""
    monkeypatch.setenv("DIGGER_HINDSIGHT_OK", "true")
    with pytest.raises(HindsightError):
        _check_opt_in(deep=True)


# ---- parsers (build fake SQLite fixtures) ---- #


def _make_history_db(tmp_path):
    """Build a Chromium-shaped History SQLite for testing."""
    db = tmp_path / "History"
    conn = sqlite3.connect(db)
    conn.executescript("""
      CREATE TABLE urls (
        id INTEGER PRIMARY KEY,
        url TEXT, title TEXT,
        visit_count INTEGER, typed_count INTEGER,
        last_visit_time INTEGER
      );
      CREATE TABLE downloads (
        id INTEGER PRIMARY KEY,
        current_path TEXT, target_path TEXT,
        start_time INTEGER,
        total_bytes INTEGER, received_bytes INTEGER,
        state INTEGER, tab_url TEXT
      );
      INSERT INTO urls VALUES
        (1, 'https://example.com', 'Example', 12, 3, 13360716800000000),
        (2, 'https://news.ycombinator.com', 'HN', 99, 50, 13360716900000000);
      INSERT INTO downloads VALUES
        (1, '/tmp/foo.zip.crdownload', '/tmp/foo.zip',
         13360716800000000, 1024, 1024, 1, 'https://dl.example.com/foo.zip');
    """)
    conn.commit()
    conn.close()
    return db


def test_parse_history_returns_rows(tmp_path):
    db = _make_history_db(tmp_path)
    rows = parse_history(db)
    assert len(rows) == 2
    # Sorted by last_visit_time DESC → HN first
    assert rows[0]["url"] == "https://news.ycombinator.com"
    assert rows[0]["title"] == "HN"
    assert rows[0]["visit_count"] == 99
    assert rows[0]["last_visit_ts"] > 1.6e9


def test_parse_history_missing_db_raises(tmp_path):
    with pytest.raises(HindsightError, match="db not found"):
        parse_history(tmp_path / "doesnotexist")


def test_parse_history_handles_missing_urls_table(tmp_path):
    db = tmp_path / "History"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE unrelated (x INTEGER)")
    conn.commit()
    conn.close()
    assert parse_history(db) == []


def test_parse_downloads_returns_rows(tmp_path):
    db = _make_history_db(tmp_path)
    rows = parse_downloads(db)
    assert len(rows) == 1
    assert rows[0]["target_path"] == "/tmp/foo.zip"
    assert rows[0]["source_url"] == "https://dl.example.com/foo.zip"
    assert rows[0]["total_bytes"] == 1024


def _make_cookies_db(tmp_path):
    db = tmp_path / "Cookies"
    conn = sqlite3.connect(db)
    conn.executescript("""
      CREATE TABLE cookies (
        creation_utc INTEGER,
        host_key TEXT, name TEXT, path TEXT,
        value TEXT, encrypted_value BLOB,
        expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER
      );
    """)
    # Plaintext-value cookie + encrypted-value cookie
    conn.execute(
        "INSERT INTO cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (13360716800000000, "example.com", "session", "/",
         "PLAINTEXT_SID", None, 13380000000000000, 1, 1),
    )
    conn.execute(
        "INSERT INTO cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (13360716900000000, "google.com", "_ga", "/",
         "", b"v10" + b"\xab" * 60, 13380000000000000, 1, 0),
    )
    conn.commit()
    conn.close()
    return db


def test_parse_cookies_records_length_not_value(tmp_path):
    db = _make_cookies_db(tmp_path)
    rows = parse_cookies(db)
    assert len(rows) == 2
    # Sorted by creation_utc DESC → google.com first
    g = rows[0]
    assert g["host"] == "google.com"
    assert g["encrypted_value_len"] == 63
    # No plaintext value should appear anywhere
    for k, v in g.items():
        if isinstance(v, str):
            assert "PLAINTEXT_SID" not in v
            assert "\xab" not in v
    # Encrypted prefix recorded as hex
    assert g["encrypted_prefix_hex"].startswith("763130")  # "v10" hex
    # plaintext cookie also recorded (length)
    e = rows[1]
    assert e["host"] == "example.com"
    assert e["plaintext_value_len"] == len("PLAINTEXT_SID")


def _make_logins_db(tmp_path):
    db = tmp_path / "Login Data"
    conn = sqlite3.connect(db)
    conn.executescript("""
      CREATE TABLE logins (
        origin_url TEXT, action_url TEXT,
        username_element TEXT, username_value TEXT,
        password_element TEXT, password_value BLOB,
        date_created INTEGER, times_used INTEGER,
        date_last_used INTEGER
      );
    """)
    conn.execute(
        "INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("https://github.com/login", "https://github.com/session",
         "login", "testuser",
         "password", b"v10" + b"\x42" * 32,
         13360716800000000, 5, 13360716900000000),
    )
    conn.commit()
    conn.close()
    return db


def test_parse_logins_never_returns_password_plaintext(tmp_path):
    db = _make_logins_db(tmp_path)
    rows = parse_logins(db)
    assert len(rows) == 1
    r = rows[0]
    assert r["origin_url"] == "https://github.com/login"
    assert r["username_value"] == "testuser"
    assert r["password_value_len"] == 35  # b"v10" + 32 bytes
    # NO password plaintext anywhere
    for k, v in r.items():
        if isinstance(v, str):
            assert "\x42" not in v
    assert r["password_prefix_hex"].startswith("763130")  # "v10"
    assert r["times_used"] == 5


def test_parse_logins_handles_missing_table(tmp_path):
    db = tmp_path / "Login Data"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE other (x INT)")
    conn.commit()
    conn.close()
    assert parse_logins(db) == []


def _make_web_data_db(tmp_path):
    db = tmp_path / "Web Data"
    conn = sqlite3.connect(db)
    conn.executescript("""
      CREATE TABLE credit_cards (
        guid TEXT, name_on_card TEXT,
        expiration_month INTEGER, expiration_year INTEGER,
        card_number_encrypted BLOB
      );
      CREATE TABLE addresses (
        guid TEXT, street_address TEXT
      );
    """)
    conn.execute(
        "INSERT INTO credit_cards VALUES (?, ?, ?, ?, ?)",
        ("g1", "F. Shooster", 12, 2030, b"\x00" * 64),
    )
    conn.execute("INSERT INTO addresses VALUES (?, ?)",
                  ("g2", "Some street"))
    conn.commit()
    conn.close()
    return db


def test_parse_web_data_records_blob_lengths_only(tmp_path):
    db = _make_web_data_db(tmp_path)
    rows = parse_web_data(db)
    assert len(rows) == 2
    cc = next(r for r in rows if r["kind"] == "credit_card")
    assert cc["name_on_card"] == "F. Shooster"
    assert cc["encrypted_pan_len"] == 64
    assert "card_number_plaintext" not in cc
    ad = next(r for r in rows if r["kind"] == "address")
    assert ad["street_address_len"] == len("Some street")


def test_parse_bookmarks_walks_tree(tmp_path):
    bm = tmp_path / "Bookmarks"
    bm.write_text(json.dumps({
        "roots": {
            "bookmark_bar": {
                "type": "folder",
                "name": "Bookmarks Bar",
                "children": [
                    {"type": "url", "name": "Example",
                     "url": "https://example.com",
                     "date_added": "13360716800000000"},
                    {"type": "folder", "name": "Dev",
                     "children": [
                         {"type": "url", "name": "GitHub",
                          "url": "https://github.com",
                          "date_added": "13360716900000000"},
                     ]},
                ],
            },
            "other": {"type": "folder", "name": "Other", "children": []},
        },
    }))
    out = parse_bookmarks(bm)
    assert len(out) == 2
    by_name = {o["name"]: o for o in out}
    assert by_name["Example"]["url"] == "https://example.com"
    assert by_name["GitHub"]["folder"] == "bookmark_bar/Bookmarks Bar/Dev"
    assert by_name["GitHub"]["date_added_ts"] > 1.6e9


def test_parse_bookmarks_missing_file_returns_empty(tmp_path):
    assert parse_bookmarks(tmp_path / "no-such-file") == []


def test_parse_bookmarks_malformed_json_returns_empty(tmp_path):
    bm = tmp_path / "Bookmarks"
    bm.write_text("not json")
    assert parse_bookmarks(bm) == []


# ---- run_scan with opt-in checks ---- #


def test_run_scan_without_deep_emits_skipped_stub(tmp_path, monkeypatch):
    monkeypatch.delenv("DIGGER_HINDSIGHT_OK", raising=False)
    store = EvidenceStore(tmp_path)
    summary = run_scan(store, deep=False)
    assert summary["proceeded"] is False
    assert "deep parse not requested" in summary["reason"]
    arts = list(store.iter_artifacts(collector="hindsight"))
    # The audit stub is still emitted — operator declined is part of
    # the audit trail
    assert len(arts) == 1
    assert arts[0]["data"]["proceeding"] is False
    store.close()


def test_run_scan_without_env_emits_skipped_stub(tmp_path, monkeypatch):
    monkeypatch.delenv("DIGGER_HINDSIGHT_OK", raising=False)
    store = EvidenceStore(tmp_path)
    summary = run_scan(store, deep=True)
    assert summary["proceeded"] is False
    assert "environment opt-in missing" in summary["reason"]
    store.close()


def test_run_scan_rejects_unknown_include(tmp_path):
    store = EvidenceStore(tmp_path)
    try:
        with pytest.raises(HindsightError, match="unknown include"):
            run_scan(store, deep=False, include=["notarealkind"])
    finally:
        store.close()


def test_run_scan_with_both_gates_processes_profile(tmp_path, monkeypatch):
    """Build a fake profile dir + run with deep + env set."""
    monkeypatch.setenv("DIGGER_HINDSIGHT_OK", "1")
    profile = tmp_path / "FakeProfile"
    profile.mkdir()
    _make_history_db(profile)   # creates History
    # Bookmarks file
    (profile / "Bookmarks").write_text(json.dumps({
        "roots": {"bookmark_bar": {
            "type": "folder", "name": "Bar", "children": [
                {"type": "url", "name": "X", "url": "https://x.example",
                 "date_added": "13360716800000000"},
            ],
        }},
    }))
    case = tmp_path / "case"
    store = EvidenceStore(case)
    summary = run_scan(
        store, deep=True, include=("history", "downloads", "bookmarks"),
        profiles=[profile],
    )
    assert summary["proceeded"] is True
    assert summary["profiles"] == 1
    # 2 urls + 1 download + 1 bookmark = 4 rows
    assert summary["rows_emitted"] == 4
    arts = list(store.iter_artifacts(collector="hindsight"))
    # 1 audit stub + 1 history Artifact + 1 downloads Artifact +
    # 1 bookmarks Artifact = 4 artifacts
    assert len(arts) == 4
    by_subject = {a["subject"]: a for a in arts}
    assert any("history" in s for s in by_subject)
    assert any("downloads" in s for s in by_subject)
    assert any("bookmarks" in s for s in by_subject)
    store.close()


def test_run_scan_skips_missing_profile_databases(tmp_path, monkeypatch):
    """A profile dir with no DBs (just exists) shouldn't crash —
    parser silently skips."""
    monkeypatch.setenv("DIGGER_HINDSIGHT_OK", "1")
    empty_profile = tmp_path / "Empty"
    empty_profile.mkdir()
    store = EvidenceStore(tmp_path / "case")
    summary = run_scan(
        store, deep=True,
        include=("history", "cookies"),
        profiles=[empty_profile],
    )
    assert summary["proceeded"] is True
    assert summary["rows_emitted"] == 0
    store.close()


def test_run_scan_default_include_lower_sensitivity(tmp_path, monkeypatch):
    """The default include set should be the lower-sensitivity tables
    (history+downloads+bookmarks), NOT cookies/logins."""
    monkeypatch.setenv("DIGGER_HINDSIGHT_OK", "1")
    store = EvidenceStore(tmp_path / "case")
    summary = run_scan(store, deep=True, profiles=[])
    assert summary["proceeded"] is True
    assert set(summary["include"]) == set(DEFAULT_INCLUDE)
    # Critical: cookies + logins NOT in default
    assert "cookies" not in summary["include"]
    assert "logins" not in summary["include"]
    store.close()


def test_run_scan_handles_cookie_extraction_when_explicitly_included(
    tmp_path, monkeypatch,
):
    """Cookies need explicit opt-in via include="""
    monkeypatch.setenv("DIGGER_HINDSIGHT_OK", "1")
    profile = tmp_path / "CookieProfile"
    profile.mkdir()
    _make_cookies_db(profile)
    store = EvidenceStore(tmp_path / "case")
    summary = run_scan(
        store, deep=True, include=("cookies",),
        profiles=[profile],
    )
    assert summary["rows_emitted"] == 2  # 2 fixture cookies
    arts = list(store.iter_artifacts(collector="hindsight"))
    cookies_art = next(
        a for a in arts if "cookies" in a["subject"]
    )
    # Verify NO plaintext cookie values made it into the Artifact
    full_json = json.dumps(cookies_art["data"], default=str)
    assert "PLAINTEXT_SID" not in full_json   # the fixture's plain value
    store.close()


# ---- CLI smoke ---- #


def test_cli_list_kinds():
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "hindsight", "scan", "--list-kinds"],
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0
    assert "history" in r.stdout
    assert "cookies" in r.stdout
    assert "(default)" in r.stdout
    assert "(explicit)" in r.stdout


def test_cli_scan_without_opt_in_exits_1(tmp_path, monkeypatch):
    """Without --deep-browser-parse and DIGGER_HINDSIGHT_OK, the CLI
    proceeds far enough to emit the audit stub but reports SKIPPED
    with rc=1."""
    import os
    env = {k: v for k, v in os.environ.items()
           if k != "DIGGER_HINDSIGHT_OK"}
    case = tmp_path / "case"
    r = subprocess.run(
        [sys.executable, "-m", "digger", "--no-banner",
         "hindsight", "scan", "--case-dir", str(case)],
        capture_output=True, text=True, timeout=15, env=env,
    )
    assert r.returncode == 1
    assert "SKIPPED" in r.stderr


def test_supported_include_is_what_we_advertise():
    """Tests of the surface area itself — ensures the parser knows
    every kind the CLI / docstring lists."""
    expected = {"history", "downloads", "bookmarks",
                 "cookies", "logins", "autofill", "web_data"}
    assert set(SUPPORTED_INCLUDE) == expected
