"""Browser forensics: history, downloads, extensions, service workers.

Best-effort cross-browser. Reads SQLite history DBs read-only via ``mode=ro``
URI so we never lock the browser's live DB. Skips locked DBs gracefully.

Service-worker storage gets its own pass because the persistent-fetch / Cache
API bug (https://issues.chromium.org/issues/40062121, disclosed summer 2022
and never fixed) lets a registered worker keep phoning home long after the
page that installed it was closed. We extract installed-worker origins,
script counts, and total storage size so the detector can flag (a) unusually
large SW storage, (b) workers from low-reputation origins, and (c) workers
whose origin is no longer in the user's recent history.
"""

from __future__ import annotations

import glob
import os
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Iterable

from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS, current_os


def _strings_origins(paths: list[Path], limit: int = 200) -> list[str]:
    """Extract https?:// origins from binary LevelDB files.

    Chrome's service-worker registry lives in LevelDB; we don't ship a
    LevelDB parser, but the origin strings appear verbatim in the .log and
    .ldb files. ``strings(1)`` is available everywhere we care about.
    """
    if not paths:
        return []
    cmd = ["strings"]
    if not any(os.access(d, os.X_OK)
               for d in ("/usr/bin/strings", "/usr/local/bin/strings",
                          "/opt/homebrew/bin/strings")):
        return []
    try:
        out = subprocess.run(
            cmd + [str(p) for p in paths],
            capture_output=True, text=True, timeout=15, check=False,
        ).stdout or ""
    except (subprocess.SubprocessError, OSError):
        return ""
    seen: set[str] = set()
    for m in re.finditer(r"https?://[a-zA-Z0-9][a-zA-Z0-9.\-]{1,253}", out):
        seen.add(m.group(0))
        if len(seen) >= limit:
            break
    return sorted(seen)


def _chrome_profile_dirs() -> list[Path]:
    home = Path.home()
    candidates: list[Path] = []
    os_ = current_os()
    if os_ == OS.WINDOWS:
        local = os.environ.get("LOCALAPPDATA", str(home / "AppData/Local"))
        roaming = os.environ.get("APPDATA", str(home / "AppData/Roaming"))
        candidates += [
            Path(local) / "Google/Chrome/User Data",
            Path(local) / "Microsoft/Edge/User Data",
            Path(local) / "BraveSoftware/Brave-Browser/User Data",
            Path(local) / "Chromium/User Data",
            Path(local) / "Vivaldi/User Data",
            Path(roaming) / "Opera Software/Opera Stable",
        ]
    elif os_ == OS.MACOS:
        lib = home / "Library/Application Support"
        candidates += [
            lib / "Google/Chrome",
            lib / "Microsoft Edge",
            lib / "BraveSoftware/Brave-Browser",
            lib / "Chromium",
            lib / "Vivaldi",
            lib / "Arc/User Data",
        ]
    elif os_ == OS.LINUX:
        cfg = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        candidates += [
            cfg / "google-chrome",
            cfg / "chromium",
            cfg / "microsoft-edge",
            cfg / "BraveSoftware/Brave-Browser",
            cfg / "vivaldi",
        ]
    profiles: list[Path] = []
    for root in candidates:
        if not root.is_dir():
            continue
        for sub in root.iterdir():
            if sub.is_dir() and (sub / "History").exists():
                profiles.append(sub)
    return profiles


def _firefox_profile_dirs() -> list[Path]:
    home = Path.home()
    os_ = current_os()
    if os_ == OS.WINDOWS:
        root = Path(os.environ.get("APPDATA", str(home / "AppData/Roaming"))) / "Mozilla/Firefox/Profiles"
    elif os_ == OS.MACOS:
        root = home / "Library/Application Support/Firefox/Profiles"
    else:
        root = home / ".mozilla/firefox"
    if not root.is_dir():
        return []
    return [p for p in root.iterdir() if p.is_dir() and (p / "places.sqlite").exists()]


def _safe_query(db_path: Path, query: str, limit: int = 5000) -> list[tuple]:
    if not db_path.exists():
        return []
    try:
        uri = f"file:{db_path}?immutable=1&mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
            cur = conn.execute(query)
            return cur.fetchmany(limit)
    except sqlite3.Error:
        return []


class BrowserCollector(Collector):
    name = "browsers"
    category = "browser"
    description = "Chrome/Edge/Brave/Firefox history, downloads, extensions."

    def collect(self) -> Iterable[Artifact]:
        for profile in _chrome_profile_dirs():
            yield from self._chrome_profile(profile)
        for profile in _firefox_profile_dirs():
            yield from self._firefox_profile(profile)

    def _chrome_profile(self, profile: Path) -> Iterable[Artifact]:
        prod = profile.parent.name + "/" + profile.name
        # History
        rows = _safe_query(
            profile / "History",
            "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 5000",
        )
        if rows:
            yield self.make(
                subject=f"chrome.history:{prod}",
                profile=str(profile),
                count=len(rows),
                entries=[{"url": r[0], "title": r[1], "visits": r[2], "last_visit_chrome": r[3]} for r in rows],
            )
        # Downloads
        dl = _safe_query(
            profile / "History",
            "SELECT target_path, tab_url, total_bytes, start_time, end_time, danger_type, "
            "interrupt_reason FROM downloads ORDER BY start_time DESC LIMIT 1000",
        )
        if dl:
            yield self.make(
                subject=f"chrome.downloads:{prod}",
                profile=str(profile),
                count=len(dl),
                entries=[
                    {
                        "target": r[0],
                        "source_url": r[1],
                        "size": r[2],
                        "start": r[3],
                        "end": r[4],
                        "danger_type": r[5],
                        "interrupt_reason": r[6],
                    }
                    for r in dl
                ],
            )
        # Extensions
        ext_dir = profile / "Extensions"
        if ext_dir.is_dir():
            extensions = []
            for ext_id in ext_dir.iterdir():
                if not ext_id.is_dir():
                    continue
                for ver in ext_id.iterdir():
                    manifest = ver / "manifest.json"
                    if manifest.exists():
                        try:
                            import json
                            m = json.loads(manifest.read_text(encoding="utf-8"))
                        except Exception:
                            m = {}
                        extensions.append({
                            "id": ext_id.name,
                            "version": ver.name,
                            "name": m.get("name"),
                            "permissions": m.get("permissions"),
                            "host_permissions": m.get("host_permissions"),
                            "manifest_version": m.get("manifest_version"),
                            "update_url": m.get("update_url"),
                        })
            if extensions:
                yield self.make(
                    subject=f"chrome.extensions:{prod}",
                    profile=str(profile),
                    count=len(extensions),
                    entries=extensions,
                )

        # ---- Cookies: per-domain counts + size totals (no contents) ----
        cookies_db = profile / "Cookies"
        if cookies_db.exists():
            try:
                rows = _safe_query(
                    cookies_db,
                    "SELECT host_key, COUNT(*), SUM(LENGTH(value)) "
                    "FROM cookies GROUP BY host_key "
                    "ORDER BY SUM(LENGTH(value)) DESC LIMIT 500",
                )
            except sqlite3.Error:
                rows = []
            if rows:
                total_count = sum(r[1] for r in rows if r[1] is not None)
                total_bytes = sum(int(r[2] or 0) for r in rows)
                yield self.make(
                    subject=f"chrome.cookies:{prod}",
                    profile=str(profile),
                    domain_count=len(rows),
                    total_cookie_count=total_count,
                    total_value_bytes=total_bytes,
                    domains=[
                        {"host": r[0], "count": r[1],
                         "value_bytes": int(r[2] or 0)}
                        for r in rows
                    ],
                )

        # ---- Saved passwords: COUNT ONLY, never contents ----
        login_db = profile / "Login Data"
        if login_db.exists():
            try:
                rows = _safe_query(
                    login_db,
                    "SELECT COUNT(*), COUNT(DISTINCT signon_realm) FROM logins",
                )
            except sqlite3.Error:
                rows = []
            if rows and rows[0]:
                yield self.make(
                    subject=f"chrome.passwords_summary:{prod}",
                    profile=str(profile),
                    saved_count=rows[0][0] or 0,
                    distinct_realm_count=rows[0][1] or 0,
                )

        # ---- IndexedDB origins (file-system enumeration) ----
        idb_root = profile / "IndexedDB"
        if idb_root.is_dir():
            origins = []
            total_bytes = 0
            for sub in idb_root.iterdir():
                if not sub.is_dir():
                    continue
                size = 0
                try:
                    for p in sub.rglob("*"):
                        if p.is_file():
                            try:
                                size += p.stat().st_size
                            except (OSError, FileNotFoundError):
                                pass
                except (PermissionError, OSError):
                    continue
                total_bytes += size
                # Chrome IndexedDB dir names are like
                # "https_example.com_0.indexeddb.leveldb" — convert back
                # to a URL-shaped string by reversing the underscore mangling.
                origin = sub.name
                if origin.startswith(("https_", "http_")):
                    sch, _, rest = origin.partition("_")
                    host_port = rest.rsplit("_", 1)[0]
                    origin = f"{sch}://{host_port}"
                origins.append({"origin": origin, "bytes": size})
            origins.sort(key=lambda o: -o["bytes"])
            if origins:
                yield self.make(
                    subject=f"chrome.indexeddb:{prod}",
                    profile=str(profile),
                    origin_count=len(origins),
                    total_bytes=total_bytes,
                    origins=origins[:200],
                )

        # ---- Local Storage origins (LevelDB) ----
        ls_root = profile / "Local Storage" / "leveldb"
        if ls_root.is_dir():
            ldb_paths = list(ls_root.glob("*.log")) + list(ls_root.glob("*.ldb"))
            origins = _strings_origins(ldb_paths, limit=500) if ldb_paths else []
            total_bytes = 0
            try:
                for p in ls_root.rglob("*"):
                    if p.is_file():
                        try:
                            total_bytes += p.stat().st_size
                        except (OSError, FileNotFoundError):
                            pass
            except (PermissionError, OSError):
                pass
            if origins or total_bytes:
                yield self.make(
                    subject=f"chrome.local_storage:{prod}",
                    profile=str(profile),
                    origin_count=len(origins),
                    total_bytes=total_bytes,
                    origins=origins,
                )

        # ---- Installed PWAs / Web Apps ----
        webapps = profile / "Web Applications"
        if webapps.is_dir():
            apps = []
            for sub in webapps.iterdir():
                if not sub.is_dir():
                    continue
                manifest = sub / "manifest.json"
                if not manifest.exists():
                    apps.append({"id": sub.name, "name": None,
                                  "start_url": None})
                    continue
                try:
                    import json as _json
                    m = _json.loads(manifest.read_text(encoding="utf-8",
                                                       errors="replace"))
                except Exception:
                    m = {}
                apps.append({
                    "id": sub.name,
                    "name": m.get("name") or m.get("short_name"),
                    "start_url": m.get("start_url"),
                    "scope": m.get("scope"),
                })
            if apps:
                yield self.make(
                    subject=f"chrome.pwas:{prod}",
                    profile=str(profile),
                    count=len(apps),
                    entries=apps,
                )

        # ---- Profile defaults: search engine, homepage, startup behavior ----
        prefs = profile / "Preferences"
        if prefs.exists():
            try:
                import json as _json
                p_data = _json.loads(prefs.read_text(encoding="utf-8",
                                                      errors="replace"))
                default_search = (
                    p_data.get("default_search_provider_data", {})
                    .get("template_url_data", {})
                )
                yield self.make(
                    subject=f"chrome.profile_defaults:{prod}",
                    profile=str(profile),
                    default_search_engine={
                        "short_name": default_search.get("short_name"),
                        "keyword": default_search.get("keyword"),
                        "url": default_search.get("url"),
                    },
                    homepage=p_data.get("homepage"),
                    show_home_button=p_data.get("browser", {})
                        .get("show_home_button"),
                    restore_on_startup=p_data.get("session", {})
                        .get("restore_on_startup"),
                    startup_urls=p_data.get("session", {})
                        .get("startup_urls"),
                    safe_browsing_enabled=p_data.get("safebrowsing", {})
                        .get("enabled"),
                )
            except Exception:
                pass

        # Service workers — see module docstring for the threat model.
        sw_root = profile / "Service Worker"
        if sw_root.is_dir():
            db_dir = sw_root / "Database"
            scripts_dir = sw_root / "ScriptCache"
            cache_dir = sw_root / "CacheStorage"
            ldb_paths: list[Path] = []
            if db_dir.is_dir():
                for ext in ("*.log", "*.ldb"):
                    ldb_paths.extend(db_dir.glob(ext))
            origins = _strings_origins(ldb_paths)
            script_count = (
                sum(1 for _ in scripts_dir.rglob("*") if _.is_file())
                if scripts_dir.is_dir() else 0
            )
            cache_bytes = 0
            for d in (sw_root,):
                for p in d.rglob("*"):
                    try:
                        if p.is_file():
                            cache_bytes += p.stat().st_size
                    except (PermissionError, OSError, FileNotFoundError):
                        continue
            if origins or script_count or cache_bytes:
                yield self.make(
                    subject=f"chrome.service_workers:{prod}",
                    profile=str(profile),
                    origins=origins,
                    origin_count=len(origins),
                    script_count=script_count,
                    storage_bytes=cache_bytes,
                    db_path=str(db_dir) if db_dir.is_dir() else "",
                )

    def _firefox_profile(self, profile: Path) -> Iterable[Artifact]:
        rows = _safe_query(
            profile / "places.sqlite",
            "SELECT url, title, visit_count, last_visit_date FROM moz_places "
            "ORDER BY last_visit_date DESC LIMIT 5000",
        )
        if rows:
            yield self.make(
                subject=f"firefox.history:{profile.name}",
                profile=str(profile),
                count=len(rows),
                entries=[{"url": r[0], "title": r[1], "visits": r[2], "last_visit_ff": r[3]} for r in rows],
            )
        ext_json = profile / "extensions.json"
        if ext_json.exists():
            try:
                import json
                data = json.loads(ext_json.read_text(encoding="utf-8"))
                addons = data.get("addons", [])
                yield self.make(
                    subject=f"firefox.extensions:{profile.name}",
                    profile=str(profile),
                    count=len(addons),
                    entries=[
                        {
                            "id": a.get("id"),
                            "name": a.get("defaultLocale", {}).get("name"),
                            "version": a.get("version"),
                            "active": a.get("active"),
                            "sourceURI": a.get("sourceURI"),
                            "installDate": a.get("installDate"),
                        }
                        for a in addons
                    ],
                )
            except Exception:
                pass
