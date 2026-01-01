"""Threat-intel feed registry and downloader.

Each `Feed` has:
    name         identifier — also the cache filename stem
    url          authoritative source
    interval     recommended refresh interval (seconds)
    parser       callable(raw_bytes) -> JSON-serializable normalized record
                 (or None to store raw)
    description  what this feed is

The cache lives under ``$DIGGER_INTEL_DIR`` or ``~/.cache/digger/intel``.
Every cache file has a ``.meta.json`` sidecar with the etag/last-modified/
fetched-at metadata so subsequent fetches are conditional.

Polling is opportunistic and resilient: a failed feed is logged, never
fatal. Detectors degrade gracefully to bundled snapshots in
``digger/rules/`` when the cache is empty.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import requests

_USER_AGENT = "digger-forensics/0.1 (+local-only; reports false-positives via github issues)"


def intel_dir() -> Path:
    raw = os.environ.get("DIGGER_INTEL_DIR")
    if raw:
        d = Path(raw)
    else:
        d = Path.home() / ".cache" / "digger" / "intel"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---- Parsers --------------------------------------------------------------- #


def parse_kev(raw: bytes) -> dict[str, Any]:
    data = json.loads(raw)
    entries = []
    for v in data.get("vulnerabilities", []):
        entries.append({
            "cve": v.get("cveID"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "vulnerability": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "known_ransomware": v.get("knownRansomwareCampaignUse"),
            "summary": v.get("shortDescription"),
            "notes": v.get("notes"),
        })
    return {
        "source": "cisa-kev",
        "catalog_version": data.get("catalogVersion"),
        "date_released": data.get("dateReleased"),
        "count": data.get("count") or len(entries),
        "entries": entries,
    }


def parse_urlhaus_csv(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    rows = []
    reader = csv.reader(
        [line for line in text.splitlines() if line and not line.startswith("#")],
        quotechar='"',
    )
    for row in reader:
        if len(row) < 9:
            continue
        rows.append({
            "id": row[0],
            "date_added": row[1],
            "url": row[2],
            "url_status": row[3],
            "last_online": row[4],
            "threat": row[5],
            "tags": row[6],
            "urlhaus_link": row[7],
            "reporter": row[8],
        })
    return {"source": "urlhaus", "count": len(rows), "entries": rows}


def parse_malwarebazaar_csv(raw: bytes) -> dict[str, Any]:
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="replace")
    rows = []
    reader = csv.reader(
        [line for line in text.splitlines() if line and not line.startswith("#")],
        quotechar='"',
    )
    for row in reader:
        if len(row) < 13:
            continue
        rows.append({
            "first_seen": row[0],
            "sha256": row[1],
            "md5": row[2],
            "sha1": row[3],
            "reporter": row[4],
            "file_name": row[5],
            "file_type_guess": row[6],
            "mime_type": row[7],
            "signature": row[8],
            "clamav_sig": row[9],
            "vt_pct": row[10],
            "imphash": row[11],
            "ssdeep": row[12],
        })
    return {"source": "malwarebazaar", "count": len(rows), "entries": rows}


def parse_threatfox(raw: bytes) -> dict[str, Any]:
    data = json.loads(raw)
    rows = []
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("data") or []
    return {"source": "threatfox", "count": len(rows), "entries": rows}


def parse_lines(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    lines = [
        l.strip() for l in text.splitlines()
        if l.strip() and not l.strip().startswith("#") and not l.strip().startswith(";")
    ]
    return {"count": len(lines), "entries": lines}


def parse_spamhaus(raw: bytes) -> dict[str, Any]:
    """Spamhaus DROP / EDROP — entries like `1.2.3.0/24 ; SBL123`."""
    text = raw.decode("utf-8", errors="replace")
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = [p.strip() for p in line.split(";", 1)]
        cidr = parts[0]
        ref = parts[1] if len(parts) > 1 else ""
        entries.append({"cidr": cidr, "ref": ref})
    return {"count": len(entries), "entries": entries}


def parse_github_advisories(raw: bytes) -> dict[str, Any]:
    data = json.loads(raw)
    rows = data if isinstance(data, list) else data.get("advisories", [])
    return {"source": "github-advisories", "count": len(rows), "entries": rows}


# ---- Feed registry --------------------------------------------------------- #


@dataclass
class Feed:
    name: str
    url: str
    interval: int                   # seconds between polls
    parser: Optional[Callable[[bytes], dict[str, Any]]] = None
    description: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    # Composite-feed hook: when set, overrides the single-URL fetch path.
    # ``fetch_fn`` is responsible for any HTTP it does (it must call
    # ``assert_network_allowed`` if it makes its own requests). It returns
    # raw bytes that the regular ``parser`` then sees.
    fetch_fn: Optional[Callable[[], bytes]] = None

    @property
    def cache_path(self) -> Path:
        return intel_dir() / f"{self.name}.json"

    @property
    def raw_path(self) -> Path:
        return intel_dir() / f"{self.name}.raw"

    @property
    def meta_path(self) -> Path:
        return intel_dir() / f"{self.name}.meta.json"


FEEDS: list[Feed] = [
    Feed(
        name="cisa_kev",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        interval=24 * 3600,
        parser=parse_kev,
        description="CISA Known Exploited Vulnerabilities catalog.",
    ),
    Feed(
        name="urlhaus_recent",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        interval=15 * 60,
        parser=parse_urlhaus_csv,
        description="abuse.ch URLhaus — recently observed malware URLs.",
    ),
    Feed(
        name="malwarebazaar_recent",
        url="https://bazaar.abuse.ch/export/csv/recent/",
        interval=15 * 60,
        parser=parse_malwarebazaar_csv,
        description="abuse.ch MalwareBazaar — recent malware-sample hashes.",
    ),
    Feed(
        name="threatfox_recent",
        url="https://threatfox.abuse.ch/export/json/recent/",
        interval=15 * 60,
        parser=parse_threatfox,
        description="abuse.ch ThreatFox — fresh IOCs (IPs, domains, URLs, hashes).",
    ),
    Feed(
        name="tor_exit_list",
        url="https://check.torproject.org/torbulkexitlist",
        interval=3600,
        parser=parse_lines,
        description="Tor Project bulk exit-node list.",
    ),
    Feed(
        name="spamhaus_drop",
        url="https://www.spamhaus.org/drop/drop.txt",
        interval=12 * 3600,
        parser=parse_spamhaus,
        description="Spamhaus DROP — directly-allocated IP space hijacked by criminals.",
    ),
    Feed(
        name="spamhaus_edrop",
        url="https://www.spamhaus.org/drop/edrop.txt",
        interval=12 * 3600,
        parser=parse_spamhaus,
        description="Spamhaus EDROP — extended DROP (sub-allocations).",
    ),
    Feed(
        name="emerging_threats_compromised",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        interval=6 * 3600,
        parser=parse_lines,
        description="Emerging Threats compromised-IPs blocklist.",
    ),
    Feed(
        name="openssf_malicious_packages",
        url="https://github.com/ossf/malicious-packages/raw/main/osv/all.json",
        interval=12 * 3600,
        parser=lambda raw: {"source": "openssf", "raw": json.loads(raw)},
        description="OpenSSF malicious-packages dataset (OSV format).",
    ),
    Feed(
        name="shai_hulud_packages",
        # Aikido publishes a refreshed package list on Github; URL configurable
        # via env so users can point to mirrors.
        url=os.environ.get(
            "DIGGER_SHAI_HULUD_URL",
            "https://raw.githubusercontent.com/aikidosec/shai-hulud-iocs/main/iocs.json",
        ),
        interval=3600,
        parser=lambda raw: __import__(
            "digger.intel.sources.shai_hulud", fromlist=["parse_iocs"]
        ).parse_iocs(raw),
        description="Shai-Hulud worm IOCs: compromised packages + marker tiers "
                    "+ exfil URLs + worm workflow filename (Aikido / community).",
    ),
    Feed(
        name="github_advisory_npm",
        url="https://api.github.com/advisories?ecosystem=npm&per_page=100",
        interval=3 * 3600,
        parser=parse_github_advisories,
        description="GitHub Advisory Database — npm ecosystem.",
        headers={"Accept": "application/vnd.github+json"},
    ),
    Feed(
        name="github_advisory_pip",
        url="https://api.github.com/advisories?ecosystem=pip&per_page=100",
        interval=3 * 3600,
        parser=parse_github_advisories,
        description="GitHub Advisory Database — PyPI ecosystem.",
        headers={"Accept": "application/vnd.github+json"},
    ),
    # Composite feed: paginates NVD API 2.0 across ~30 CPEs to maintain
    # an up-to-date service-version → CVE corpus. Polled every 24h.
    Feed(
        name="nvd_service_cves",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        interval=24 * 3600,
        parser=lambda raw: __import__(
            "digger.intel.sources.nvd_cpe", fromlist=["parse_feed_payload"]
        ).parse_feed_payload(raw),
        fetch_fn=lambda: __import__(
            "digger.intel.sources.nvd_cpe", fromlist=["fetch_as_feed_bytes"]
        ).fetch_as_feed_bytes(),
        description="NVD CPE-keyed CVE corpus for installed services.",
    ),
    # Composite feed: pulls the SigmaHQ rule corpus (a curated slice — see
    # digger/intel/sources/sigma_corpus.py for the keep-rule filter) into
    # the cache so the existing SigmaLoader / SigmaDetector picks them up.
    # 24h cadence is plenty — SigmaHQ ships rules weekly at most.
    Feed(
        name="sigmahq_corpus",
        url="https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master",
        interval=24 * 3600,
        parser=lambda raw: __import__(
            "digger.intel.sources.sigma_corpus", fromlist=["parse_feed_payload"]
        ).parse_feed_payload(raw),
        fetch_fn=lambda: __import__(
            "digger.intel.sources.sigma_corpus", fromlist=["fetch_as_feed_bytes"]
        ).fetch_as_feed_bytes(),
        description="SigmaHQ community detection rules (C2 / cred-access / "
                    "lateral / persistence subset).",
    ),
    # MITRE ATT&CK Enterprise STIX 2.1 — actors / software / techniques.
    # ATT&CK ships ~quarterly major, monthly minor; weekly poll is plenty.
    Feed(
        name="mitre_attack_groups",
        url="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        interval=7 * 24 * 3600,
        parser=lambda raw: __import__(
            "digger.intel.sources.mitre_attack", fromlist=["parse_feed_payload"]
        ).parse_feed_payload(raw),
        fetch_fn=lambda: __import__(
            "digger.intel.sources.mitre_attack", fromlist=["fetch_as_feed_bytes"]
        ).fetch_as_feed_bytes(),
        description="MITRE ATT&CK Enterprise — groups, associated software, techniques.",
    ),
]


# ---- Update mechanics ------------------------------------------------------ #


def _read_meta(feed: Feed) -> dict[str, Any]:
    if feed.meta_path.exists():
        try:
            return json.loads(feed.meta_path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _write_meta(feed: Feed, meta: dict[str, Any]) -> None:
    feed.meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def update_feed(feed: Feed, force: bool = False) -> dict[str, Any]:
    """Fetch `feed`, store the cache, return the status dict."""
    # Opsec air-gap gate — refuses outbound HTTP when in air-gap mode.
    from digger.opsec.airgap import assert_network_allowed
    assert_network_allowed(f"intel-feed:{feed.name}")
    meta = _read_meta(feed)
    now = time.time()
    last = meta.get("fetched_at", 0)
    if not force and (now - last) < feed.interval and feed.cache_path.exists():
        return {"feed": feed.name, "status": "fresh", "skipped": True, "age_s": now - last}

    # Composite-feed path: custom fetcher returns raw bytes directly.
    if feed.fetch_fn is not None:
        try:
            raw = feed.fetch_fn()
        except Exception as exc:
            return {"feed": feed.name, "status": "error", "error": str(exc)}
        if not raw:
            return {"feed": feed.name, "status": "error", "error": "fetch_fn returned no data"}
        feed.raw_path.write_bytes(raw)
        try:
            parsed = feed.parser(raw) if feed.parser is not None else {
                "raw": raw.decode("utf-8", errors="replace")
            }
        except Exception as exc:
            return {"feed": feed.name, "status": "parse-error", "error": str(exc)}
        feed.cache_path.write_text(json.dumps(parsed, default=str), encoding="utf-8")
        new_meta = {
            "feed": feed.name,
            "url": feed.url,
            "fetched_at": now,
            "size": len(raw),
            "http": "composite",
        }
        _write_meta(feed, new_meta)
        return {"feed": feed.name, "status": "updated", **new_meta}

    headers = {
        "User-Agent": _USER_AGENT,
        **feed.headers,
    }
    if meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    if meta.get("last_modified"):
        headers["If-Modified-Since"] = meta["last_modified"]
    if "GITHUB_TOKEN" in os.environ and "api.github.com" in feed.url:
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    try:
        resp = requests.get(feed.url, headers=headers, timeout=60)
    except requests.RequestException as exc:
        return {"feed": feed.name, "status": "error", "error": str(exc)}

    if resp.status_code == 304:
        meta["fetched_at"] = now
        meta["last_status"] = 304
        _write_meta(feed, meta)
        return {"feed": feed.name, "status": "unmodified", "http": 304}

    if resp.status_code != 200:
        return {
            "feed": feed.name,
            "status": "error",
            "http": resp.status_code,
            "body": resp.text[:512],
        }

    raw = resp.content
    feed.raw_path.write_bytes(raw)
    parsed: Any
    if feed.parser is not None:
        try:
            parsed = feed.parser(raw)
        except Exception as exc:
            return {"feed": feed.name, "status": "parse-error", "error": str(exc)}
    else:
        parsed = {"raw": raw.decode("utf-8", errors="replace")}
    feed.cache_path.write_text(json.dumps(parsed, default=str), encoding="utf-8")
    new_meta = {
        "feed": feed.name,
        "url": feed.url,
        "etag": resp.headers.get("ETag"),
        "last_modified": resp.headers.get("Last-Modified"),
        "fetched_at": now,
        "size": len(raw),
        "http": resp.status_code,
    }
    _write_meta(feed, new_meta)
    return {"feed": feed.name, "status": "updated", **new_meta}


def update_all(
    force: bool = False,
    only: Optional[list[str]] = None,
    auto_sign_key: Optional[str] = None,
    sign_alg: str = "ML-DSA-65",
) -> list[dict[str, Any]]:
    """Update every (or named) feed; optionally PQC-sign the cache afterward.

    If ``auto_sign_key`` is None we still look at ``DIGGER_INTEL_SIGN_KEY``
    so a cron job can pick it up from the environment.
    """
    out: list[dict[str, Any]] = []
    for feed in FEEDS:
        if only and feed.name not in only:
            continue
        out.append(update_feed(feed, force=force))

    if auto_sign_key is None:
        env_key = os.environ.get("DIGGER_INTEL_SIGN_KEY")
        if env_key:
            auto_sign_key = env_key
    if auto_sign_key:
        try:
            from digger.intel.integrity import sign_intel
            sig_path = sign_intel(None, secret_key_path=auto_sign_key, algorithm=sign_alg)
            out.append({"feed": "_signature", "status": "signed",
                        "sig_path": str(sig_path), "algorithm": sign_alg})
        except Exception as exc:
            out.append({"feed": "_signature", "status": "sign-error",
                        "error": str(exc)})
    return out


def load_cached(name: str) -> Optional[dict[str, Any]]:
    """Load the parsed cache for a feed, or None if not present."""
    for feed in FEEDS:
        if feed.name == name:
            if feed.cache_path.exists():
                try:
                    return json.loads(feed.cache_path.read_text(encoding="utf-8"))
                except Exception:
                    return None
            return None
    return None


def cache_status() -> list[dict[str, Any]]:
    out = []
    for feed in FEEDS:
        meta = _read_meta(feed)
        age = time.time() - meta.get("fetched_at", 0) if meta else None
        out.append({
            "name": feed.name,
            "url": feed.url,
            "interval_s": feed.interval,
            "fetched_at": meta.get("fetched_at"),
            "age_s": age,
            "stale": (age is None) or (age > feed.interval),
            "size": meta.get("size"),
        })
    return out
