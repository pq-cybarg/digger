"""NVD CPE-keyed CVE fetcher.

Pulls every advisory matching a curated set of vendor:product CPEs from
the National Vulnerability Database API 2.0 and reduces them to the
service → list[CVE] shape that ``ServiceCVEDetector`` consumes.

CPE-keyed matching uses *upstream* version strings, so the data
aligns with what ``ServiceVersionsCollector`` extracts from
``<binary> --version``.

Rate limits:
  - Without API key: 5 requests / 30 seconds
  - With $NVD_API_KEY: 50 requests / 30 seconds

Free key in 30 seconds: https://nvd.nist.gov/developers/request-an-api-key
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# service-key -> [virtualMatchString, ...]
SERVICE_CPES: dict[str, list[str]] = {
    "openssh-server": [
        "cpe:2.3:a:openbsd:openssh",
        "cpe:2.3:a:openssh:openssh",
    ],
    "openssh-client": [
        "cpe:2.3:a:openbsd:openssh",
        "cpe:2.3:a:openssh:openssh",
    ],
    "nginx": [
        "cpe:2.3:a:nginx:nginx",
        "cpe:2.3:a:f5:nginx",
    ],
    "apache-httpd": ["cpe:2.3:a:apache:http_server"],
    "redis": [
        "cpe:2.3:a:redis:redis",
        "cpe:2.3:a:redislabs:redis",
    ],
    "postgresql": ["cpe:2.3:a:postgresql:postgresql"],
    "mysql": [
        "cpe:2.3:a:oracle:mysql",
        "cpe:2.3:a:mysql:mysql",
    ],
    "mariadb": ["cpe:2.3:a:mariadb:mariadb"],
    "mongodb": [
        "cpe:2.3:a:mongodb:mongodb",
        "cpe:2.3:a:mongodb:mongodb_server",
    ],
    "python3": ["cpe:2.3:a:python:python"],
    "nodejs": [
        "cpe:2.3:a:nodejs:node.js",
        "cpe:2.3:a:nodejs:nodejs",
    ],
    "openssl": ["cpe:2.3:a:openssl:openssl"],
    "curl": [
        "cpe:2.3:a:haxx:curl",
        "cpe:2.3:a:haxx:libcurl",
    ],
    "git": [
        "cpe:2.3:a:git-scm:git",
        "cpe:2.3:a:git:git",
    ],
    "docker": [
        "cpe:2.3:a:docker:docker",
        "cpe:2.3:a:docker:engine",
    ],
    "docker-daemon": [
        "cpe:2.3:a:docker:docker",
        "cpe:2.3:a:docker:engine",
    ],
    "php": ["cpe:2.3:a:php:php"],
    "ruby": [
        "cpe:2.3:a:ruby-lang:ruby",
        "cpe:2.3:a:ruby:ruby",
    ],
    "go": ["cpe:2.3:a:golang:go"],
    "rustc": ["cpe:2.3:a:rust-lang:rust"],
    "kubelet": ["cpe:2.3:a:kubernetes:kubernetes"],
    "kubectl": ["cpe:2.3:a:kubernetes:kubernetes"],
    "elasticsearch": [
        "cpe:2.3:a:elastic:elasticsearch",
        "cpe:2.3:a:elasticsearch:elasticsearch",
    ],
    "memcached": ["cpe:2.3:a:memcached:memcached"],
    "haproxy": ["cpe:2.3:a:haproxy:haproxy"],
    "samba": ["cpe:2.3:a:samba:samba"],
    "bind9": ["cpe:2.3:a:isc:bind"],
    "powerdns": [
        "cpe:2.3:a:powerdns:authoritative",
        "cpe:2.3:a:powerdns:recursor",
    ],
    "varnish": [
        "cpe:2.3:a:varnish-cache:varnish",
        "cpe:2.3:a:varnish_cache_project:varnish_cache",
    ],
    "squid": [
        "cpe:2.3:a:squid-cache:squid",
        "cpe:2.3:a:squid:squid",
    ],
    "rabbitmq": [
        "cpe:2.3:a:rabbitmq:rabbitmq",
        "cpe:2.3:a:vmware:rabbitmq",
    ],
}


def _api_key() -> str | None:
    return os.environ.get("NVD_API_KEY") or None


def _sleep_quota(api_key: str | None) -> float:
    return 0.7 if api_key else 6.5


def _get_page(virtual: str, start: int, page: int,
              api_key: str | None) -> dict | None:
    """One paginated GET with retry/backoff for 429/5xx."""
    headers = {"apiKey": api_key} if api_key else {}
    params = {
        "virtualMatchString": virtual,
        "resultsPerPage": page,
        "startIndex": start,
    }
    delay = _sleep_quota(api_key) * 1.2
    for attempt in range(5):
        try:
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
        except requests.RequestException as exc:
            print(f"  [nvd] {virtual} GET error: {exc}; backing off",
                  file=sys.stderr)
            time.sleep(delay)
            delay *= 1.5
            continue
        if r.status_code == 200:
            return r.json()
        if r.status_code in (429, 502, 503, 504):
            print(f"  [nvd] {virtual} HTTP {r.status_code}; backoff {delay:.1f}s",
                  file=sys.stderr)
            time.sleep(delay)
            delay *= 1.5
            continue
        print(f"  [nvd] {virtual} HTTP {r.status_code}: {r.text[:200]}",
              file=sys.stderr)
        return None
    return None


def _fetch_cves_for_cpe(virtual: str, api_key: str | None) -> list[dict]:
    out: list[dict] = []
    start = 0
    page = 2000  # NVD max
    while True:
        data = _get_page(virtual, start, page, api_key)
        if not data:
            break
        for item in data.get("vulnerabilities") or []:
            cve = item.get("cve")
            if cve:
                out.append(cve)
        total = int(data.get("totalResults", 0))
        start += page
        time.sleep(_sleep_quota(api_key))
        if start >= total:
            break
    return out


def _cvss_to_severity(metrics: dict) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr:
            continue
        try:
            score = float(arr[0]["cvssData"]["baseScore"])
            if score >= 9: return "critical"
            if score >= 7: return "high"
            if score >= 4: return "medium"
            if score > 0: return "low"
        except (KeyError, ValueError, TypeError):
            continue
    return "medium"


def _extract_summary(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            s = (d.get("value") or "").replace("\n", " ").strip()
            return s[:217] + "..." if len(s) > 220 else s
    return ""


def _extract_refs(cve: dict, cap: int = 6) -> list[str]:
    out: list[str] = []
    for ref in cve.get("references") or []:
        u = ref.get("url")
        if u and u not in out:
            out.append(u)
        if len(out) >= cap:
            break
    return out


def _extract_ranges(cve: dict, product: str) -> list[dict]:
    ranges: list[dict] = []
    seen: set = set()
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                crit = (m.get("criteria") or "").lower()
                if product.lower() not in crit:
                    continue
                introduced = (m.get("versionStartIncluding")
                              or m.get("versionStartExcluding")
                              or "0")
                fixed = m.get("versionEndExcluding")
                last_affected = m.get("versionEndIncluding")
                if (not fixed and not last_affected
                        and (m.get("versionStartIncluding")
                             or m.get("versionStartExcluding"))):
                    last_affected = introduced
                if not fixed and not last_affected:
                    parts = crit.split(":")
                    if len(parts) >= 6:
                        v = parts[5]
                        if v not in ("*", "-", "", "any"):
                            introduced = v
                            last_affected = v
                r: dict = {"introduced": introduced}
                if fixed:
                    r["fixed"] = fixed
                if last_affected:
                    r["last_affected"] = last_affected
                if r["introduced"] == "0" and not fixed and not last_affected:
                    continue
                key = tuple(sorted(r.items()))
                if key not in seen:
                    ranges.append(r)
                    seen.add(key)
    return ranges


def _product_from_cpe(virtual: str) -> str:
    parts = virtual.split(":")
    return parts[4] if len(parts) >= 5 else virtual


def collect_service_cves(only: set[str] | None = None,
                         api_key: str | None = None,
                         progress=None) -> dict[str, list[dict]]:
    """Pull NVD entries for every (service, CPE) pair in ``SERVICE_CPES``.

    Returns ``{service_name: [cve_entry, ...]}``. ``cve_entry`` has the
    schema ServiceCVEDetector expects (id, severity, summary, affected,
    references).
    """
    api_key = api_key or _api_key()
    corpus: dict[str, list[dict]] = {}
    for service, cpes in SERVICE_CPES.items():
        if only and service not in only:
            continue
        if progress:
            progress(f"  [nvd] {service}  ({len(cpes)} CPEs)")
        by_id: dict[str, dict] = {}
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        for v in cpes:
            product = _product_from_cpe(v)
            for cve in _fetch_cves_for_cpe(v, api_key):
                cve_id = cve.get("id") or ""
                if not cve_id.startswith("CVE-"):
                    continue
                ranges = _extract_ranges(cve, product)
                if not ranges:
                    continue
                entry = by_id.get(cve_id)
                if entry is None:
                    entry = {
                        "id": cve_id,
                        "severity": _cvss_to_severity(cve.get("metrics") or {}),
                        "summary": _extract_summary(cve),
                        "affected": [],
                        "references": _extract_refs(cve),
                    }
                    by_id[cve_id] = entry
                existing = {tuple(sorted(r.items())) for r in entry["affected"]}
                for r in ranges:
                    key = tuple(sorted(r.items()))
                    if key not in existing:
                        entry["affected"].append(r)
                        existing.add(key)
                new_sev = _cvss_to_severity(cve.get("metrics") or {})
                if order.get(new_sev, 2) > order.get(entry["severity"], 2):
                    entry["severity"] = new_sev
        entries = sorted(by_id.values(), key=lambda e: e["id"], reverse=True)
        if entries:
            corpus[service] = entries
        if progress:
            progress(f"     -> {len(entries)} CVEs")
    return corpus


def fetch_as_feed_bytes() -> bytes:
    """The shape the IntelFeed system expects: raw bytes that the parser
    will then JSON-decode. We package the full corpus in our schema.

    Honors air-gap mode by deferring to ``assert_network_allowed`` per
    HTTP request inside ``_fetch_cves_for_cpe``? Actually we call it
    explicitly here so the very first call is guarded.
    """
    from digger.opsec.airgap import assert_network_allowed
    assert_network_allowed("intel-feed:nvd_service_cves")
    corpus = collect_service_cves(
        progress=lambda msg: print(msg, file=sys.stderr),
    )
    return json.dumps({
        "source": "nvd",
        "generated_at": time.time(),
        "service_count": len(corpus),
        "cve_count": sum(len(v) for v in corpus.values()),
        "services": corpus,
    }, default=str).encode("utf-8")


def parse_feed_payload(raw: bytes) -> dict[str, Any]:
    """Parse the bytes ``fetch_as_feed_bytes`` produces back to a dict."""
    return json.loads(raw)
