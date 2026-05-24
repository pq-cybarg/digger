"""Browser extension + service-worker risk flagger.

Covers two attack surfaces:
  - Extensions with sweeping permissions (longstanding signal)
  - Service workers that may be abusing the persistent-fetch /
    Cache API bug at https://issues.chromium.org/issues/40062121
    (disclosed summer 2022, never fixed by Google). A registered
    worker can keep phoning home long after the page that installed
    it was closed; the detector flags (a) bulk SW storage that has
    grown unusually large, (b) workers whose origin is on the user's
    known-bad / outside-of-browsing-history list, and (c) a baseline
    informational finding that simply records every SW origin so the
    operator can audit.

MITRE: T1176 (Browser Extensions), T1546 (Event-Triggered Execution —
Component Object Model Hijacking analogue for the service-worker case).
"""

from __future__ import annotations

import urllib.parse
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_intel, load_yaml
from digger.detectors.base import Detector

# live-first-ok: bundled hosts are a curated friendly-allowlist, not a
# detection corpus — there's no upstream "safe-host list" feed to mirror.
# The unpatched-Chromium-bug corpus (chromium_unpatched.yaml) is also
# digger-curated; no canonical upstream "vendor-won't-fix browser bugs"
# feed exists. Swap to load_intel when one becomes available.

_RISKY_PERMS = {
    "<all_urls>", "tabs", "webRequest", "webRequestBlocking",
    "cookies", "history", "clipboardRead", "clipboardWrite",
    "downloads", "management", "nativeMessaging", "proxy",
    "debugger", "declarativeNetRequestFeedback",
}

# Heuristic thresholds for service-worker storage.
_SW_STORAGE_LARGE_BYTES = 500 * 1024 * 1024       # 500 MB per profile is excessive
_SW_STORAGE_HUGE_BYTES  = 2 * 1024 * 1024 * 1024  # 2 GB across one profile is alarming
_SW_ORIGIN_COUNT_HIGH    = 60                     # >60 distinct SW origins on one profile

# Additional storage thresholds for IndexedDB / Local Storage / cookies.
_IDB_BLOAT_BYTES         = 200 * 1024 * 1024      # 200 MB single-origin IDB is large
_COOKIE_HIGH_DOMAIN_CNT  = 500                    # 500+ cookie domains = heavy tracking
_PASSWORD_SAVE_HIGH      = 200                    # 200+ saved passwords worth flagging


def _live_bad_origins() -> set[str]:
    """Build the union of bad-host indicators from URLhaus / ThreatFox /
    MalwareBazaar live feeds, normalized to lowercase host strings."""
    out: set[str] = set()
    for fname in ("urlhaus_recent", "threatfox_recent"):
        feed = load_intel(fname)
        if not feed:
            continue
        entries = feed.get("entries") or (feed.get("data") if isinstance(
            feed.get("data"), list) else []) or []
        for e in entries:
            if not isinstance(e, dict):
                continue
            for k in ("url", "host", "domain", "value", "ioc"):
                v = e.get(k)
                if not v or not isinstance(v, str):
                    continue
                h = _host(v) or v.lower().split("/")[0].split(":")[0]
                if h:
                    out.add(h.lower())
    return out


def _matches_bad_origin(origin: str, bad_hosts: set[str]) -> str | None:
    """Return the bad-host needle that matches ``origin``, or None."""
    if not bad_hosts:
        return None
    h = _host(origin)
    if not h:
        return None
    h_low = h.lower()
    if h_low in bad_hosts:
        return h_low
    # Subdomain match: foo.bar.com origin should hit bar.com bad-host entry
    base = _strip_subdomain(h_low)
    if base in bad_hosts:
        return base
    return None

# Common "uncontroversial" service-worker hosts. Anything else gets the
# audit-me treatment via the info-level baseline finding.
_KNOWN_FRIENDLY_SW_HOSTS = {
    # Google Workspace + properties
    "mail.google.com", "calendar.google.com", "docs.google.com",
    "drive.google.com", "meet.google.com", "chat.google.com",
    "www.google.com", "accounts.google.com", "storage.googleapis.com",
    "www.googletagmanager.com", "translate.google.com",
    "photos.google.com",
    # Microsoft 365 + Teams
    "teams.microsoft.com", "office.com", "www.office.com",
    "outlook.live.com", "outlook.office.com", "outlook.office365.com",
    "edge.microsoft.com",
    # Common SaaS the average dev uses
    "app.slack.com", "slack.com",
    "github.com", "githubusercontent.com",
    "gitlab.com", "bitbucket.org",
    "notion.so", "linear.app", "monday.com",
    "atlassian.net", "jira.com",
    "zoom.us",
    "youtube.com", "www.youtube.com", "music.youtube.com",
    "twitter.com", "x.com", "abs.twimg.com",
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "linkedin.com", "www.linkedin.com",
    "reddit.com", "www.reddit.com",
    "adobe.com", "acrobat.adobe.com",
}


def _host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


def _strip_subdomain(host: str) -> str:
    """For matching against the friendly set: drop everything past the
    last two dotted labels (so docs.google.com matches google.com)."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class BrowserDetector(Detector):
    name = "browser"
    description = (
        "Browser extensions with sweeping permissions + service-worker storage "
        "anomalies (https://issues.chromium.org/issues/40062121)."
    )

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        bad_hosts = _live_bad_origins()
        unpatched_corpus = (load_yaml("browsers/chromium_unpatched.yaml")
                            or {}).get("issues", [])

        for art in store.iter_artifacts(category="browser"):
            subj = art["subject"]
            data = art["data"]

            # ---- 1. Risky extensions ----
            if "extensions" in subj:
                for ext in data.get("entries") or []:
                    perms = set(ext.get("permissions") or []) | set(ext.get("host_permissions") or [])
                    hits = perms & _RISKY_PERMS
                    if "<all_urls>" in (ext.get("host_permissions") or []) or hits:
                        yield Finding(
                            detector=self.name,
                            severity="medium",
                            title=f"Risky browser extension: {ext.get('name') or ext.get('id')}",
                            summary=(
                                f"Extension {ext.get('name') or ext.get('id')} (id {ext.get('id')}) "
                                f"holds sweeping permissions: {sorted(hits)}. Audit its source and "
                                "the marketplace listing for ownership changes."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={"extension": ext, "risky_perms": sorted(hits)},
                            mitre="T1176",
                        )

            # ---- 2. Service workers ----
            if "service_workers" in subj:
                origins = data.get("origins") or []
                origin_count = data.get("origin_count") or 0
                script_count = data.get("script_count") or 0
                storage_bytes = data.get("storage_bytes") or 0
                profile = data.get("profile") or ""

                # 2a. Baseline informational finding: enumerate every origin
                # that has a registered service worker. The user is responsible
                # for triage — this is the "did I really authorize ALL of
                # these?" finding. We split friendly vs unfamiliar.
                friendly: list[str] = []
                unfamiliar: list[str] = []
                for origin in origins:
                    host = _host(origin)
                    if not host:
                        continue
                    if host in _KNOWN_FRIENDLY_SW_HOSTS or _strip_subdomain(host) in _KNOWN_FRIENDLY_SW_HOSTS:
                        friendly.append(host)
                    else:
                        unfamiliar.append(host)

                # Fire each corpus entry whose detection_signal matches.
                for issue in unpatched_corpus:
                    sig = issue.get("detection_signal") or {}
                    if sig.get("kind") != "service_worker_presence":
                        continue
                    threshold = sig.get("threshold", "any")
                    fires = (
                        (threshold == "any" and origin_count > 0)
                        or (isinstance(threshold, int) and origin_count >= threshold)
                    )
                    if not fires:
                        continue
                    yield Finding(
                        detector=self.name,
                        severity=issue.get("impact") or "medium",
                        title=(
                            f"Unpatched Chromium bug {issue.get('short_id')} "
                            f"applies on profile {profile.split('/')[-1] or '?'}: "
                            f"{issue.get('title')}"
                        ),
                        summary=(
                            f"{issue.get('title')}\n\n"
                            f"Status: vendor_status={issue.get('vendor_status')!r}, "
                            f"affected_versions={issue.get('affected_versions')!r}, "
                            f"disclosed={issue.get('disclosed')}.\n\n"
                            f"This profile has {origin_count} registered "
                            "service worker(s); the detection signal for this "
                            f"issue is service_worker_presence (threshold={threshold!r}), "
                            "so the issue applies here.\n\n"
                            "Workarounds:\n  - "
                            + "\n  - ".join(issue.get("workaround") or [])
                            + "\n\nUpstream tracker: " + (issue.get("url") or "?")
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "unpatched_chromium_bug",
                            "issue_id": issue.get("id"),
                            "short_id": issue.get("short_id"),
                            "url": issue.get("url"),
                            "vendor_status": issue.get("vendor_status"),
                            "affected_versions": issue.get("affected_versions"),
                            "workaround": issue.get("workaround"),
                            "references": issue.get("references"),
                            "profile": profile,
                            "origin_count": origin_count,
                        },
                        mitre="T1176",
                    )

                # Always emit a baseline summary
                yield Finding(
                    detector=self.name,
                    severity="info",
                    title=(
                        f"Service-worker storage: profile {profile.split('/')[-1] or '?'} "
                        f"has {origin_count} origins, {script_count} cached scripts, "
                        f"{storage_bytes // (1024*1024)} MB"
                    ),
                    summary=(
                        "All Chromium browsers are subject to the persistent service-worker "
                        "/ background-fetch issue at "
                        "https://issues.chromium.org/issues/40062121 (disclosed 2022, "
                        "never patched). The bug lets a registered service worker keep "
                        "phoning home long after its tab is closed. Every origin below "
                        "has a registered worker; review the unfamiliar ones and clear "
                        "them in chrome://serviceworker-internals if you don't recognize "
                        "having opted in.\n\n"
                        f"  Friendly origins ({len(friendly)}): "
                        f"{', '.join(sorted(set(friendly))[:30])}\n"
                        f"  Unfamiliar origins ({len(unfamiliar)}): "
                        f"{', '.join(sorted(set(unfamiliar))[:30])}"
                    ),
                    artifact_refs=[art["artifact_uuid"]],
                    evidence={
                        "kind": "service_worker_baseline",
                        "profile": profile,
                        "origin_count": origin_count,
                        "script_count": script_count,
                        "storage_bytes": storage_bytes,
                        "origins_friendly": sorted(set(friendly)),
                        "origins_unfamiliar": sorted(set(unfamiliar)),
                        "chromium_bug": "https://issues.chromium.org/issues/40062121",
                    },
                    mitre="T1176",
                )

                # 2b. Unfamiliar-origin alert if the unfamiliar list is long
                if len(unfamiliar) >= 5:
                    yield Finding(
                        detector=self.name,
                        severity="medium",
                        title=(
                            f"{len(unfamiliar)} unfamiliar service-worker origins on "
                            f"Chrome profile {profile.split('/')[-1] or '?'}"
                        ),
                        summary=(
                            "The detector found a substantial number of installed "
                            "service workers from origins that are not in the curated "
                            "common-SaaS friendly list. None of these are necessarily "
                            "malicious; however, since the persistent-SW bug "
                            "(crbug 40062121) is unpatched in every Chromium release, "
                            "an unauthorized worker registered by a malicious or "
                            "compromised origin will continue phoning home indefinitely. "
                            "Open chrome://serviceworker-internals and unregister any "
                            "origin you don't recognize having opted in.\n\n"
                            f"Unfamiliar origins: {', '.join(sorted(set(unfamiliar))[:40])}"
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "service_worker_unfamiliar_origins",
                            "profile": profile,
                            "unfamiliar_count": len(unfamiliar),
                            "unfamiliar_origins": sorted(set(unfamiliar)),
                        },
                        mitre="T1546",
                    )

                # 2c. Storage-size alarms
                if storage_bytes >= _SW_STORAGE_HUGE_BYTES:
                    sev = "high"
                elif storage_bytes >= _SW_STORAGE_LARGE_BYTES:
                    sev = "medium"
                else:
                    sev = None
                if sev:
                    yield Finding(
                        detector=self.name,
                        severity=sev,
                        title=(
                            f"Excessive service-worker storage on profile "
                            f"{profile.split('/')[-1] or '?'}: "
                            f"{storage_bytes // (1024*1024)} MB"
                        ),
                        summary=(
                            "This profile's service-worker storage is unusually large. "
                            "Combined with the unpatched persistent-SW bug "
                            "(https://issues.chromium.org/issues/40062121), bloated "
                            "Cache API storage can indicate (a) heavy use of legitimate "
                            "PWAs/offline apps, (b) advertising telemetry, or (c) abuse "
                            "of background-fetch for botnet-style persistence. Review "
                            "the origin breakdown."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "service_worker_storage_bloat",
                            "profile": profile,
                            "storage_bytes": storage_bytes,
                            "origin_count": origin_count,
                            "script_count": script_count,
                        },
                        mitre="T1176",
                    )

                # 2d. Many distinct SW origins is itself a soft signal
                if origin_count >= _SW_ORIGIN_COUNT_HIGH:
                    yield Finding(
                        detector=self.name,
                        severity="low",
                        title=(
                            f"High service-worker origin count on profile "
                            f"{profile.split('/')[-1] or '?'}: {origin_count} origins"
                        ),
                        summary=(
                            f"{origin_count} distinct origins have registered service "
                            "workers on this profile. Normal heavy users sit around "
                            "20–40; counts above 60 deserve a once-over."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "service_worker_high_origin_count",
                            "profile": profile,
                            "origin_count": origin_count,
                        },
                        mitre="T1176",
                    )

                # 2e. Cross-reference SW origins vs live URLhaus/ThreatFox
                for origin in origins:
                    hit = _matches_bad_origin(origin, bad_hosts)
                    if hit:
                        yield Finding(
                            detector=self.name,
                            severity="critical",
                            title=(
                                f"Service worker registered by known-bad origin: "
                                f"{origin}"
                            ),
                            summary=(
                                f"Profile {profile} has a service worker "
                                f"registered by {origin}, whose host matches "
                                f"an entry in the live URLhaus / ThreatFox "
                                f"feed (matched: {hit}). Unregister "
                                "immediately in chrome://serviceworker-internals."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "service_worker_bad_origin",
                                "origin": origin,
                                "matched_host": hit,
                                "profile": profile,
                            },
                            mitre="T1185",
                        )

            # ---- 3. Cookies: high-domain tracking + bad-host cookies ----
            if "cookies" in subj:
                domains = data.get("domains") or []
                domain_count = data.get("domain_count") or 0
                profile = data.get("profile") or ""
                if domain_count >= _COOKIE_HIGH_DOMAIN_CNT:
                    yield Finding(
                        detector=self.name,
                        severity="low",
                        title=(
                            f"Cookie store holds {domain_count} distinct domains "
                            f"on profile {profile.split('/')[-1] or '?'}"
                        ),
                        summary=(
                            "Heavy tracker exposure. Cookie counts above 500 "
                            "domains generally indicate ad-tech / analytics "
                            "saturation; the larger the surface, the more "
                            "third-party data can be correlated with you."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"kind": "cookie_high_domain_count",
                                   "domain_count": domain_count},
                        mitre="T1539",
                    )
                for d_entry in domains:
                    host = (d_entry.get("host") or "").lstrip(".")
                    hit = _matches_bad_origin(f"https://{host}", bad_hosts)
                    if hit:
                        yield Finding(
                            detector=self.name,
                            severity="high",
                            title=f"Cookies stored for known-bad host: {host}",
                            summary=(
                                f"Profile {profile} has {d_entry.get('count')} "
                                f"cookies for host {host} (matched live feed: "
                                f"{hit}). Clear the cookies and review browsing "
                                "history for the visit that set them."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "cookies_for_bad_host",
                                "host": host,
                                "matched_host": hit,
                                "count": d_entry.get("count"),
                            },
                            mitre="T1539",
                        )

            # ---- 4. Saved passwords: count-only ----
            if "passwords_summary" in subj:
                saved = data.get("saved_count") or 0
                realms = data.get("distinct_realm_count") or 0
                if saved >= _PASSWORD_SAVE_HIGH:
                    yield Finding(
                        detector=self.name,
                        severity="info",
                        title=(
                            f"Browser holds {saved} saved passwords across "
                            f"{realms} sites"
                        ),
                        summary=(
                            "Large saved-password store. Browser password "
                            "managers are a major credential-theft target; "
                            "consider exporting to a dedicated manager and "
                            "disabling browser autofill, especially for "
                            "admin credentials."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"kind": "password_store_size",
                                   "saved_count": saved,
                                   "distinct_realms": realms},
                        mitre="T1555.003",
                    )

            # ---- 5. IndexedDB: bloat per origin + bad-host hits ----
            if "indexeddb" in subj:
                origins = data.get("origins") or []
                profile = data.get("profile") or ""
                for o in origins:
                    origin = o.get("origin") or ""
                    size = o.get("bytes") or 0
                    if size >= _IDB_BLOAT_BYTES:
                        yield Finding(
                            detector=self.name,
                            severity="low",
                            title=(
                                f"IndexedDB bloat: {origin} holds "
                                f"{size // (1024*1024)} MB"
                            ),
                            summary=(
                                "A single origin is storing >200 MB in "
                                "IndexedDB. Common for legitimate offline-"
                                "first apps; worth confirming the origin is "
                                "one you authorized."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={"kind": "indexeddb_bloat",
                                       "origin": origin, "bytes": size},
                            mitre="T1185",
                        )
                    hit = _matches_bad_origin(origin, bad_hosts)
                    if hit:
                        yield Finding(
                            detector=self.name,
                            severity="critical",
                            title=(
                                f"IndexedDB data for known-bad origin: {origin}"
                            ),
                            summary=(
                                f"Profile {profile} has IndexedDB data "
                                f"({size} bytes) for {origin}, which matches "
                                f"a live URLhaus/ThreatFox entry ({hit})."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "indexeddb_bad_origin",
                                "origin": origin,
                                "matched_host": hit,
                                "bytes": size,
                            },
                            mitre="T1185",
                        )

            # ---- 6. Local Storage: bad-host origin check ----
            if "local_storage" in subj:
                origins = data.get("origins") or []
                profile = data.get("profile") or ""
                for origin in origins:
                    hit = _matches_bad_origin(origin, bad_hosts)
                    if hit:
                        yield Finding(
                            detector=self.name,
                            severity="critical",
                            title=(
                                f"Local Storage data for known-bad origin: "
                                f"{origin}"
                            ),
                            summary=(
                                f"Profile {profile} has Local Storage data "
                                f"for {origin}, matching live feed entry "
                                f"{hit}. Clear via DevTools / "
                                "chrome://settings/clearBrowserData."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={
                                "kind": "local_storage_bad_origin",
                                "origin": origin,
                                "matched_host": hit,
                            },
                            mitre="T1185",
                        )

            # ---- 7. Profile defaults: hijacked search engine / startup ----
            if "profile_defaults" in subj:
                dse = data.get("default_search_engine") or {}
                dse_url = (dse.get("url") or "").lower()
                # Hijacked search engines almost always redirect through a
                # non-mainstream domain. The mainstream set is small.
                mainstream_search = (
                    "google.", "bing.com", "duckduckgo.com", "ecosia.org",
                    "kagi.com", "qwant.com", "startpage.com", "yandex.",
                    "baidu.com", "search.yahoo.com", "you.com", "perplexity.ai",
                    "brave.com", "search.brave.com",
                )
                if dse_url and not any(m in dse_url for m in mainstream_search):
                    yield Finding(
                        detector=self.name,
                        severity="medium",
                        title=(
                            f"Non-mainstream default search engine: "
                            f"{dse.get('short_name') or '?'}"
                        ),
                        summary=(
                            f"The default search engine URL ({dse_url}) is "
                            "not in the mainstream-providers list. Could be "
                            "a privacy-respecting niche engine the user "
                            "deliberately chose, or a search-hijack from a "
                            "malicious extension."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={"kind": "default_search_hijack",
                                   "default_search": dse},
                        mitre="T1176",
                    )
                startup_urls = data.get("startup_urls") or []
                for url in startup_urls:
                    hit = _matches_bad_origin(url, bad_hosts)
                    if hit:
                        yield Finding(
                            detector=self.name,
                            severity="critical",
                            title=(
                                f"Startup URL is a known-bad host: {url}"
                            ),
                            summary=(
                                f"Profile loads {url} on startup; this host "
                                f"matches a live feed entry ({hit})."
                            ),
                            artifact_refs=[art["artifact_uuid"]],
                            evidence={"kind": "startup_url_bad_origin",
                                       "url": url, "matched_host": hit},
                            mitre="T1176",
                        )

            # ---- 8. PWAs: just enumerate at info level ----
            if "pwas" in subj:
                apps = data.get("entries") or []
                profile = data.get("profile") or ""
                if apps:
                    yield Finding(
                        detector=self.name,
                        severity="info",
                        title=(
                            f"{len(apps)} PWA(s) installed on profile "
                            f"{profile.split('/')[-1] or '?'}"
                        ),
                        summary=(
                            "Installed Progressive Web Apps. PWAs can "
                            "register service workers and persist between "
                            "browser restarts even when the source tab is "
                            "closed — review for any you didn't deliberately "
                            "install."
                        ),
                        artifact_refs=[art["artifact_uuid"]],
                        evidence={
                            "kind": "pwa_inventory",
                            "count": len(apps),
                            "apps": [{"id": a.get("id"),
                                       "name": a.get("name"),
                                       "start_url": a.get("start_url")}
                                      for a in apps[:50]],
                        },
                        mitre="T1176",
                    )
                    # Bad-host start_url check
                    for app in apps:
                        url = app.get("start_url") or ""
                        hit = _matches_bad_origin(url, bad_hosts)
                        if hit:
                            yield Finding(
                                detector=self.name,
                                severity="critical",
                                title=f"PWA start URL is known-bad: {url}",
                                summary=(
                                    f"PWA '{app.get('name')}' starts at "
                                    f"{url}, matching live feed entry {hit}. "
                                    "Uninstall via chrome://apps."
                                ),
                                artifact_refs=[art["artifact_uuid"]],
                                evidence={
                                    "kind": "pwa_bad_start_url",
                                    "app": app,
                                    "matched_host": hit,
                                },
                                mitre="T1176",
                            )
