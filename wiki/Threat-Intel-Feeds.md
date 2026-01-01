# Threat-intel feeds

15 continuously-polled feeds, per-feed cadence, conditional fetches
(ETag / If-Modified-Since). Live-first convention is statically
enforced — no detector ships consuming only hand-typed seed data.

## Single-URL feeds

| Feed | Source | Refresh | What it gives detectors |
|---|---|---|---|
| `cisa_kev` | cisa.gov | 24h | Known Exploited Vulnerabilities catalog. `supply_chain` cross-checks installed software. |
| `urlhaus_recent` | abuse.ch | 15min | Recently observed malware URLs. `c2` + `browser` origin cross-reference. |
| `malwarebazaar_recent` | abuse.ch | 15min | Recent sample SHA-256/MD5. `c2` flags running exes by hash. |
| `threatfox_recent` | abuse.ch | 15min | Fresh IPs/domains/URLs/hashes. `c2` + `browser`. |
| `tor_exit_list` | torproject.org | 1h | Bulk Tor exit-node list. |
| `spamhaus_drop` | spamhaus.org | 12h | Hijacked IP space (DROP). |
| `spamhaus_edrop` | spamhaus.org | 12h | Extended DROP. |
| `emerging_threats_compromised` | emergingthreats.net | 6h | Compromised-IPs blocklist. |
| `openssf_malicious_packages` | OpenSSF | 12h | OSV-formatted malicious-package dataset. **Authoritative for `supply_chain`** — bundled YAML is fallback only. |
| `shai_hulud_packages` | Aikido (community) | 1h | Shai-Hulud worm IOCs: compromised packages, worm marker tiers, exfil URL patterns, worm workflow filename. **Authoritative per-tier**. |
| `github_advisory_npm` | api.github.com | 3h | GitHub Advisory DB, npm ecosystem. |
| `github_advisory_pip` | api.github.com | 3h | GitHub Advisory DB, PyPI ecosystem. |

## Composite multi-URL feeds (`fetch_fn` hook)

| Feed | Source | Refresh | Notes |
|---|---|---|---|
| `nvd_service_cves` | NVD API 2.0 (~30 CPEs) | 24h | CPE-keyed CVE corpus paginated across the curated service-product list. Used by `service_cve`. Honors `$NVD_API_KEY` for the 50 req/30s tier. |
| `sigmahq_corpus` | SigmaHQ master tarball | 24h | Community detection rules filtered to 8 attack categories. `SigmaLoader` auto-extends its search path with the live cache. |
| `mitre_attack_groups` | MITRE ATT&CK Enterprise STIX 2.1 | 7d | Threat-actor groups + associated software + techniques. **Authoritative for `threat_actor`**. |

## Live-first convention

Detectors that load bundled rule data MUST also call `load_intel(...)`
for the live equivalent first. The live feed is authoritative when
present; bundled is fallback only.

This is statically enforced by `tests/test_data_freshness.py` — an
AST guardrail that walks every detector file and asserts the call
order. PR-blocking on regression.

Escape hatch for digger-native data with no upstream counterpart
(e.g., the unpatched-Chromium-bug corpus): per-file comment
`# live-first-ok: <reason>`.

## Signing the intel cache

The cache itself can be PQC-signed (dual SHA-256 + SHA3-256 tree-hash,
ML-DSA-65 signature). Detectors verify the signature on first
`load_intel()` call per process; with `DIGGER_INTEL_STRICT=1` they
refuse tampered/unsigned data.

```bash
digger intel sign --key ./op.sk          # sign the cache
digger intel verify                       # verify (returns the tree roots + file count)
digger intel update --sign-key ./op.sk   # auto-sign after each refresh
```

## Adding a new feed

See [CONTRIBUTING.md](https://github.com/pq-cybarg/digger/blob/main/CONTRIBUTING.md). Most feeds are
single-URL with a parser — drop into `digger/intel/feeds.py:FEEDS`.
Composite multi-URL feeds use the `fetch_fn` hook — see
`digger/intel/sources/nvd_cpe.py` for the template.
