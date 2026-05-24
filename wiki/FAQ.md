# FAQ

## Is digger safe to run on a production server?

Yes, with the usual caveats:

- It's observation-only by default; nothing modifies host state
- It runs with whatever privilege you launch it with (`sudo` for full
  coverage of audit logs / EVTX / TCC, less without)
- The evidence DB contains sensitive data (process command lines,
  browser history, password-store counts) — handle accordingly
- One collection on a busy host can take 1-5 minutes and ~50-500 MB
  of evidence DB depending on the workload

If you're worried about resource footprint, run individual collectors:
```
digger collect --case-dir /tmp/case --only system,users,processes,network
```

## Does the LLM see my data?

Only what you opt into. By default the triage runner sends finding
**metadata** (detector name, MITRE tag, severity, evidence-dict
summary, target identifier) — not raw file contents, not raw browser
history, not actual command-line strings beyond truncated samples.

If you point it at a hosted endpoint (OpenAI, Anthropic, etc.) instead
of a local llama.cpp / ollama, that data leaves your network. Air-gap
mode (`DIGGER_AIRGAP=1`) refuses all such egress.

## Does it work offline?

Yes. After one `digger intel update` while you have network, the
intel feeds are cached locally and detectors work fully offline.
Without ever running update, detectors still work — they just don't
have live IOC enrichment (e.g., the `c2` detector still pattern-matches
on framework signatures from the bundled YAML; it just won't have the
last 15 minutes of ThreatFox).

## What's the deal with the dual SHA-256 + SHA3-256 chain?

`artifacts` and `findings` rows each carry **two** content hashes and
**two** chain hashes — one Merkle-Damgård (SHA-256) and one Keccak
sponge (SHA3-256). Forging tampering requires breaking both algorithm
families simultaneously, which no known attack does.

If either chain breaks at row N, `digger verify` reports which one
broke and at which row. The PQC signature is over the chain tip
message, which includes both algorithm roots.

## What's the deal with the post-quantum signing?

ML-DSA-65 (FIPS 204, formerly Dilithium) replaces RSA / ECDSA for the
case-signature use case. Quantum computers (when they exist at scale)
break RSA + ECDSA; ML-DSA is believed to be quantum-resistant. We
sign now so case evidence remains verifiable in a future where RSA
signatures don't.

## Can I add my own detector / collector / feed / compliance framework?

Yes — see [CONTRIBUTING.md](https://github.com/pq-cybarg/digger/blob/main/CONTRIBUTING.md). Most extensions are
single-file additions:

- New compliance framework: drop a YAML at
  `digger/compliance/frameworks/<name>.yaml`. Zero code.
- New collector: one Python file, register in
  `digger/collectors/__init__.py`.
- New detector: one Python file, register in
  `digger/detectors/__init__.py`. Must call `load_intel(...)` first
  if you also load bundled rules (live-first rule, AST-enforced).
- New intel feed: append to `digger/intel/feeds.py:FEEDS`. Single-URL
  is just URL + parser; multi-URL uses the `fetch_fn` hook.

## Does it support Linux fleet management?

Indirectly — each host runs digger locally and produces a `.digger`
bundle. You aggregate the bundles centrally with `digger opsec
encrypt` for transit + a script of your choice to ingest. There's no
"digger server" — that would violate P1 (local host only).

If you want fleet-wide trends from the data, `digger export stix`
gives you a STIX 2.1 bundle per case for ingest into any TIP.

## What about Windows?

Full support. Windows-specific collectors: `windows.registry_persistence`,
`windows.scheduled_tasks`, `windows.services`, `windows.event_logs`,
`windows.defender`, `windows.firewall`, `windows.wmi_persistence`,
`windows.startup_folders`. Some need admin (notably event_logs);
collectors degrade gracefully without.

## Why a custom Sigma loader instead of pysigma?

Pragmatic: zero-dependency parser that supports the subset of Sigma
that maps to digger's collected artifacts (process_creation,
network_connection log sources; `contains` / `startswith` /
`endswith` / `re` modifiers; `and`/`or` between two named selections).
Rules using unsupported features are silently skipped.

If you need full Sigma compliance, run sigma-cli against the
SigmaHQ-corpus cache that digger populates (the rules are real .yml
files at `$DIGGER_INTEL_DIR/sigma-corpus/`).

## Where do reports go?

Wherever you point `--out`. Default formats:

- `--format html` — single-file self-contained HTML with embedded CSS
- `--format md` — markdown with anchors
- `--format json` — full case payload (artifacts + findings + meta)
- `--format pdf` — needs `weasyprint`, not installed by default

For sharing externally, use `digger opsec redact --case-dir … --out
shared/` first — strips usernames, hostnames, network identifiers
with pseudonyms that are stable within the case.
