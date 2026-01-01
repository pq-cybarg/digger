# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (editable) + every optional dep
pip install -e ".[all,dev]"

# Tests
python -m pytest tests/                          # full suite
python -m pytest tests/test_detectors.py         # one file
python -m pytest tests/test_compliance.py::test_assessor_detects_failure  # one test

# Lint
ruff check digger/ tests/

# Smoke-test on this host
digger --no-banner collect --case-dir /tmp/case --only system,env,users
digger --no-banner scan --case-dir /tmp/case
digger --no-banner report --case-dir /tmp/case --format html --out /tmp/case/report.html
digger --no-banner verify --case-dir /tmp/case

# Launch the comprehensive docs site (auto-opens browser)
./docs.sh                  # http://127.0.0.1:8765
./docs.sh 9000             # custom port
./docs.sh --no-open        # serve only, don't open browser
```

The `liboqs version (major, minor) ... differs from liboqs-python` warning during tests is expected and harmless.

For the full architecture, every CLI command, gotchas, and how-to-extend recipes, run `./docs.sh` — it serves `docs/` locally and opens 18 pages of structured documentation.

## Architecture

digger is a forensics suite organized around **one append-only, hash-chained SQLite evidence store** (`digger/core/evidence.py`). Every component reads or writes that store; nothing communicates out-of-band. The pipeline:

```
collectors → Artifacts ──► EvidenceStore ──► detectors → Findings ──► AI triage → triaged Findings ──► reports / exports / compliance
                                  ▲
                          intel feeds (live) ──► detector inputs (with bundled YAML fallback)
                          chain-of-custody log
                          PQC signature
                          signature-base (LOKI corpus)
```

### Evidence store contract (`digger/core/evidence.py`)
- `artifacts` and `findings` tables are append-only. Every row carries **two** content hashes (`data_sha256`, `data_sha3_256`) and **two** chain hashes (`chain_sha256`, `chain_sha3_256`) that thread through the table in parallel. Forging tampering requires breaking both algorithm families simultaneously (Merkle-Damgård and Keccak sponge are structurally independent).
- `chain_sha256[n] = SHA-256(chain_sha256[n-1] || data_sha256[n])`; same shape for SHA3-256. `verify_chain()` returns `{"sha256": bool, "sha3_256": bool, "all": bool}` per table.
- **Never modify or delete rows** — breaks both chains and invalidates any PQC signature over the chain tip.
- `Finding.severity` must be one of `info|low|medium|high|critical` (validated in `__post_init__`).
- Artifact data is stored as canonical JSON. The hashes cover `collector|category|subject|canonical_json`, so renaming any of those changes both hashes.
- `findings.triage_json` is the **only** column updated post-hoc; it is deliberately not part of the chain so re-triage with a different model doesn't invalidate forensic integrity.
- External-interop hashes (`processes.exe_sha256`, `files.sha256`, IOC feeds, signature-base) stay SHA-256 only — the ecosystem expects it. SHA3-256 is purely for digger-internal integrity.

### Collectors (`digger/collectors/`)
- Subclass `Collector` (in `digger/core/collector.py`), set `name`, `category`, `supported_os`, `requires_admin`, implement `collect() -> Iterable[Artifact]`. Use `self.make(subject=..., **fields)` to build artifacts tagged with the collector's identity.
- **Degrade gracefully** — catch `PermissionError`, `OSError`, `subprocess.SubprocessError`, missing tools (`shutil.which(...)` is None). A collector that can't run should produce zero artifacts, not raise. `Collector.run()` catches everything else.
- Register new collectors in `digger/collectors/__init__.py` (`_common()` / `_windows()` / `_macos()` / `_linux()`). OS dispatch in `all_collectors()` defers platform-specific imports to runtime, so a Windows-only import in `digger/collectors/windows/foo.py` won't break Linux.

### Detectors (`digger/detectors/`)
- Subclass `Detector` (in `digger/detectors/base.py`), implement `detect(store) -> Iterable[Finding]`. Iterate artifacts via `store.iter_artifacts(collector=..., category=...)`.
- Register in `digger/detectors/__init__.py:all_detectors()`. The `TimelineBuilder` must stay last — it consumes other findings.
- Data-driven detectors (`shai_hulud`, `supply_chain`, `c2`, `threat_actor`, `loki`) load YAML/text rules from `digger/rules/<topic>/` or `signature-base/iocs/` via `digger/detectors/_rules_io.py`. `load_intel()` overlays live cached feed data; detectors always have a bundled fallback.

### LOKI / signature-base (`digger/loki/`)
- `digger loki update` clones (or fast-forwards) `Neo23x0/signature-base` to `$DIGGER_SIGNATURE_BASE_DIR` or `~/.cache/digger/signature-base/`.
- When present, the YARA detector picks up `signature-base/yara/*.yar` automatically (additive to bundled rules), and `LokiStyleDetector` consumes `iocs/hash-iocs.txt`, `iocs/filename-iocs.txt`, `iocs/c2-iocs.txt`, with `iocs/falsepositive-iocs.txt` as a suppression list.
- The detector also runs filename anomaly checks (double extensions, RTL override) regardless of whether signature-base is installed.
- `digger.loki.run_loki_binary()` is a bridge to an installed LOKI / Loki-RS binary if you want full parity with their workflow.

### Threat-intel feeds (`digger/intel/`)
- Each feed in `feeds.py:FEEDS` declares URL + per-feed cadence + parser. `update_feed()` is conditional (ETag/If-Modified-Since). Cache at `$DIGGER_INTEL_DIR` or `~/.cache/digger/intel/`.
- Detectors call `load_intel("cisa_kev")` etc. with bundled-snapshot fallback. Never make a detector hard-require a live feed.
- `IntelScheduler` is a single background thread ticking at the shortest pending interval.

### AI triage (`digger/ai/`)
- `LLMClient` is OpenAI-compatible over plain `requests` (no `openai` package). Talks to llama.cpp, ollama, vllm — anything serving `/v1/chat/completions`.
- `TriageRunner` writes results into `findings.triage_json`. The prompt in `prompts.py` requires IC analytic-tradecraft fields (estimative probability, analytic confidence, NATO Admiralty source/info reliability, TLP, assumptions, alternative hypotheses); schema enforced in `_FINDING_SCHEMA` in `triage.py`.

### FIPS mode (`digger/fips/`)
- `enable_fips_mode()` runs KATs (SHA-256, AES-256-GCM, ML-DSA-65, ML-KEM-768) and sets `_state` in `digger/fips/mode.py`.
- `PQCBackend.generate_signing_key()` / `generate_kem_key()` call `assert_approved_sig()` / `assert_approved_kem()`, which **only enforce when FIPS mode is on**.
- The CLI `--fips-mode` flag and `DIGGER_FIPS_MODE` env var both enable the gate.

### PQC (`digger/crypto/pqc.py`)
- Backed by `oqs-python`. Tables `PQC_FIPS_FINALIZED` / `PQC_NIST_ROUND4` / `PQC_SIG_ONRAMP` are informational — the actually-usable set is `available_kems()` / `available_sigs()`, read from whatever liboqs is linked at runtime.
- `sign_evidence(message, out_path, algorithm, secret_key_path)` writes `case_signature.json`. If `secret_key_path` exists, both the secret key file and `<path>.pub` must be present alongside.

### Compliance (`digger/compliance/`)
- Frameworks are YAML files in `digger/compliance/frameworks/*.yaml`. Each control has zero or more `checks`. Supported predicates: `artifact_present`, `artifact_count_min`, `no_finding_with_detector`, `no_finding_with_mitre`, `no_finding_above`, `data_contains`, `manual: true`.
- `ComplianceAssessor` reduces multiple checks per control to `pass`/`fail`/`partial`/`manual`. Adding a new framework is just dropping a YAML file — no code changes.

### Chain of custody (`digger/coc/`)
- `chain_of_custody.json` sits alongside `evidence.db`. `open_custody()` is idempotent; lifecycle events are appended automatically by `digger/core/runner.py`.

### Exchange formats (`digger/exchange/`)
- STIX 2.1, MISP, ATT&CK Navigator, TAXII 2.1 client, Sigma loader — all zero-dependency, hand-rolled. Adding fields is safer than swapping in upstream libraries.
- Sigma support is a deliberately limited subset (process_creation, network_connection log sources; modifiers `contains`/`endswith`/`startswith`/`re`; `and`/`or` between two named selections). Rules using unsupported features are silently skipped.

### Docs site (`docs/`)
- Static HTML, no build step. Shared chrome (topbar + sidebar) is injected at runtime by `docs/docs.js` so the chrome lives in one place; individual pages just set `<body data-page="...">`. To add a new page: write `docs/<id>.html` with `data-page="<id>"`, then append an entry to the `NAV` array in `docs/docs.js`.

## Gotchas

- `digger/assets/__init__.py:ASCII_LOGO` uses `r'''...'''` (triple-single-quote raw) because the art contains `""""`. Don't switch to `r"""..."""`.
- `pwd`, `grp`, `winreg`, and `Evtx` are platform-only — import inside the function, never at module top level.
- `psutil.process_iter()` can raise `AccessDenied` per-process. Iterate with the `attrs=` list to get partial info on processes you can't fully inspect.
- The ASCII banner prints by default. Always pass `--no-banner` in scripts/tests to avoid polluting stdout.
- Browser SQLite DBs must be opened via `file:...?immutable=1&mode=ro` URI or they lock against the live browser.
- The hash chain doesn't cover `triage_json`. Snapshot + sign externally if you need to attest to a specific triage run.
- Sigma rules with count aggregation / complex parenthesized conditions / unsupported log sources are **silently** skipped — debug by loading them via `SigmaLoader` directly.
- `can_share(item_tlp, sharing_level)` is "and-stricter," not equality — exporting at TLP:GREEN includes CLEAR + GREEN findings.
