# digger

**Cross-platform endpoint forensics suite. Runs entirely on your machine.
Codified ethics, post-quantum signed evidence, 30 detectors including a
defensive mirror of every offensive-tooling kill-chain phase.**

[![docs](https://img.shields.io/badge/docs-pq--cybarg.github.io%2Fdigger-2ea44f)](https://pq-cybarg.github.io/digger/)
[![license](https://img.shields.io/badge/license-MIT-blue)](#license)
[![tests](https://img.shields.io/badge/tests-337%20passing-2ea44f)]()
[![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)]()
[![python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![ethics](https://img.shields.io/badge/ethics-load--bearing-orange)](ETHICS.md)
[![PQC](https://img.shields.io/badge/PQC-ML--DSA--65%20%7C%20ML--KEM--768-purple)]()

```
┌────────────────────────────────────────────────────────────────┐
│ collectors → Artifacts → EvidenceStore → detectors → Findings  │
│                              ▲                          │      │
│                              │                          ▼      │
│            chain-of-custody  │              AI triage (local)  │
│                  PQC signature                 │               │
│           live intel feeds → detector inputs   ▼               │
│           signature-base / LOKI corpus      reports • exports  │
└────────────────────────────────────────────────────────────────┘
```

---

## What it does, in one minute

`digger` walks into a host, pulls hundreds of forensic artifacts into an
**append-only, dual-hash-chained, post-quantum-signable SQLite evidence
store**, runs a stack of 30 detectors over them, and produces case
reports suitable for legal disclosure, SOC handoff, or internal
incident-response review. Every step is observation-only: it never
modifies the system it's investigating without explicit, audited
consent.

```bash
digger collect --case-dir ./case-2026-05-24                                       # gather artifacts
digger scan    --case-dir ./case-2026-05-24                                       # run detectors
digger triage  --case-dir ./case-2026-05-24 --llm-base-url http://127.0.0.1:8080/v1   # local LLM grading
digger report  --case-dir ./case-2026-05-24 --format html --out report.html       # shareable report
digger pqc sign --case-dir ./case-2026-05-24 --key ./op.sk                        # ML-DSA-65 signed chain
```

Or one-shot: `digger investigate --case-dir ./case --report report.html`.

---

## What makes it different

| Capability | Why it matters |
|---|---|
| **Ethical contract enforced in code** | 10 principles (`digger.ethics.contract`) raise `EthicsViolation` rather than warning. 19 load-bearing tests fail if a guardrail is removed. See [ETHICS.md](ETHICS.md). |
| **Dual hash chain on every record** | SHA-256 *and* SHA3-256 threaded through artifacts + findings tables in parallel. Forging tampering requires breaking both algorithm families simultaneously (Merkle-Damgård + Keccak sponge). |
| **Post-quantum signed evidence** | ML-DSA-65 (FIPS 204) signature over the chain tip via liboqs. FIPS 140-3 mode with KATs for SHA-256, AES-256-GCM, ML-DSA-65, ML-KEM-768. |
| **9 Decepticon countermeasures** | One defensive detector per offensive kill-chain phase (recon → exploitation → privesc → lateral → AD → cloud → counter-RE → persistent sessions → attacker tooling). |
| **15 live threat-intel feeds** | CISA KEV, abuse.ch (URLhaus/ThreatFox/MalwareBazaar), Spamhaus, OpenSSF, GitHub Advisory DB, NVD CPE-keyed CVEs, SigmaHQ rule corpus, MITRE ATT&CK STIX, Aikido Shai-Hulud IOCs. Statically-enforced "live-first" convention: no detector ships consuming only hand-typed seed data. |
| **AI triage under IC tradecraft** | OpenAI-compatible local LLM (llama.cpp / ollama / vllm). Schema-enforced output under ICD 203 estimative probability + NATO Admiralty source/info reliability + TLP. The LLM never sees raw file contents. |
| **18 compliance frameworks** | NIST 800-53, NIST 800-171, SOC 2, ISO 27001, ISO 27037, CIS, CMMC L1/L2, PCI-DSS, HIPAA, GDPR, FedRAMP, FFIEC, NIS2. Adding a framework is one YAML file. |
| **Comprehensive browser scanner** | Chromium + Firefox: cookies (counts only, never values), saved-passwords summary (counts only), IndexedDB, Local Storage, PWAs, profile defaults, service workers. Live URLhaus + ThreatFox cross-reference on every origin. Tracks unpatched-Chromium bug class (e.g., [crbug-40062121](https://issues.chromium.org/issues/40062121) service-worker persistence). |
| **Firewall audit + remediation** | Unified pf / nftables / iptables / ufw / firewalld / WFP audit. Emits copy-pasteable platform-specific fix commands routed through `redact_dangerous_command`. Never applies changes itself. |
| **Auto-Sigma export per detector** | `digger generate sigma --from-detectors` writes one SIEM-deployable Sigma rule per detector. Plus per-finding Sigma generation for case-specific signatures. |

---

## Install

```bash
# Base install
pip install -e .

# With YARA, Windows registry parsing, GeoIP, etc.
pip install -e ".[all]"

# Dev (tests, linting)
pip install -e ".[dev]"
```

No build-time C extensions are required for the base install. Optional
features fall back gracefully when their libraries are missing.

---

## Quick start

```bash
# 1. Collect into ./case-2026-05-24/
digger collect --case-dir ./case-2026-05-24

# 2. Run detectors against the collected evidence
digger scan --case-dir ./case-2026-05-24

# 3. Optional: triage findings through a local LLM (llama.cpp on :8080)
digger triage --case-dir ./case-2026-05-24 \
    --llm-base-url http://127.0.0.1:8080/v1 \
    --llm-model GLM-4.6

# 4. Generate a self-contained HTML report
digger report --case-dir ./case-2026-05-24 --format html --out report.html

# 5. PQC-sign the evidence chain so any future tampering breaks the signature
digger pqc sign --case-dir ./case-2026-05-24 --key ./op.sk

# 6. Anyone with the public key can verify later
digger pqc verify --case-dir ./case-2026-05-24
```

One-shot:

```bash
digger investigate --case-dir ./case --report report.html
```

Run with elevated privileges (`sudo` / `runas administrator`) for full
coverage — most collectors degrade gracefully without root, but several
artifacts (audit logs, EVTX, TCC database, unified logs, kernel modules,
firewall rules) require it.

---

## The Decepticon countermeasure suite

Nine detectors that mirror — and counter — every phase of the autonomous
red-team kill chain ([PurpleAILAB/Decepticon](https://github.com/PurpleAILAB/Decepticon)):

| Phase | digger detector | MITRE |
|---|---|---|
| Reconnaissance | `recon` | T1595.001 / T1110.001 / T1592.002 |
| Exploitation | `exploitation` | T1190 / T1059 / T1203 |
| Privilege escalation | `privesc` | T1548 / T1068 / T1547.006 |
| Lateral movement | `lateral` | T1021 / T1550 / T1570 |
| C2 frameworks (extended) | `c2` | T1071 / T1573 / T1055 |
| Active Directory | `ad_attacks` | T1558.003 / T1003.006 / T1484.001 |
| Cloud | `cloud_attacks` | T1552.005 / T1078.004 / T1611 |
| Counter-RE (debuggers on us) | `counter_re` | T1622 / T1057 |
| Persistent sessions | `persistent_sessions` | T1546 / T1543.002 |
| Attacker tooling on host | `attacker_tooling` | T1588.002 |

All are observation-only: digger never sends a payload to verify
exploitability (P3 of the ethical contract). Each detector ships a generic
SIEM-deployable Sigma rule via `digger generate sigma --from-detectors`.

Full walkthrough at [docs/decepticon-counter](https://pq-cybarg.github.io/digger/decepticon-counter.html).

---

## Local LLM setup (optional)

`digger` talks to any OpenAI-compatible `/v1/chat/completions` endpoint.

### llama.cpp

```bash
huggingface-cli download zai-org/GLM-4.6-GGUF GLM-4.6-Q4_K_M.gguf --local-dir ./models
llama-server -m ./models/GLM-4.6-Q4_K_M.gguf --host 127.0.0.1 --port 8080 -c 32768 --jinja
```

### ollama

```bash
ollama serve
ollama pull qwen2.5:14b-instruct
digger triage --case-dir … --llm-base-url http://127.0.0.1:11434/v1 --llm-model qwen2.5:14b-instruct
```

The LLM never receives raw file contents unless you opt in — only
metadata, detector findings, and short context windows. See
[`digger/ai/triage.py`](digger/ai/triage.py).

---

## Architecture, briefly

```
digger/
├── core/         Evidence store, platform detection, hashing, runner
├── collectors/   common/, windows/, macos/, linux/ artifact collectors
├── detectors/    Behavioral + YARA + IOC + Sigma + C2 + supply-chain + 9 counter-offensive
├── memory/       VM-region anomaly detection (RWX, anonymous-exec, drop-loaded modules)
├── signing/      Code-signature verification (codesign / dpkg -V / rpm -V)
├── firewall/     Unified pf / nftables / iptables / ufw / firewalld / WFP audit
├── ethics/       The 10-principle contract; engagement scope; remediation gating
├── opsec/        Air-gap mode, PQC bundle encrypt, PII redaction, watchers, self-id
├── intel/        15 live threat-intel feeds + scheduler + composite multi-URL fetchers
├── ai/           OpenAI-compatible client, ICD-203-compliant triage prompts + schema
├── crypto/       liboqs-backed NIST PQC (sign, verify, hybrid KEM + AES-256-GCM)
├── fips/         FIPS 140-3 mode + KAT self-test + algorithm gating
├── compliance/   18 framework catalogs + control assessor + reports
├── tradecraft/   ICD 203 estimative probability, NATO Admiralty, TLP, ACH
├── exchange/     STIX 2.1, MISP, ATT&CK Navigator, TAXII 2.1, Sigma loader
├── coc/          ISO/IEC 27037 + NIST SP 800-86 chain-of-custody record
├── loki/         Bridge to LOKI/signature-base (Neo23x0/signature-base)
├── genrule/      Generate Sigma YAML from findings or per-detector class templates
├── hunts/        17-query threat-hunting library
├── diff/         Stable-identity case-to-case diffing
├── rules/        Bundled YARA, IOC lists, Sigma-style rules, framework catalogs
└── report/       JSON, Markdown, HTML report renderers
```

Module-by-module docs at
[**pq-cybarg.github.io/digger**](https://pq-cybarg.github.io/digger/).

---

## Ethics & safety

This tool is for analyzing **your own** machine, or machines you have
explicit authorization to inspect (your fleet, your client's fleet under
contract, a CTF box, etc.).

The 10-principle ethical contract is enforced **programmatically**, not
by docstring:

| # | Principle | Enforced by |
|---|---|---|
| P1 | Local host only | `assert_target_is_localhost` raises `EthicsViolation` |
| P2 | Observation by default | `confirm_remediation_intent` refuses non-interactive sessions |
| P3 | No exploitation | `assert_not_exploitation` blocks msfvenom / sqlmap / exploit phrasing |
| P4 | No credential attacks | `assert_not_credential_attack` blocks john / hashcat / brute-force |
| P5 | No third-party surveillance | `assert_no_third_party_surveillance` requires consent marker |
| P6 | No egress without opt-in | `DIGGER_AIRGAP=1` blocks all outbound HTTP at the source |
| P7 | Calibrated findings | Triage schema enforces ICD 203 estimative probability |
| P8 | No biometric collection | No camera / mic / fingerprint / face-capture surface exists |
| P9 | Refuse compromised configuration | Pre-flight self-checks abort on tamper-detection |
| P10 | Audit-visible | Findings on digger itself emit with self-attribution, never silently filtered |

Full text in [ETHICS.md](ETHICS.md). The 19 tests in
`tests/test_ethics.py` fail if any guardrail is removed.

Don't ship the evidence DB anywhere it shouldn't go — it contains
process command lines, browser history, and other sensitive data by
design. See `digger opsec redact` for sharing-safe copies and
`digger opsec encrypt` for hybrid PQC-KEM + AES-256-GCM bundles.

---

## Multi-identity tooling (`tools/identity/`)

The repo ships a small companion toolchain for hosts that juggle
multiple GitHub accounts — solves the "Sourcetree-generated SSH config
silently routes every push through the first identity" foot-gun.

- `ghid` — CLI: switch / lock / verify / rotate per-repo identity
- `ghidbar` — macOS menu-bar app: shows `🔑 <identity> 🔒` while you're in the repo
- `install-hooks.sh` — unified pre-push hook: identity lock + auto-sync of gh-pages

Install: `./tools/identity/install.sh --launchd`. Docs in
[`tools/identity/README.md`](tools/identity/README.md).

---

## Documentation

Comprehensive docs at
[**pq-cybarg.github.io/digger**](https://pq-cybarg.github.io/digger/)
— 30+ pages covering:

- [Getting started](https://pq-cybarg.github.io/digger/getting-started.html)
- [CLI reference](https://pq-cybarg.github.io/digger/cli.html)
- [Architecture](https://pq-cybarg.github.io/digger/architecture.html)
- [Detectors](https://pq-cybarg.github.io/digger/detectors.html) (all 28)
- [Decepticon countermeasures](https://pq-cybarg.github.io/digger/decepticon-counter.html)
- [Browser scanner](https://pq-cybarg.github.io/digger/browser-scanner.html)
- [Unpatched Chromium bugs corpus](https://pq-cybarg.github.io/digger/chromium-unpatched.html)
- [Firewall audit + remediation](https://pq-cybarg.github.io/digger/firewall-audit.html)
- [Live threat-intel feeds](https://pq-cybarg.github.io/digger/intel.html)
- [Post-quantum crypto](https://pq-cybarg.github.io/digger/pqc.html)
- [FIPS 140-3 mode](https://pq-cybarg.github.io/digger/fips.html)
- [Compliance frameworks](https://pq-cybarg.github.io/digger/compliance.html)
- [Ethical contract](https://pq-cybarg.github.io/digger/ethics.html)
- [Extending digger](https://pq-cybarg.github.io/digger/extending.html)

Run locally: `./docs.sh` → http://127.0.0.1:8765/.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a collector,
detector, intel feed, or compliance framework. The single most
important rule: **live-first** for any detector that loads data — the
AST-level CI test in `tests/test_data_freshness.py` will fail your PR
otherwise.

---

## Security

If you find a vulnerability in `digger` itself, please follow the
disclosure process in [SECURITY.md](SECURITY.md).

---

## License

MIT — see [LICENSE](LICENSE).
