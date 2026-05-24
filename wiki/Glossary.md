# Glossary

| Term | Meaning |
|---|---|
| **Artifact** | A single forensic observation captured by a collector. Has a `collector`, `category`, `subject`, canonical-JSON `data` payload, and dual hashes (SHA-256 + SHA3-256). |
| **Finding** | A detector's positive match against artifacts. Has `detector`, `severity`, `title`, `summary`, `mitre`, `artifact_refs`, `evidence`, and (post-triage) `triage_json`. |
| **Case** | A directory holding one investigation: `evidence.db` + `chain_of_custody.json` + (optionally) `engagement_scope.json`, `case_signature.json`, `report.html`, `intel/` cache. |
| **Engagement scope** | A pre-engagement attestation (WHO/WHY/WHAT/WHEN) recorded into the chain of custody at case-open. Validated programmatically. |
| **Chain of custody** | Append-only JSON log of every lifecycle event on the case (created, collector ran, signed, etc.), distinct from the artifact/finding hash chains. |
| **Dual hash chain** | Each artifact + finding row carries `data_sha256` + `data_sha3_256` (content) AND `chain_sha256` + `chain_sha3_256` (link to previous row). Two algorithm families threaded in parallel. |
| **PQC** | Post-quantum cryptography. digger uses ML-DSA-65 (FIPS 204) signatures + ML-KEM-768 (FIPS 203) key encapsulation via liboqs. |
| **Live-first** | Convention enforced by `tests/test_data_freshness.py`: any detector that loads bundled YAML rules must call `load_intel()` for the live equivalent first. |
| **Ethical contract** | The 10 principles in `digger.ethics.contract`, programmatically enforced via `EthicsViolation` raises. See [ETHICS.md](https://github.com/pq-cybarg/digger/blob/main/ETHICS.md). |
| **Air-gap mode** | `DIGGER_AIRGAP=1` — refuses every outbound HTTP call at the source via `assert_network_allowed`. |
| **Decepticon countermeasure** | One of 9 detectors that mirror an offensive kill-chain phase. Named after the [PurpleAILAB/Decepticon](https://github.com/PurpleAILAB/Decepticon) red-team agent suite. |
| **LOKI** | [Neo23x0/loki](https://github.com/Neo23x0/Loki) — Florian Roth's APT scanner. digger consumes its YARA + IOC corpus from [signature-base](https://github.com/Neo23x0/signature-base). |
| **Self-attribution** | When a check fires on digger itself (its own process, its own files), the finding is emitted with a clear annotation (`digger.opsec.self_id.identify`) rather than silently filtered. Required by P10. |
| **GTFOBins** | Curated list of Unix binaries that can be abused for privilege escalation when setuid. digger's `privesc` detector flags any setuid binary in the GTFOBins set. |
| **LOLBAS** | Living-Off-the-Land Binaries and Scripts on Windows. digger's `lolbins` detector flags abuse patterns (certutil download, mshta with URL, regsvr32 squiblydoo, etc.). |
| **FIPS 140-3 mode** | `--fips-mode` or `DIGGER_FIPS_MODE=1`. Runs KATs on SHA-256, AES-256-GCM, ML-DSA-65, ML-KEM-768 at startup; non-FIPS algorithms refuse to bind. |
| **TLP** | Traffic Light Protocol — sharing-restriction labels (CLEAR / GREEN / AMBER / RED) on findings. `can_share(item_tlp, sharing_level)` is "and-stricter": GREEN allows CLEAR + GREEN. |
| **ICD 203** | US Intelligence Community Directive 203 — analytic-tradecraft standards (estimative probability, source/info reliability, alternative hypotheses, key assumptions). Triage output is schema-enforced under this. |
| **NATO Admiralty** | Letter (A-F) source reliability + digit (1-6) information credibility grading system. Used alongside ICD 203 in triage. |
| **STIX 2.1** | Structured Threat Information Expression — standard format for sharing CTI. `digger export stix` produces a bundle per case. |
| **TAXII 2.1** | Trusted Automated Exchange of Intelligence Information — HTTP-based transport for STIX. `digger export taxii` pushes a bundle to a TAXII collection. |
| **MITRE ATT&CK** | Adversary Tactics, Techniques & Common Knowledge — the canonical taxonomy of attacker behaviors. digger tags every finding with one or more ATT&CK technique IDs. |
| **Sigma** | YAML-based generic detection-rule format. digger both runs Sigma rules (consumer) via the `sigma` detector AND generates Sigma rules from findings/detectors (producer) via the `genrule` module. |
| **OSV** | Open Source Vulnerability — Google's machine-readable vuln format. `nvd_service_cves` normalizes NVD data into OSV-style ranges; `openssf_malicious_packages` is native OSV. |
