# Competitor research — permissively-licensed forensics / DFIR tools

Goal: find features in adjacent open-source tools whose licenses are
compatible with digger's MIT license — so we could legally integrate
ideas (or even code) without contaminating downstream redistribution.

License screen: **MIT / BSD-2 / BSD-3 / Apache-2.0** = green. **VSL v1.0**
(Volatility) = case-by-case (technically OSI-permissive). **GPL / AGPL**
= excluded.

## Surveyed projects

| Project | License | Category |
|---|---|---|
| [Velociraptor](https://github.com/Velocidex/velociraptor) | Apache 2.0 | Live endpoint forensics + IR platform |
| [GRR Rapid Response](https://github.com/google/grr) | Apache 2.0 | Remote live forensics framework |
| [osquery](https://github.com/osquery/osquery) | Apache 2.0 | SQL-over-OS-state instrumentation |
| [Plaso / log2timeline](https://github.com/log2timeline/plaso) | Apache 2.0 | Super-timeline engine |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | VSL v1.0 | Memory forensics |
| [TimeSketch](https://github.com/google/timesketch) | Apache 2.0 | Collaborative timeline analysis |

## Where digger leads

These are unique to digger across the surveyed competitors:

- **Codified ethical contract** programmatically enforced (10 principles,
  19 load-bearing tests) — no surveyed competitor has anything equivalent
- **Dual SHA-256 + SHA3-256 hash chain** on every artifact + finding
- **Post-quantum signed evidence** (ML-DSA-65) with FIPS 140-3 mode + KATs
- **AI triage** schema-enforced under ICD 203 + NATO Admiralty + TLP
  with a strict no-raw-content policy
- **10 Decepticon countermeasure detectors** mapped per offensive
  kill-chain phase (recon → exploitation → privesc → lateral → AD →
  cloud → counter-RE → persistent-sessions → attacker-tooling →
  anti-forensics) plus auto-Sigma export
- **Live-first convention** for detector data, enforced via AST CI test
- **Browser scanner** with URLhaus + ThreatFox origin cross-reference
  and unpatched-Chromium-bug corpus
- **18 compliance-framework catalogs** as drop-in YAML

## Borrow candidates (ranked by value)

Features other tools have that digger lacks. Ranked by user impact ×
implementation effort.

### A. ForensicArtifacts knowledge-base ingestion  (HIGH value, LOW effort)

**Source:** [ForensicArtifacts/artifacts](https://github.com/ForensicArtifacts/artifacts) (Apache 2.0).
The shared artifact-definition repository used by GRR, Plaso, and
Velociraptor. ~400 YAML definitions describing what to collect for
forensic-relevant artifacts across Windows / macOS / Linux (registry
keys, files, plist locations, log paths, named pipes, etc.).

**Why it matters:** digger's collectors are hand-written per platform.
Importing the ForensicArtifacts definitions as a *collection-recipe
library* would expand digger's coverage 5–10× without writing more
Python — the user would just point a generic collector at an artifact
ID and it would gather everything that definition says to gather.

**How to integrate:** new `digger.collectors.forensic_artifacts`
module + a live feed (`forensic_artifacts_corpus`) that pulls the
YAML from upstream weekly. Honors the live-first convention.

### B. Plaso storage-file (`.plaso`) ingestion  (HIGH value, MEDIUM effort)

**Source:** [log2timeline/plaso](https://github.com/log2timeline/plaso) (Apache 2.0).
Plaso is the de-facto open-source super-timeline engine. Its `.plaso`
storage format is a documented protobuf-ish schema; many DFIR teams
already produce Plaso storage from disk images.

**Why it matters:** digger's timeline is synthesized from its own
artifacts. Ingesting an existing `.plaso` would let an analyst correlate
a digger live-host case with an offline-image timeline produced by
`log2timeline` against the same host's prior disk snapshot — much
richer cross-time analysis than digger can do alone.

**How to integrate:** new `digger.exchange.plaso` reader that maps
plaso events into digger Artifact rows (collector=`plaso_import`,
category=`timeline`). The existing `TimelineBuilder` then aggregates.

### C. Velociraptor-style query layer over the evidence store  (HIGH value, HIGH effort)

**Source:** [Velocidex/velociraptor](https://github.com/Velocidex/velociraptor) (Apache 2.0).
VQL — a SQL-ish query language over arbitrary plugin-provided data
sources. Lets an investigator pivot mid-case without writing a new
detector.

**Why it matters:** today, if an analyst wants "every process whose
parent is in the browser set AND has an established external
connection AND ran in the last hour", they have to either (1) write a
new detector and re-scan, or (2) crack open the SQLite manually. A
query layer (`digger query "SELECT pid, name FROM processes WHERE
ppid IN (browsers) AND has_ext_conn"`) would close that gap.

**How to integrate:** lift the most useful subset of VQL syntax,
implement against the EvidenceStore. Could borrow the Velociraptor VQL
parser directly — Apache 2.0 is compatible — but that's significant code.

### D. osquery-style continuous-monitoring daemon  (MEDIUM value, MEDIUM effort)

**Source:** [osquery/osquery](https://github.com/osquery/osquery) (Apache 2.0).
osqueryd runs scheduled queries on an interval and ships results.

**Why it matters:** digger today is one-shot — `collect → scan →
report`. A daemon mode (`digger watch --case-dir ./live`) that
re-collects + re-scans on a cadence and appends to the existing
case-DB would catch slow-burning compromises that don't show in a
single capture.

**How to integrate:** new `digger watch` CLI subcommand + an
EvidenceStore.append_collection() path that preserves chain integrity
across multiple collection runs.

### E. Memory-image plugin (Volatility-style)  (HIGH value, HIGH effort, LICENSE NOTE)

**Source:** [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) (VSL v1.0).
Offline RAM image analysis — windows.malfind, linux.bash, etc.

**Why it matters:** digger has a memory-region collector (live VM map
of running processes) but cannot ingest an *offline* memory dump
from another host. Many IR engagements start with a raw RAM capture
shipped to the analyst.

**License note:** VSL v1.0 is OSI-permissive but custom — not the
straightforward Apache 2.0 reuse path. Recommend wrapping (shell out
to `vol.py`) rather than vendoring code, to keep licensing clean.

**How to integrate:** new `digger.memory.volatility_bridge` that
shells out to a system `vol.py`, parses plugin output, emits findings.

### F. TimeSketch-style sketches  (LOW value alone, HIGH value combined with A/B/C)

**Source:** [google/timesketch](https://github.com/google/timesketch) (Apache 2.0).
A "sketch" is a container that groups related timelines + annotations +
collaborative review.

**Why it matters:** digger today is one-case-per-directory. Multi-host
incidents need a way to group cases. Implementing this only makes
sense after (A) and (B) land so there's actually multi-source data to
sketch over.

**How to integrate:** new `digger sketch` subcommand + a top-level
sketches/ directory. Defer.

### G. ELK / OpenSearch / Splunk output  (MEDIUM value, LOW effort)

Not unique to one competitor — Velociraptor, osquery, and TimeSketch
all support pushing to a SIEM/log aggregator. digger currently emits
STIX 2.1, MISP, ATT&CK Navigator, TAXII 2.1, and Sigma rules but no
direct streaming to an indexed store.

**How to integrate:** new `digger export elk --case-dir … --url …`
(NDJSON Bulk API). Same for OpenSearch.

## What's intentionally NOT borrowed

- **GUI / web frontend** (Velociraptor, GRR, TimeSketch). digger is
  deliberately CLI-first; the docs site is the surface.
- **Multi-tenant server** (GRR's full IR platform model). Conflicts
  with P1 (local-host only).
- **Agent-deploy management** (Velociraptor's fleet management).
  Same P1 conflict.
- **GPL-licensed competitors** (Wazuh, OSSEC, Hayabusa, Chainsaw,
  Cuckoo). License-incompatible — listed for awareness only.

## Recommended next iterations

| Order | Borrow candidate | Why first |
|---|---|---|
| 1 | **A. ForensicArtifacts ingestion** | Highest value × lowest effort. Pure data + thin loader, no architectural change. |
| 2 | **G. ELK/OpenSearch output** | Low effort, opens digger to existing enterprise SIEM pipelines. |
| 3 | **D. `digger watch` daemon** | Genuinely new capability class. Builds on existing intel-scheduler. |
| 4 | **B. Plaso `.plaso` ingestion** | High value but requires a real format parser; do after A/D establish the pattern. |
| 5 | **C. VQL-style query layer** | Highest value but biggest lift. Save for v0.2.x. |

## License compatibility cheat-sheet

| Their license | OK to integrate code? | OK to vendor? | OK to model after? |
|---|---|---|---|
| MIT, BSD-2/3, ISC | yes | yes | yes |
| Apache 2.0 | yes (include NOTICE, attribution) | yes | yes |
| MPL 2.0 | file-level only (keep MPL'd files MPL) | risky | yes |
| GPL / AGPL | NO | NO | yes (clean-room only) |
| VSL v1.0 (Volatility) | review per use | prefer shelling out | yes |

— end research notes —
