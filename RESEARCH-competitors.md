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

## Round 2 — adjacent + specialist tools (added on second pass)

Round 1 covered the big-name DFIR platforms. Round 2 found
specialist tools that fill narrower roles but contain ideas digger
could adopt cleanly.

| Project | License | Niche |
|---|---|---|
| [Aftermath](https://github.com/jamf/aftermath) | MIT | macOS-only IR triage (Jamf) |
| [UAC](https://github.com/tclahr/uac) | Apache 2.0 | Unix-family triage shell (AIX / ESXi / Solaris / NAS / IoT) |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | MIT | 1,797 atomic tests mapped to MITRE ATT&CK |
| [Falco](https://github.com/falcosecurity/falco) | Apache 2.0 | eBPF syscall-level runtime security (CNCF graduated) |
| [Hindsight](https://github.com/obsidianforensics/hindsight) | Apache 2.0 | Chromium-only deep browser forensics |

### Round 2 borrow candidates

#### H. Atomic Red Team as detector-validation harness  (HIGH value, MEDIUM effort)

**Source:** [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) (MIT). 1,797 atomic tests mapped to MITRE ATT&CK techniques — Red Canary's adversary-emulation library. Each test executes a single ATT&CK technique with documented expected behavior.

**Why it matters:** digger has 29 detectors covering ~60 MITRE techniques but no systematic way to *verify* that the detector actually catches the technique it claims to. ART is the obvious harness — for each technique tag in digger's detector roster, run the matching ART test on a controlled host and assert digger's detector fires within N seconds.

**How to integrate:** new `tests/integration/atomic_red_team/` directory that pulls ART YAML at test-prep time, filters to techniques digger claims to detect, and runs an end-to-end "execute → collect → scan → assert finding" pipeline. Detector accuracy becomes measurable. Coverage gaps become a coverage matrix.

**Ethics gate:** ART executes real-ish attack primitives; must run only in a sandboxed test environment. Add `tests/integration/atomic_red_team/SANDBOX_REQUIRED.md` and refuse to run if `DIGGER_INTEGRATION_OK_TO_RUN_ATTACKS=1` isn't set.

#### I. Aftermath-style "storyline" / narrative reconstruction in reports  (HIGH value, MEDIUM effort)

**Source:** [jamf/aftermath](https://github.com/jamf/aftermath) (MIT). Aftermath's distinctive contribution isn't its collectors (most overlap with digger's) — it's the analysis phase that "reconstructs a storyline correlating file metadata, database changes, and browser information to identify infection vectors."

**Why it matters:** digger emits findings independently and the report lists them; nothing synthesizes "user X visited this URL → downloaded that file → file ran with this parent → spawned that shell → connected here". A timeline-correlation post-processor that walks the evidence store and produces a narrative would massively improve report readability.

**How to integrate:** new `digger.report.storyline` module — graph-walk findings via shared pids, file paths, and timestamps within ±30 s windows. Emit a "Likely event chain" block at the top of every report.

#### J. Hindsight-style deep Chromium parsing  (MEDIUM value, MEDIUM effort)

**Source:** [obsidianforensics/hindsight](https://github.com/obsidianforensics/hindsight) (Apache 2.0). 10 artifact types from Chromium internals including cache database parsing, autofill *values* (not counts), HTTP cookies, Local Storage records — all with cross-source correlation.

**Why it matters:** digger's browser scanner is broad-and-shallow (counts everything, parses nothing for privacy reasons). For full-IR work where the operator explicitly opts in to deeper inspection, Hindsight-style parsing would tell them *what* was stolen — not just *that there are 247 saved passwords*.

**How to integrate:** new `digger.collectors.common.browsers_deep` collector behind an explicit flag `--deep-browser-parse` that bypasses the counts-only privacy default. Routes through `confirm_remediation_intent` per P2 since it's a privacy-sensitive opt-in. Possibly vendor or shell out to Hindsight directly (Apache 2.0 compatible).

#### K. Falco-style eBPF syscall-level runtime layer  (HIGH value, HIGHEST effort)

**Source:** [falcosecurity/falco](https://github.com/falcosecurity/falco) (Apache 2.0). CNCF graduated. Kernel-level syscall monitoring with custom rule language. Real-time, not snapshot.

**Why it matters:** the biggest architectural gap. Today's digger is one-shot snapshot. A Falco-style eBPF layer would let digger ALERT in real time when a process opens a sensitive file, makes a suspicious syscall, or chains together the patterns the snapshot detectors look for. Bridges between "I scanned this host" and "I'm watching this host".

**Caveats:** Linux-only at first (eBPF maturity). Significant new dependency surface (libbpf or libbpfgo). Best done as a separate `digger.runtime` subsystem so the snapshot path stays Python-only.

#### L. ATT&CK coverage heatmap (derived from ART × digger detector tags)  (MEDIUM value, LOW effort)

**Source:** derive from Atomic Red Team's technique list + digger's per-detector `mitre` tags. No external license issue — both are MIT.

**Why it matters:** today the docs claim digger covers ~60 ATT&CK techniques but it's a hand-counted assertion. A real heatmap would render a matrix: ATT&CK technique × digger-covered? Click a technique → see which detector(s) flag it. Renders to ATT&CK Navigator JSON (already supported via `digger export attack-navigator`).

**How to integrate:** new `digger generate coverage` subcommand. Walks `all_detectors()` extracting `mitre` tags from every Finding-emitting site (AST inspection if needed). Cross-references with ART's technique manifest. Outputs Navigator-layer JSON + a Markdown summary.

### Round 2 — updated recommended order

| Order | Candidate | Why prioritized |
|---|---|---|
| 1 | **A. ForensicArtifacts ingestion** (Round 1) | Still highest value × lowest effort overall |
| 2 | **H. Atomic Red Team validation harness** | Once we have it, every detector's accuracy becomes measurable — turns subjective improvement into objective |
| 3 | **L. ATT&CK coverage heatmap** | Quick win, sets up #H by making the gap visible |
| 4 | **I. Aftermath-style storyline reconstruction** | Improves *every existing* report; no new collectors needed |
| 5 | **G. ELK/OpenSearch output** (Round 1) | Low effort, opens enterprise SIEM pipelines |
| 6 | **D. `digger watch` daemon** (Round 1) | Genuinely new capability class |
| 7 | **K. Falco-style eBPF runtime layer** | Bridges snapshot → continuous. Biggest architectural lift; do last |

— end Round 2 —

— end research notes —
