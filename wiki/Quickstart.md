# Quickstart

```bash
git clone git@github.com:pq-cybarg/digger.git
cd digger
pip install -e ".[all,dev]"
```

## First scan against your own machine

```bash
digger collect --case-dir ./my-first-case
digger scan    --case-dir ./my-first-case
digger report  --case-dir ./my-first-case --format html --out report.html
open report.html
```

## With AI triage (optional)

Spin up a local LLM that talks OpenAI-compatible HTTP:

```bash
# llama.cpp
llama-server -m ./models/Qwen2.5-14B-Instruct-Q4_K_M.gguf \
    --host 127.0.0.1 --port 8080 -c 32768 --jinja

# Then:
digger triage --case-dir ./my-first-case \
    --llm-base-url http://127.0.0.1:8080/v1 \
    --llm-model Qwen2.5-14B-Instruct
```

The LLM never receives raw file contents — only metadata, finding
summaries, and short context windows. Output is schema-enforced under
ICD 203 + NATO Admiralty + TLP analytic tradecraft.

## With PQC-signed evidence

```bash
# Generates ML-DSA-65 keypair if --key doesn't exist; signs the chain tip.
digger pqc sign --case-dir ./my-first-case --key ./op.sk

# Later, anyone with op.sk.pub can verify:
digger pqc verify --case-dir ./my-first-case
```

## Run an ongoing intel-feed scheduler

```bash
# Foreground (Ctrl-C to stop):
digger intel watch

# One-shot refresh:
digger intel update

# Status (last-fetched age per feed + integrity signature state):
digger intel status

# Sign the cache so detectors warn on tampered files at scan time:
digger intel sign --key ./op.sk
```

## Investigate everything in one shot

```bash
digger investigate --case-dir ./case --report report.html
# collect + scan + triage + report
```

## What's next

- [Detector catalog](Detector-Catalog) — 28 detectors, MITRE tags
- [Threat intel feeds](Threat-Intel-Feeds) — what each feed adds
- [Ethical contract FAQ](Ethics-FAQ) — why the contract refuses certain operations
