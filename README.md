# digger

Cross-platform, forensics-grade endpoint investigation suite with local-LLM triage.
Works on Windows, macOS, and Linux. Runs entirely on your machine. Sends nothing
to the cloud unless you point it there explicitly.

## What it does

1. **Collect** — pulls forensic artifacts from the running host (processes,
   network state, persistence mechanisms, browser data, system logs, scheduled
   tasks/services, kernel modules, authentication events, recent files, etc.)
   into a tamper-evident SQLite evidence store with paired SHA-256 + SHA3-256 hash chaining.
2. **Detect** — runs collected artifacts through a stack of detectors: YARA
   rules, IOC matching, persistence outlier analysis, network anomaly
   detection, LOLBin/LOLBAS usage, suspicious child-process trees, and more.
3. **Triage** — feeds suspicious findings into a local LLM (llama.cpp,
   ollama, or any OpenAI-compatible endpoint) for natural-language
   explanations, severity grading, and recommended next steps.
4. **Report** — produces JSON, Markdown, and self-contained HTML reports
   suitable for sharing with a SOC, embedding in a ticket, or archiving.

## Install

```bash
# Clone, then:
pip install -e .

# For YARA scanning, Windows registry parsing, GeoIP, etc:
pip install -e ".[all]"

# Dev:
pip install -e ".[dev]"
```

No build-time C extensions are required for the base install. Optional features
fall back gracefully when their libraries are missing.

## Quick start

```bash
# 1. Collect everything into ./case-2026-05-19/
digger collect --case-dir ./case-2026-05-19

# 2. Run detectors against the collected evidence
digger scan --case-dir ./case-2026-05-19

# 3. Triage findings through a local LLM (assumes llama.cpp on :8080)
digger triage --case-dir ./case-2026-05-19 \
    --llm-base-url http://127.0.0.1:8080/v1 \
    --llm-model GLM-4.6

# 4. Generate the report
digger report --case-dir ./case-2026-05-19 --format html --out report.html

# One-shot: collect + scan + triage + report
digger investigate --case-dir ./case-2026-05-19 --report report.html
```

Run with elevated privileges (`sudo` / `runas administrator`) for full
coverage — most collectors degrade gracefully without root, but several
artifacts (audit logs, EVTX, TCC database, unified logs, kernel modules)
require it.

## Local LLM setup

`digger` talks to any OpenAI-compatible `/v1/chat/completions` endpoint.
The two easiest paths:

### llama.cpp

```bash
# Pull a GLM-family GGUF
huggingface-cli download zai-org/GLM-4.6-GGUF GLM-4.6-Q4_K_M.gguf --local-dir ./models
# Or a Qwen, Llama-3.x, etc.

llama-server -m ./models/GLM-4.6-Q4_K_M.gguf \
    --host 127.0.0.1 --port 8080 \
    -c 32768 --jinja
```

### ollama

```bash
ollama serve
ollama pull qwen2.5:14b-instruct
digger triage --case-dir … \
    --llm-base-url http://127.0.0.1:11434/v1 --llm-model qwen2.5:14b-instruct
```

The LLM never receives raw file contents unless you opt in; only metadata,
detector findings, and short context windows. See `digger/ai/triage.py`.

## Architecture

```
digger/
├── core/         Evidence store, platform detection, hashing, runner
├── collectors/   common/, windows/, macos/, linux/ artifact collectors
├── detectors/    YARA, IOC, persistence, network, LOLBin, timeline
├── ai/           llama.cpp/OpenAI client, triage prompts
├── intel/        Threat-intel feed loaders
├── rules/        Bundled YARA, IOC lists, Sigma-style rules
└── report/       JSON, Markdown, HTML report renderers
```

Every collector inherits `digger.core.collector.Collector` and emits
`Artifact` rows into the evidence DB. Every detector inherits
`digger.detectors.base.Detector` and emits `Finding` rows. Reports and triage
operate on those two tables — nothing else.

## Safety and ethics

This tool is for analyzing **your own** machine, or machines you have
explicit authorization to inspect (your fleet, your client's fleet under
contract, a CTF box, etc.). Several detectors will pull, hash, and analyze
files you didn't write. Don't run this on machines you don't own without
permission. Don't ship the evidence DB anywhere it shouldn't go — it
contains process command lines, browser history, and other sensitive data
by design.

## License

MIT.
