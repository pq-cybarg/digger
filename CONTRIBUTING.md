# Contributing to digger

Thanks for opening a PR. Before you write code, please skim this — it'll
save you a round of review feedback.

## The non-negotiables

1. **Live-first.** Every detector that loads bundled rule data MUST
   also call `load_intel(...)` for the live equivalent first.
   `tests/test_data_freshness.py` enforces this via AST inspection
   and will fail your PR. If your detector consumes digger-native
   data with no upstream feed, add a `# live-first-ok: <reason>`
   comment with a non-empty reason explaining why.

2. **Ethics are load-bearing.** Anything that modifies host state must
   route through `digger.ethics.contract.confirm_remediation_intent()`.
   Destructive shell commands must pass through
   `redact_dangerous_command()`. Cross-host operations require
   `cross_host_allowed=True` + deconfliction documentation. The 19
   tests in `tests/test_ethics.py` are intentionally fragile — if you
   refactor a guardrail away, they break.

3. **Append-only evidence store.** `artifacts` and `findings` rows are
   never modified or deleted. The only writable column post-insert is
   `findings.triage_json` (deliberately outside the chain hashes).
   Renaming `collector`, `category`, or `subject` changes both hashes
   and invalidates downstream signatures.

4. **No PII in code or commits.** No hardcoded usernames, real emails,
   or personal hostnames in source. Use `analyst@localhost` / generic
   `/Users/analyst/` in samples and tests.

5. **Tests pass and add to coverage.** Full suite is 337 passing; PRs
   that drop coverage need a justification in the description.

## How to add a collector

```python
# digger/collectors/<platform>/my_collector.py
from typing import Iterable
from digger.core.collector import Collector
from digger.core.evidence import Artifact
from digger.core.platform import OS

class MyCollector(Collector):
    name         = "my_thing"           # unique
    category     = "persistence"        # grouping (process | network | persistence | …)
    supported_os = (OS.LINUX, OS.MACOS) # platforms this runs on
    requires_admin = False
    description  = "What it collects, in one line."

    def collect(self) -> Iterable[Artifact]:
        # Degrade gracefully: never raise from collect(). Catch
        # PermissionError, OSError, missing tools (shutil.which),
        # etc. and return empty if you can't run.
        yield self.make(
            subject="some-stable-identifier",
            **fields,
        )
```

Then register in `digger/collectors/__init__.py` under the right
platform helper (`_common`, `_windows`, `_macos`, or `_linux`).

## How to add a detector

```python
# digger/detectors/my_detector.py
from typing import Iterable
from digger.core.evidence import EvidenceStore, Finding
from digger.detectors._rules_io import load_intel, load_yaml
from digger.detectors.base import Detector

class MyDetector(Detector):
    name = "my_detector"
    description = "What it detects."

    def to_sigma_template(self) -> dict:
        # OPTIONAL: per-detector generic Sigma rule for SIEM export
        # via `digger generate sigma --from-detectors`.
        return { "title": "...", "logsource": {...}, "detection": {...} }

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        # LIVE-FIRST (this is the one that test_data_freshness checks):
        live = load_intel("my_feed_name") or {}
        if not live:
            bundled = load_yaml("my_topic/bundled.yaml") or {}
            # ... fall back to bundled
        for art in store.iter_artifacts(category="..."):
            # ... match logic
            yield Finding(
                detector=self.name,
                severity="medium",   # info | low | medium | high | critical
                title="...",
                summary="...",
                artifact_refs=[art["artifact_uuid"]],
                evidence={...},
                mitre="T1059",
            )
```

Then register in `digger/detectors/__init__.py:all_detectors()`. Order
is incidental except `TimelineBuilder` which must stay last.

## How to add a threat-intel feed

Most feeds are a single URL with a parser. Add to
`digger/intel/feeds.py:FEEDS`:

```python
Feed(
    name="my_feed",
    url="https://example.com/feed.json",
    interval=12 * 3600,
    parser=lambda raw: {"source": "example", "entries": json.loads(raw)},
    description="One-line description for `digger intel status`.",
),
```

Composite feeds that need multi-URL pagination (NVD, SigmaHQ corpus,
MITRE ATT&CK STIX) use the `fetch_fn` hook — see
`digger/intel/sources/nvd_cpe.py` for the template.

## How to add a compliance framework

Drop a YAML file under `digger/compliance/frameworks/<name>.yaml`.
Each control has zero or more `checks`. Supported predicates:
`artifact_present`, `artifact_count_min`, `no_finding_with_detector`,
`no_finding_with_mitre`, `no_finding_above`, `data_contains`,
`manual: true`. No code changes required.

## Pull-request checklist

- [ ] `python -m pytest tests/` — full suite green
- [ ] `ruff check digger/ tests/` — no lint errors
- [ ] If you added a detector, you also added Sigma generators in
      `digger/genrule/sigma.py` (per-finding) OR `to_sigma_template`
      on the detector (per-class), or both
- [ ] If you added a detector that loads bundled YAML, you wired
      `load_intel("...")` first
- [ ] If you added a destructive cmdline-emitter, it routes through
      `redact_dangerous_command`
- [ ] No hardcoded usernames, real emails, personal hostnames
- [ ] CHANGELOG.md entry if user-facing

## Coding conventions

- Python 3.11+. Type hints encouraged but not required.
- 4-space indent.
- Modules: catch platform-specific imports inside the function (e.g.,
  `import winreg` inside `collect()`, not at top level), so Windows
  imports don't break Linux.
- `psutil.process_iter()` can raise `AccessDenied` per-process. Always
  iterate with `attrs=[...]` to get partial info on processes you
  can't fully inspect.
- The ASCII banner prints by default. Pass `--no-banner` in scripts
  and tests.
- Browser SQLite DBs must be opened via
  `file:...?immutable=1&mode=ro` URI or they lock against the live
  browser.

## License

By contributing, you agree your contribution is licensed under MIT
(see [LICENSE](LICENSE)).
