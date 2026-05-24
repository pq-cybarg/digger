"""YARA scanning of files referenced by collected artifacts.

Uses `yara-python` if available (optional dependency). Compiles every
`.yar` / `.yara` rule under `digger/rules/yara/` plus any extra dirs.
Scans:
    - exe files of running processes
    - recently-modified files in drop locations
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from digger.core.evidence import EvidenceStore, Finding
from digger.detectors.base import Detector

_RULES_DIR = Path(__file__).parent.parent / "rules" / "yara"


class YaraDetector(Detector):
    name = "yara"
    description = "YARA rule matches against process executables and recently modified files."

    def __init__(self, extra_dirs: Iterable[Path] = ()):
        self.extra_dirs = list(extra_dirs)

    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        try:
            import yara  # type: ignore[import-not-found]
        except ImportError:
            store.log("info", "yara-python not installed, skipping YARA scan")
            return

        rule_files: list[Path] = []
        for d in [_RULES_DIR, *self.extra_dirs]:
            if d.is_dir():
                rule_files += list(d.glob("*.yar")) + list(d.glob("*.yara"))
        # signature-base YARA rules if available
        try:
            from digger.loki.signature_base import cached as _sb_cached
            sb = _sb_cached()
            if sb.is_loaded and sb.yara_rule_paths:
                rule_files += sb.yara_rule_paths
                store.log("info", f"yara: loaded {len(sb.yara_rule_paths)} rules from signature-base")
        except Exception:
            pass
        if not rule_files:
            store.log("info", "no YARA rules found")
            return

        rules = yara.compile(filepaths={f.stem: str(f) for f in rule_files})

        targets: set[str] = set()
        for art in store.iter_artifacts(collector="processes"):
            exe = art["data"].get("exe")
            if exe:
                targets.add(exe)
        for art in store.iter_artifacts(collector="recent_files"):
            for e in art["data"].get("entries") or []:
                if e.get("executable"):
                    targets.add(e["path"])

        for path in targets:
            try:
                matches = rules.match(path)
            except (yara.Error, PermissionError, OSError):
                continue
            for m in matches or []:
                yield Finding(
                    detector=self.name,
                    severity="high",
                    title=f"YARA match: rule {m.rule} on {path}",
                    summary=(
                        f"YARA rule '{m.rule}' (namespace {m.namespace}) "
                        f"matched file {path}. Tags: {m.tags}. "
                        "Confirm with a sandbox or AV vendor before treating as TP."
                    ),
                    artifact_refs=[],
                    evidence={
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "tags": m.tags,
                        "path": path,
                    },
                )
