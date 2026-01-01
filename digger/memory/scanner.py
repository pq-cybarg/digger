"""YARA-on-memory.

If yara-python is available, compile every YARA rule under
``digger/rules/yara/`` plus any extras (including signature-base when
present) and match against dumped region bytes. Returns the list of
matched rule names per region.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from digger.memory.maps import MemoryRegion
from digger.memory.dumper import dump_region


_BUNDLED_RULES_DIR = Path(__file__).parent.parent / "rules" / "yara"


def _compile_rules():
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        return None
    rule_files: list[Path] = []
    if _BUNDLED_RULES_DIR.is_dir():
        rule_files += list(_BUNDLED_RULES_DIR.glob("*.yar"))
        rule_files += list(_BUNDLED_RULES_DIR.glob("*.yara"))
    # signature-base YARA if present
    try:
        from digger.loki.signature_base import cached as _sb_cached
        sb = _sb_cached()
        if sb.is_loaded and sb.yara_rule_paths:
            rule_files += sb.yara_rule_paths
    except Exception:
        pass
    if not rule_files:
        return None
    return yara.compile(filepaths={f.stem: str(f) for f in rule_files})


def yara_scan_region(region: MemoryRegion, rules=None,
                     max_bytes: int = 16 * 1024 * 1024) -> list[dict]:
    """Dump region (best-effort) and YARA-scan the bytes.

    Returns a list of match dicts: ``[{rule, namespace, tags}]``.
    Empty list if the dump failed, no rules compiled, or no matches.
    """
    if rules is None:
        rules = _compile_rules()
    if rules is None:
        return []
    data = dump_region(region, max_bytes=max_bytes)
    if not data:
        return []
    try:
        matches = rules.match(data=data)
    except Exception:
        return []
    return [
        {"rule": m.rule, "namespace": m.namespace, "tags": list(m.tags or [])}
        for m in (matches or [])
    ]
