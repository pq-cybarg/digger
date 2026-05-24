"""Loader for Neo23x0/signature-base.

signature-base is a directory of three categories of content:

  yara/                  ~3000 YARA rules (.yar / .yara)
  iocs/                  Plain-text IOC lists used by LOKI/THOR:
    filename-iocs.txt    Regex per line; format `regex;description;score;owner`
    hash-iocs.txt        Hash IOCs; format `hash;description;score` (md5/sha1/sha256)
    c2-iocs.txt          C2 hosts/IPs/URLs; format `value;description;score`
    falsepositive-iocs.txt
    domain-iocs.txt
  misc/                  YARA-compatible rule snippets

We treat the directory as read-only data. The detector reads the
files at run time; tags are preserved end-to-end so findings cite the
exact upstream rule.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


DEFAULT_DIRS = [
    "~/.cache/digger/signature-base",
    "~/.local/share/signature-base",
    "/usr/local/share/signature-base",
    "/opt/signature-base",
]


def signature_base_dir() -> Path:
    """The signature-base path digger writes/reads. Override via env."""
    raw = os.environ.get("DIGGER_SIGNATURE_BASE_DIR")
    if raw:
        return Path(raw).expanduser()
    return Path("~/.cache/digger/signature-base").expanduser()


def discover_signature_base() -> Path | None:
    """Return the first existing signature-base path, or None."""
    raw = os.environ.get("DIGGER_SIGNATURE_BASE_DIR")
    candidates = [raw] if raw else DEFAULT_DIRS
    for cand in candidates:
        if not cand:
            continue
        p = Path(cand).expanduser()
        if p.is_dir() and (p / "iocs").is_dir():
            return p
    return None


@dataclass
class FilenameIOC:
    regex: str
    description: str
    score: int
    raw: str
    compiled: re.Pattern | None = None


@dataclass
class HashIOC:
    value: str        # lower-case hex
    kind: str         # "md5" | "sha1" | "sha256"
    description: str
    score: int


@dataclass
class C2IOC:
    value: str
    kind: str         # "ipv4" | "domain" | "url"
    description: str
    score: int


@dataclass
class SignatureBase:
    root: Path
    filename_iocs: list[FilenameIOC] = field(default_factory=list)
    hash_iocs: list[HashIOC] = field(default_factory=list)
    c2_iocs: list[C2IOC] = field(default_factory=list)
    false_positive_hashes: set[str] = field(default_factory=set)
    yara_rule_paths: list[Path] = field(default_factory=list)

    @property
    def is_loaded(self) -> bool:
        return bool(self.filename_iocs or self.hash_iocs or self.c2_iocs or self.yara_rule_paths)

    def summary(self) -> dict[str, int]:
        return {
            "filename_iocs": len(self.filename_iocs),
            "hash_iocs": len(self.hash_iocs),
            "c2_iocs": len(self.c2_iocs),
            "false_positive_hashes": len(self.false_positive_hashes),
            "yara_rule_files": len(self.yara_rule_paths),
        }


_HEX_LEN_TO_KIND = {32: "md5", 40: "sha1", 64: "sha256"}


def _parse_ioc_line(line: str, expected_fields: int = 3) -> list[str] | None:
    """signature-base lines are `;`-separated and may have varying fields."""
    s = line.strip()
    if not s or s.startswith("#") or s.startswith(";"):
        return None
    parts = [p.strip() for p in s.split(";")]
    # Pad / truncate to expected_fields
    while len(parts) < expected_fields:
        parts.append("")
    return parts


def _parse_score(field: str, default: int = 75) -> int:
    try:
        return int(field)
    except (ValueError, TypeError):
        return default


def _classify_c2(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return "url"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "ipv4"
    return "domain"


def load_signature_base(root: Path | None = None) -> SignatureBase:
    """Parse a signature-base directory into a SignatureBase struct."""
    if root is None:
        root = discover_signature_base()
    if root is None:
        return SignatureBase(root=signature_base_dir())
    if isinstance(root, str):
        root = Path(root)

    sb = SignatureBase(root=root)
    iocs_dir = root / "iocs"

    # filename-iocs.txt — `regex;description;score;owner`
    fn = iocs_dir / "filename-iocs.txt"
    if fn.exists():
        for raw in fn.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = _parse_ioc_line(raw, expected_fields=3)
            if not parts:
                continue
            regex, desc, score_s = parts[0], parts[1], parts[2]
            if not regex:
                continue
            try:
                compiled = re.compile(regex, re.I)
            except re.error:
                continue
            sb.filename_iocs.append(FilenameIOC(
                regex=regex, description=desc, score=_parse_score(score_s),
                raw=raw, compiled=compiled,
            ))

    # hash-iocs.txt — `hash;description;score`
    fh = iocs_dir / "hash-iocs.txt"
    if fh.exists():
        for raw in fh.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = _parse_ioc_line(raw, expected_fields=3)
            if not parts:
                continue
            h, desc, score_s = parts[0].lower(), parts[1], parts[2]
            if not re.match(r"^[a-f0-9]+$", h):
                continue
            kind = _HEX_LEN_TO_KIND.get(len(h))
            if not kind:
                continue
            sb.hash_iocs.append(HashIOC(
                value=h, kind=kind, description=desc, score=_parse_score(score_s),
            ))

    # c2-iocs.txt — `value;description;score`
    fc = iocs_dir / "c2-iocs.txt"
    if fc.exists():
        for raw in fc.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = _parse_ioc_line(raw, expected_fields=3)
            if not parts:
                continue
            value, desc, score_s = parts[0], parts[1], parts[2]
            if not value:
                continue
            sb.c2_iocs.append(C2IOC(
                value=value.lower(), kind=_classify_c2(value),
                description=desc, score=_parse_score(score_s),
            ))

    # falsepositive-iocs.txt — bare hashes
    ffp = iocs_dir / "falsepositive-iocs.txt"
    if ffp.exists():
        for raw in ffp.read_text(encoding="utf-8", errors="replace").splitlines():
            s = raw.strip().lower()
            if s and not s.startswith("#"):
                # first ";" delimited field
                sb.false_positive_hashes.add(s.split(";")[0])

    # YARA rules
    yara_root = root / "yara"
    if yara_root.is_dir():
        sb.yara_rule_paths = sorted(
            list(yara_root.glob("*.yar")) + list(yara_root.glob("*.yara"))
        )

    return sb


# Convenience: load and cache once per process.
_cached: SignatureBase | None = None


def cached() -> SignatureBase:
    global _cached
    if _cached is None:
        _cached = load_signature_base()
    return _cached


def reload() -> SignatureBase:
    global _cached
    _cached = load_signature_base()
    return _cached
