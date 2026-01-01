"""Hunt registration + execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from digger.core.evidence import EvidenceStore


@dataclass
class Hunt:
    id: str
    title: str
    description: str
    columns: list[str]
    fn: Callable[[EvidenceStore], Iterable[dict]]
    severity_hint: str = "low"     # info | low | medium | high | critical
    mitre: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class HuntResult:
    hunt: Hunt
    rows: list[dict] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.rows)


_REGISTRY: dict[str, Hunt] = {}


def register(hunt: Hunt) -> Hunt:
    """Add a hunt to the global registry. Returns the hunt for chaining."""
    if hunt.id in _REGISTRY:
        raise ValueError(f"duplicate hunt id {hunt.id!r}")
    _REGISTRY[hunt.id] = hunt
    return hunt


def all_hunts() -> list[Hunt]:
    return sorted(_REGISTRY.values(), key=lambda h: h.id)


def run_hunt(store: EvidenceStore, hunt_id: str) -> HuntResult:
    if hunt_id not in _REGISTRY:
        raise KeyError(f"unknown hunt: {hunt_id!r}")
    h = _REGISTRY[hunt_id]
    rows = list(h.fn(store))
    return HuntResult(hunt=h, rows=rows)
