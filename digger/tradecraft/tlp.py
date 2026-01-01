"""Traffic Light Protocol 2.0 (FIRST.org standard).

Markings: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED.
Used by CISA, ENISA, FIRST CSIRTs, ISACs.

  CLEAR        — disclosure permitted without restriction
  GREEN        — disclosure limited to peer & partner organizations
  AMBER        — limited to recipient organization and clients on need-to-know
  AMBER+STRICT — limited to recipient organization only, no client sharing
  RED          — for named recipients only, no further sharing
"""

from __future__ import annotations

from enum import Enum


class TLP(str, Enum):
    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"

    @property
    def order(self) -> int:
        return _ORDER[self]


_ORDER = {
    TLP.CLEAR: 0,
    TLP.GREEN: 1,
    TLP.AMBER: 2,
    TLP.AMBER_STRICT: 3,
    TLP.RED: 4,
}

TLP_LEVELS = [t.value for t in TLP]


def can_share(item_tlp: TLP, sharing_level: TLP) -> bool:
    """True if a finding marked `item_tlp` may be shared at `sharing_level`.

    Sharing-level semantics: the export destination's allowed maximum
    sensitivity. e.g., exporting publicly = TLP.CLEAR; exporting to
    a trusted ISAC = TLP.AMBER.
    """
    return item_tlp.order <= sharing_level.order


def apply_tlp_filter(findings: list[dict], sharing_level: TLP) -> list[dict]:
    """Return only findings whose TLP marking is shareable at the given level."""
    out = []
    for f in findings:
        marking = f.get("tlp") or TLP.AMBER.value
        try:
            item = TLP(marking)
        except ValueError:
            item = TLP.AMBER
        if can_share(item, sharing_level):
            out.append(f)
    return out
