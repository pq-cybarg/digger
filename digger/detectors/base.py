"""Base detector class.

Subclasses implement ``detect()`` to produce ``Finding`` objects from an
``EvidenceStore``. They MAY also implement ``to_sigma_template()`` to
declare a *generic* Sigma rule for the SIEM use case — independent of
any specific case finding. The generic rule is what `digger generate
sigma --from-detectors` exports; the per-finding rule (mapped by
``digger.genrule.sigma:finding_to_sigma``) is what `digger generate
sigma --case-dir ...` exports.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Optional

from digger.core.evidence import EvidenceStore, Finding


class Detector(ABC):
    name: str = ""
    description: str = ""

    @abstractmethod
    def detect(self, store: EvidenceStore) -> Iterable[Finding]:
        ...

    def to_sigma_template(self) -> Optional[dict]:
        """Return a generic Sigma rule for this detector, or None.

        The rule should match the *class* of behavior the detector
        watches for, not a specific instance. Output must be a dict
        with at minimum ``title``, ``id``, ``logsource``, ``detection``,
        and ``condition``; ``level`` and ``tags`` are recommended.

        Default: None — detectors that have no class-level Sigma form
        (e.g., the timeline builder) simply don't export.
        """
        return None

    def run(self, store: EvidenceStore) -> int:
        count = 0
        try:
            for finding in self.detect(store):
                store.add_finding(finding)
                count += 1
        except Exception as exc:
            store.log("error", f"detector {self.name} failed: {exc!r}")
        return count
