"""Threat-hunting query library.

Hunts are exploratory queries over the evidence store. They differ from
detectors in three ways:

  1. **Tabular**, not finding-shaped. A hunt returns rows of columns —
     the analyst reviews them as data, not as alerts.
  2. **High recall, low precision is OK.** Detectors are designed to fire
     on confirmed-bad. Hunts cast a wider net; some rows will be benign.
     The point is to surface candidates for human inspection.
  3. **Composable / ad-hoc.** A hunt asks one specific question: "show
     me X." Combine hunts to answer the actual investigative question.

Each hunt has metadata (id, title, description, severity_hint, mitre,
columns) and a generator function ``run(store) -> Iterable[dict]`` that
yields one dict per result row.
"""

from digger.hunts.base import Hunt, HuntResult, register, all_hunts, run_hunt
from digger.hunts import library  # noqa: F401 — populates the registry on import

__all__ = ["Hunt", "HuntResult", "register", "all_hunts", "run_hunt"]
