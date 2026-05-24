"""IC analytic standards from ICD 203 / Sherman Kent / NIPF.

Two scales:
  ESTIMATIVE_PROBABILITY: the seven-step "words of estimative probability"
    ladder used across the US Intelligence Community since the Kent days
    and codified in ICD 203 (and aligned with the ODNI tradecraft
    standards). Each label has a numeric range we use to make the AI
    triage output computable.
  ANALYTIC_CONFIDENCE: a three-step ladder (low/moderate/high) for the
    analyst's confidence in the judgment itself — distinct from the
    probability of the event.

ICD 203 also requires properly:
  - Distinguishing analytic assessments from underlying source data.
  - Properly expressing and explaining uncertainties.
  - Explicitly stating assumptions and stating alternative judgments.
  - Citing sources with reliability.
The AI triage prompt in digger/ai/prompts.py implements these conventions.
"""

from __future__ import annotations

from typing import Optional

# Seven-step ladder. Numeric ranges are the official ODNI/Kent intervals
# (inclusive low, inclusive high).
ESTIMATIVE_PROBABILITY = [
    "almost no chance",
    "very unlikely",
    "unlikely",
    "roughly even chance",
    "likely",
    "very likely",
    "almost certain",
]

ESTIMATIVE_RANGES = {
    "almost no chance":   (0.01, 0.05),
    "very unlikely":      (0.05, 0.20),
    "unlikely":           (0.20, 0.45),
    "roughly even chance":(0.45, 0.55),
    "likely":             (0.55, 0.80),
    "very likely":        (0.80, 0.95),
    "almost certain":     (0.95, 0.99),
}

ANALYTIC_CONFIDENCE = ["low", "moderate", "high"]


def validate_judgment(label: str) -> bool:
    return label in ESTIMATIVE_PROBABILITY


def judgment_to_probability_range(label: str) -> Optional[tuple[float, float]]:
    return ESTIMATIVE_RANGES.get(label)


def label_for_probability(p: float) -> str:
    """Map a 0..1 probability to the closest IC label."""
    for label, (lo, hi) in ESTIMATIVE_RANGES.items():
        if lo <= p <= hi:
            return label
    return "roughly even chance"
