"""Analytic tradecraft modules."""

from __future__ import annotations

import pytest

from digger.tradecraft import (
    ACH, ANALYTIC_CONFIDENCE, ESTIMATIVE_PROBABILITY, ESTIMATIVE_RANGES,
    INFO_CREDIBILITY, SOURCE_RELIABILITY, TLP, apply_tlp_filter, build_matrix,
    can_share, rate_info, rate_source, validate_judgment,
)
from digger.tradecraft.icd203 import label_for_probability


def test_icd203_seven_labels_present():
    for label in ["almost no chance", "very unlikely", "unlikely",
                  "roughly even chance", "likely", "very likely", "almost certain"]:
        assert validate_judgment(label)
        lo, hi = ESTIMATIVE_RANGES[label]
        assert 0 <= lo < hi <= 1


def test_icd203_invalid_label_rejected():
    assert not validate_judgment("probably")
    assert not validate_judgment("maybe")


def test_label_for_probability_round_trips():
    for label, (lo, hi) in ESTIMATIVE_RANGES.items():
        mid = (lo + hi) / 2
        assert label_for_probability(mid) == label


def test_admiralty_codes():
    assert rate_source("A").startswith("Completely")
    assert rate_source("Z") == SOURCE_RELIABILITY["F"]
    assert rate_info("1").startswith("Confirmed")
    assert rate_info("9") == INFO_CREDIBILITY["6"]


def test_tlp_sharing_lattice():
    assert can_share(TLP.CLEAR, TLP.AMBER)
    assert not can_share(TLP.RED, TLP.AMBER)
    assert can_share(TLP.AMBER, TLP.RED)


def test_tlp_filter():
    findings = [
        {"title": "a", "tlp": "TLP:CLEAR"},
        {"title": "b", "tlp": "TLP:AMBER"},
        {"title": "c", "tlp": "TLP:RED"},
    ]
    result = apply_tlp_filter(findings, TLP.GREEN)
    titles = {f["title"] for f in result}
    assert titles == {"a"}


def test_ach_inconsistency_scoring():
    matrix = build_matrix(
        hypotheses=["H1: legitimate", "H2: malicious"],
        evidence=["E1: cron job", "E2: weird URL", "E3: signed binary"],
        ratings=[
            ["C", "C"],   # E1 consistent with both
            ["I", "C"],   # E2 inconsistent with H1
            ["C", "I"],   # E3 inconsistent with H2
        ],
    )
    inc = matrix.inconsistency_scores()
    assert inc == [1, 1]
    # tie-break by most consistent — both same here
    assert matrix.winning_hypothesis() in (0, 1)
