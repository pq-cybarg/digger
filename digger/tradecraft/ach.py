"""Analysis of Competing Hypotheses (Heuer, 1999; ODNI SAT 5).

A structured analytic technique to defend against confirmation bias.
The analyst enumerates competing hypotheses, lists relevant evidence,
then for each (hypothesis, evidence) pair marks whether the evidence
is Consistent, Inconsistent, or Not Applicable to that hypothesis.

The "winning" hypothesis is the one that minimizes *inconsistencies* —
not the one with the most consistencies (which biases toward the obvious).

digger uses ACH to express AI triage output for higher-severity
findings where multiple explanations are plausible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Rating = Literal["C", "I", "NA"]  # Consistent / Inconsistent / Not Applicable


@dataclass
class ACH:
    hypotheses: list[str]
    evidence: list[str]
    # matrix[evidence_idx][hypothesis_idx] = rating
    matrix: list[list[Rating]] = field(default_factory=list)
    notes: dict[tuple[int, int], str] = field(default_factory=dict)

    def inconsistency_scores(self) -> list[int]:
        scores = [0] * len(self.hypotheses)
        for row in self.matrix:
            for j, r in enumerate(row):
                if r == "I":
                    scores[j] += 1
        return scores

    def consistency_scores(self) -> list[int]:
        scores = [0] * len(self.hypotheses)
        for row in self.matrix:
            for j, r in enumerate(row):
                if r == "C":
                    scores[j] += 1
        return scores

    def winning_hypothesis(self) -> int:
        """Index of the hypothesis with the fewest inconsistencies (ties broken by most-consistent)."""
        inc = self.inconsistency_scores()
        con = self.consistency_scores()
        best, best_inc, best_con = 0, inc[0], con[0]
        for j in range(1, len(self.hypotheses)):
            if inc[j] < best_inc or (inc[j] == best_inc and con[j] > best_con):
                best, best_inc, best_con = j, inc[j], con[j]
        return best

    def to_dict(self) -> dict:
        return {
            "hypotheses": self.hypotheses,
            "evidence": self.evidence,
            "matrix": self.matrix,
            "inconsistency_scores": self.inconsistency_scores(),
            "consistency_scores": self.consistency_scores(),
            "winning_index": self.winning_hypothesis(),
            "winning_hypothesis": self.hypotheses[self.winning_hypothesis()] if self.hypotheses else None,
        }


def build_matrix(hypotheses: list[str], evidence: list[str], ratings: list[list[Rating]]) -> ACH:
    if len(ratings) != len(evidence):
        raise ValueError("ratings rows must equal number of evidence items")
    for row in ratings:
        if len(row) != len(hypotheses):
            raise ValueError("each ratings row must equal number of hypotheses")
    return ACH(hypotheses=hypotheses, evidence=evidence, matrix=ratings)
