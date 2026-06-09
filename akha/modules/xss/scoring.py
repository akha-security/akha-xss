"""
Unified confidence scoring model for XSS findings.

Provides a calibrated, evidence-based confidence score that replaces
ad-hoc scoring scattered across the codebase. Each piece of evidence
contributes independently and scores are clamped to [0, 100].

Severity levels:
  - confirmed  : strong evidence of exploitable XSS (score >= 80)
  - high       : very likely exploitable (score 60-79)
  - medium     : possible XSS, needs manual review (score 40-59)
  - low        : reflection only, unlikely exploitable (score < 40)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_score(cls, score: int) -> "Severity":
        if score >= 80:
            return cls.CONFIRMED
        if score >= 60:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class Evidence:
    """A single piece of evidence contributing to the confidence score."""
    name: str
    points: int
    detail: str = ""


@dataclass
class ScoringResult:
    """Final scored result for a finding."""
    score: int
    severity: Severity
    exploitability_score: int
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity.value,
            "exploitability_score": self.exploitability_score,
            "evidence": [
                {"name": e.name, "points": e.points, "detail": e.detail}
                for e in self.evidence
            ],
        }


class ConfidenceScorer:
    """
    Calculates a unified confidence score from multiple evidence signals.

    Usage::

        scorer = ConfidenceScorer()
        result = scorer.score(
            marker_in_tag=True,
            payload_reflected_raw=True,
            reverify_ok=True,
            browser_executed=True,
            browser_method="js_variable",
            diff_has_suspicious=True,
            diff_high_severity=False,
            context_executable=True,
        )
        print(result.score, result.severity)
    """

    MARKER_IN_TAG = 35
    PAYLOAD_RAW = 20
    REVERIFY_BONUS = 15
    BROWSER_DIALOG = 30       # JS dialog (alert/confirm/prompt) fired
    BROWSER_CONSOLE = 25      # Console marker detected
    BROWSER_DOM = 20          # DOM mutation detected
    DIFF_SUSPICIOUS = 5
    DIFF_HIGH_SEVERITY = 10
    STRUCTURAL_DOM_EVIDENCE = 8
    CONTEXT_EXECUTABLE = 5

    REPRO_STRONG = 8
    REPRO_WEAK = -8

    NO_REVERIFY_PENALTY = -10
    NO_MARKER_NO_RAW_PENALTY = -20

    def score(
        self,
        *,
        marker_in_tag: bool = False,
        payload_reflected_raw: bool = False,
        reverify_ok: bool = False,
        browser_executed: bool = False,
        browser_method: Optional[str] = None,
        diff_has_suspicious: bool = False,
        diff_high_severity: bool = False,
        structural_dom_evidence: bool = False,
        reproducibility_ratio: Optional[float] = None,
        context_executable: bool = False,
    ) -> ScoringResult:
        evidence: List[Evidence] = []
        total = 0

        if marker_in_tag:
            e = Evidence("marker_in_tag", self.MARKER_IN_TAG,
                         "Verification marker found inside a real HTML tag")
            evidence.append(e)
            total += e.points

        if payload_reflected_raw:
            e = Evidence("payload_raw", self.PAYLOAD_RAW,
                         "Full payload reflected unencoded in response")
            evidence.append(e)
            total += e.points

        if reverify_ok:
            e = Evidence("reverify", self.REVERIFY_BONUS,
                         "Consistent reflection across multiple requests")
            evidence.append(e)
            total += e.points
        elif marker_in_tag or payload_reflected_raw:
            e = Evidence("no_reverify", self.NO_REVERIFY_PENALTY,
                         "Single-shot only — could not confirm consistency")
            evidence.append(e)
            total += e.points

        if browser_executed:
            if browser_method == "js_variable":
                pts = self.BROWSER_DIALOG
                detail = "JS execution confirmed via alert/dialog hook"
            elif browser_method == "console_hook":
                pts = self.BROWSER_CONSOLE
                detail = "JS execution confirmed via console marker"
            else:
                pts = self.BROWSER_DOM
                detail = f"JS execution confirmed via {browser_method or 'DOM mutation'}"
            e = Evidence("browser_execution", pts, detail)
            evidence.append(e)
            total += e.points

        if diff_has_suspicious:
            e = Evidence("html_diff", self.DIFF_SUSPICIOUS,
                         "Suspicious DOM structural changes detected")
            evidence.append(e)
            total += e.points

        if diff_high_severity:
            e = Evidence("html_diff_high", self.DIFF_HIGH_SEVERITY,
                         "High-severity structural injection (script/iframe/svg)")
            evidence.append(e)
            total += e.points

        if structural_dom_evidence:
            e = Evidence("structural_dom_evidence", self.STRUCTURAL_DOM_EVIDENCE,
                         "DOM-level structural changes support exploitability")
            evidence.append(e)
            total += e.points

        if reproducibility_ratio is not None:
            ratio = max(0.0, min(1.0, float(reproducibility_ratio)))
            if ratio >= 0.9:
                e = Evidence("reproducibility_strong", self.REPRO_STRONG,
                             f"Payload reproduced consistently (ratio={ratio:.2f})")
                evidence.append(e)
                total += e.points
            elif ratio < 0.67:
                e = Evidence("reproducibility_weak", self.REPRO_WEAK,
                             f"Payload reflection unstable (ratio={ratio:.2f})")
                evidence.append(e)
                total += e.points

        if context_executable:
            e = Evidence("context_exec", self.CONTEXT_EXECUTABLE,
                         "Payload is in an executable context")
            evidence.append(e)
            total += e.points

        if not marker_in_tag and not payload_reflected_raw and not browser_executed:
            e = Evidence("no_primary_evidence", self.NO_MARKER_NO_RAW_PENALTY,
                         "No marker, no raw reflection, no browser execution")
            evidence.append(e)
            total += e.points

        score = max(0, min(100, total))
        severity = Severity.from_score(score)
        exploitability_score = max(0, min(100, score + (10 if browser_executed else 0)))
        if not browser_executed and (marker_in_tag or payload_reflected_raw):
            exploitability_score = min(exploitability_score, 70)

        return ScoringResult(
            score=score,
            severity=severity,
            exploitability_score=exploitability_score,
            evidence=evidence,
        )
