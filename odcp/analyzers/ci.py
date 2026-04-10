"""CI/CD integration analyzer.

Compares two scan reports (baseline vs. current) to detect regressions,
improvements, and policy violations suitable for automated gating in
CI/CD pipelines.
"""

from __future__ import annotations

import logging
from enum import Enum

from pydantic import BaseModel, Field

from odcp.models.report import ScanReport
from odcp.models.scoring import ReadinessStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CiVerdict(str, Enum):
    """Overall CI gate verdict."""

    passed = "passed"
    failed = "failed"
    warning = "warning"


class CiPolicyViolation(BaseModel):
    """A single policy violation detected during CI analysis."""

    rule: str
    severity: str  # "error" | "warning"
    message: str
    detection_id: str | None = None
    detection_name: str | None = None


class ScoreChange(BaseModel):
    """Change in a numeric score between baseline and current."""

    metric: str
    baseline: float
    current: float
    delta: float


class DetectionRegression(BaseModel):
    """A detection whose readiness worsened between baseline and current."""

    detection_id: str
    detection_name: str
    baseline_status: str
    current_status: str
    baseline_score: float
    current_score: float


class DetectionImprovement(BaseModel):
    """A detection whose readiness improved between baseline and current."""

    detection_id: str
    detection_name: str
    baseline_status: str
    current_status: str
    baseline_score: float
    current_score: float


class CiResult(BaseModel):
    """Full result of a CI/CD analysis run."""

    verdict: CiVerdict
    exit_code: int = 0
    summary: str = ""
    score_changes: list[ScoreChange] = Field(default_factory=list)
    regressions: list[DetectionRegression] = Field(default_factory=list)
    improvements: list[DetectionImprovement] = Field(default_factory=list)
    new_detections: int = 0
    removed_detections: int = 0
    policy_violations: list[CiPolicyViolation] = Field(default_factory=list)
    total_detections: int = 0
    total_findings: int = 0
    critical_findings: int = 0


# ---------------------------------------------------------------------------
# Default policy thresholds
# ---------------------------------------------------------------------------


class CiPolicy(BaseModel):
    """Configurable policy thresholds for CI gating."""

    min_readiness_score: float = 0.0
    max_blocked_ratio: float = 1.0
    fail_on_regression: bool = True
    fail_on_new_blocked: bool = True
    max_critical_findings: int = -1  # -1 = unlimited
    max_high_findings: int = -1


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class CiAnalyzer:
    """Analyze scan reports for CI/CD gating decisions."""

    def __init__(self, policy: CiPolicy | None = None) -> None:
        self.policy = policy or CiPolicy()

    def analyze_single(self, report: ScanReport) -> CiResult:
        """Analyze a single scan report against policy thresholds (no baseline)."""
        violations: list[CiPolicyViolation] = []
        rs = report.readiness_summary

        # Count findings by severity
        critical_count = sum(
            1 for f in report.findings if f.severity.value == "critical"
        )
        high_count = sum(
            1 for f in report.findings if f.severity.value == "high"
        )

        # Policy: minimum readiness score
        if self.policy.min_readiness_score > 0 and rs.overall_score < self.policy.min_readiness_score:
            violations.append(CiPolicyViolation(
                rule="min_readiness_score",
                severity="error",
                message=(
                    f"Readiness score {rs.overall_score:.0%} is below minimum "
                    f"threshold {self.policy.min_readiness_score:.0%}"
                ),
            ))

        # Policy: max blocked ratio
        if rs.total_detections > 0:
            blocked_ratio = rs.blocked / rs.total_detections
            if blocked_ratio > self.policy.max_blocked_ratio:
                violations.append(CiPolicyViolation(
                    rule="max_blocked_ratio",
                    severity="error",
                    message=(
                        f"Blocked ratio {blocked_ratio:.0%} "
                        f"({rs.blocked}/{rs.total_detections}) exceeds maximum "
                        f"threshold {self.policy.max_blocked_ratio:.0%}"
                    ),
                ))

        # Policy: critical findings cap
        if self.policy.max_critical_findings >= 0 and critical_count > self.policy.max_critical_findings:
            violations.append(CiPolicyViolation(
                rule="max_critical_findings",
                severity="error",
                message=(
                    f"{critical_count} critical findings exceed limit of "
                    f"{self.policy.max_critical_findings}"
                ),
            ))

        # Policy: high findings cap
        if self.policy.max_high_findings >= 0 and high_count > self.policy.max_high_findings:
            violations.append(CiPolicyViolation(
                rule="max_high_findings",
                severity="warning",
                message=(
                    f"{high_count} high-severity findings exceed limit of "
                    f"{self.policy.max_high_findings}"
                ),
            ))

        errors = [v for v in violations if v.severity == "error"]
        warnings = [v for v in violations if v.severity == "warning"]

        if errors:
            verdict = CiVerdict.failed
            exit_code = 1
        elif warnings:
            verdict = CiVerdict.warning
            exit_code = 0
        else:
            verdict = CiVerdict.passed
            exit_code = 0

        summary = (
            f"{rs.total_detections} detections: "
            f"{rs.runnable} runnable, {rs.blocked} blocked, "
            f"score {rs.overall_score:.0%}. "
            f"Verdict: {verdict.value}."
        )

        return CiResult(
            verdict=verdict,
            exit_code=exit_code,
            summary=summary,
            total_detections=rs.total_detections,
            total_findings=len(report.findings),
            critical_findings=critical_count,
            policy_violations=violations,
        )

    def compare(
        self,
        baseline: ScanReport,
        current: ScanReport,
    ) -> CiResult:
        """Compare baseline and current scan reports to detect regressions."""
        violations: list[CiPolicyViolation] = []
        rs_base = baseline.readiness_summary
        rs_curr = current.readiness_summary

        # Score changes
        score_changes: list[ScoreChange] = []
        score_delta = rs_curr.overall_score - rs_base.overall_score
        score_changes.append(ScoreChange(
            metric="overall_readiness",
            baseline=rs_base.overall_score,
            current=rs_curr.overall_score,
            delta=round(score_delta, 4),
        ))

        if rs_base.total_detections > 0 and rs_curr.total_detections > 0:
            base_blocked_ratio = rs_base.blocked / rs_base.total_detections
            curr_blocked_ratio = rs_curr.blocked / rs_curr.total_detections
            score_changes.append(ScoreChange(
                metric="blocked_ratio",
                baseline=round(base_blocked_ratio, 4),
                current=round(curr_blocked_ratio, 4),
                delta=round(curr_blocked_ratio - base_blocked_ratio, 4),
            ))

        # Per-detection regressions and improvements
        base_scores = {s.detection_id: s for s in baseline.readiness_scores}
        curr_scores = {s.detection_id: s for s in current.readiness_scores}

        regressions: list[DetectionRegression] = []
        improvements: list[DetectionImprovement] = []

        for det_id, curr_s in curr_scores.items():
            base_s = base_scores.get(det_id)
            if base_s is None:
                continue  # new detection, not a regression

            if curr_s.score < base_s.score:
                regressions.append(DetectionRegression(
                    detection_id=det_id,
                    detection_name=curr_s.detection_name,
                    baseline_status=base_s.status.value,
                    current_status=curr_s.status.value,
                    baseline_score=base_s.score,
                    current_score=curr_s.score,
                ))
            elif curr_s.score > base_s.score:
                improvements.append(DetectionImprovement(
                    detection_id=det_id,
                    detection_name=curr_s.detection_name,
                    baseline_status=base_s.status.value,
                    current_status=curr_s.status.value,
                    baseline_score=base_s.score,
                    current_score=curr_s.score,
                ))

        # New / removed detections
        base_ids = set(base_scores.keys())
        curr_ids = set(curr_scores.keys())
        new_dets = len(curr_ids - base_ids)
        removed_dets = len(base_ids - curr_ids)

        # Check for newly blocked detections
        newly_blocked: list[DetectionRegression] = []
        for r in regressions:
            if r.current_status == ReadinessStatus.blocked.value and r.baseline_status != ReadinessStatus.blocked.value:
                newly_blocked.append(r)

        # Policy enforcement
        if self.policy.fail_on_regression and regressions:
            violations.append(CiPolicyViolation(
                rule="no_regressions",
                severity="error",
                message=f"{len(regressions)} detection(s) regressed in readiness score",
            ))

        if self.policy.fail_on_new_blocked and newly_blocked:
            for nb in newly_blocked:
                violations.append(CiPolicyViolation(
                    rule="no_new_blocked",
                    severity="error",
                    message=f"Detection '{nb.detection_name}' became blocked",
                    detection_id=nb.detection_id,
                    detection_name=nb.detection_name,
                ))

        # Also run single-report policy checks on current
        single_result = self.analyze_single(current)
        violations.extend(single_result.policy_violations)

        errors = [v for v in violations if v.severity == "error"]
        warnings = [v for v in violations if v.severity == "warning"]

        if errors:
            verdict = CiVerdict.failed
            exit_code = 1
        elif warnings:
            verdict = CiVerdict.warning
            exit_code = 0
        else:
            verdict = CiVerdict.passed
            exit_code = 0

        summary = (
            f"Baseline: {rs_base.overall_score:.0%} -> Current: {rs_curr.overall_score:.0%} "
            f"(delta {score_delta:+.0%}). "
            f"{len(regressions)} regressions, {len(improvements)} improvements, "
            f"{new_dets} new, {removed_dets} removed. "
            f"Verdict: {verdict.value}."
        )

        return CiResult(
            verdict=verdict,
            exit_code=exit_code,
            summary=summary,
            score_changes=score_changes,
            regressions=regressions,
            improvements=improvements,
            new_detections=new_dets,
            removed_detections=removed_dets,
            policy_violations=violations,
            total_detections=rs_curr.total_detections,
            total_findings=len(current.findings),
            critical_findings=single_result.critical_findings,
        )
