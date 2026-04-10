"""Tests for CI/CD integration analyzer."""

import pytest

from odcp.analyzers.ci import (
    CiAnalyzer,
    CiPolicy,
    CiResult,
    CiVerdict,
)
from odcp.models import (
    Dependency,
    DependencyKind,
    DependencyStatus,
    Detection,
    Environment,
    Finding,
    FindingCategory,
    FindingSeverity,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ScanReport,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(
    *,
    detections: list[Detection] | None = None,
    readiness_scores: list[ReadinessScore] | None = None,
    findings: list[Finding] | None = None,
    overall_score: float = 0.8,
    runnable: int = 4,
    blocked: int = 1,
    total: int = 5,
) -> ScanReport:
    dets = detections or [
        Detection(id=f"det-{i}", name=f"Detection {i}", search_query=f"index=test{i}")
        for i in range(total)
    ]
    scores = readiness_scores or [
        ReadinessScore(
            detection_id=f"det-{i}",
            detection_name=f"Detection {i}",
            status=ReadinessStatus.blocked if i < blocked else ReadinessStatus.runnable,
            score=0.0 if i < blocked else 1.0,
        )
        for i in range(total)
    ]
    from odcp.models.report import ReadinessSummary
    return ScanReport(
        environment=Environment(
            name="Test",
            platforms=[Platform(name="splunk", vendor="splunk", adapter_type="splunk")],
        ),
        detections=dets,
        readiness_scores=scores,
        readiness_summary=ReadinessSummary(
            total_detections=total,
            runnable=runnable,
            blocked=blocked,
            overall_score=overall_score,
        ),
        findings=findings or [],
    )


# ---------------------------------------------------------------------------
# Single-report analysis
# ---------------------------------------------------------------------------

class TestAnalyzeSingle:
    def test_passes_with_default_policy(self) -> None:
        report = _make_report()
        result = CiAnalyzer().analyze_single(report)
        assert result.verdict == CiVerdict.passed
        assert result.exit_code == 0

    def test_fails_when_score_below_threshold(self) -> None:
        report = _make_report(overall_score=0.3)
        policy = CiPolicy(min_readiness_score=0.5)
        result = CiAnalyzer(policy).analyze_single(report)
        assert result.verdict == CiVerdict.failed
        assert result.exit_code == 1
        assert any(v.rule == "min_readiness_score" for v in result.policy_violations)

    def test_fails_when_blocked_ratio_exceeded(self) -> None:
        report = _make_report(blocked=4, runnable=1, total=5)
        policy = CiPolicy(max_blocked_ratio=0.5)
        result = CiAnalyzer(policy).analyze_single(report)
        assert result.verdict == CiVerdict.failed
        assert any(v.rule == "max_blocked_ratio" for v in result.policy_violations)

    def test_fails_when_critical_findings_exceeded(self) -> None:
        findings = [
            Finding(
                detection_id="det-0",
                category=FindingCategory.missing_dependency,
                severity=FindingSeverity.critical,
                title="Critical issue",
                description="Something critical",
            )
            for _ in range(3)
        ]
        report = _make_report(findings=findings)
        policy = CiPolicy(max_critical_findings=2)
        result = CiAnalyzer(policy).analyze_single(report)
        assert result.verdict == CiVerdict.failed
        assert any(v.rule == "max_critical_findings" for v in result.policy_violations)

    def test_warning_when_high_findings_exceeded(self) -> None:
        findings = [
            Finding(
                detection_id="det-0",
                category=FindingCategory.missing_dependency,
                severity=FindingSeverity.high,
                title="High issue",
                description="Something high",
            )
            for _ in range(5)
        ]
        report = _make_report(findings=findings)
        policy = CiPolicy(max_high_findings=3)
        result = CiAnalyzer(policy).analyze_single(report)
        assert result.verdict == CiVerdict.warning
        assert result.exit_code == 0
        assert any(v.rule == "max_high_findings" for v in result.policy_violations)

    def test_passes_at_exact_threshold(self) -> None:
        report = _make_report(overall_score=0.5)
        policy = CiPolicy(min_readiness_score=0.5)
        result = CiAnalyzer(policy).analyze_single(report)
        assert result.verdict == CiVerdict.passed

    def test_summary_includes_counts(self) -> None:
        report = _make_report(total=10, runnable=7, blocked=3, overall_score=0.7)
        result = CiAnalyzer().analyze_single(report)
        assert "10 detections" in result.summary
        assert result.total_detections == 10


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------

class TestCompare:
    def test_no_regressions_passes(self) -> None:
        baseline = _make_report(overall_score=0.6)
        current = _make_report(overall_score=0.8)
        result = CiAnalyzer().compare(baseline, current)
        assert result.verdict == CiVerdict.passed
        assert len(result.regressions) == 0

    def test_regression_detected(self) -> None:
        baseline_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ]
        current_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.blocked, score=0.0,
            ),
        ]
        baseline = _make_report(
            readiness_scores=baseline_scores, total=1, runnable=1, blocked=0, overall_score=1.0
        )
        current = _make_report(
            readiness_scores=current_scores, total=1, runnable=0, blocked=1, overall_score=0.0
        )
        result = CiAnalyzer().compare(baseline, current)
        assert result.verdict == CiVerdict.failed
        assert len(result.regressions) == 1
        assert result.regressions[0].detection_id == "det-1"

    def test_improvement_detected(self) -> None:
        baseline_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.blocked, score=0.0,
            ),
        ]
        current_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ]
        baseline = _make_report(
            readiness_scores=baseline_scores, total=1, runnable=0, blocked=1, overall_score=0.0
        )
        current = _make_report(
            readiness_scores=current_scores, total=1, runnable=1, blocked=0, overall_score=1.0
        )
        policy = CiPolicy(fail_on_regression=False)
        result = CiAnalyzer(policy).compare(baseline, current)
        assert result.verdict == CiVerdict.passed
        assert len(result.improvements) == 1

    def test_new_detections_counted(self) -> None:
        baseline_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ]
        current_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.runnable, score=1.0,
            ),
            ReadinessScore(
                detection_id="det-2", detection_name="Det 2",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ]
        baseline = _make_report(
            readiness_scores=baseline_scores, total=1, runnable=1, blocked=0, overall_score=1.0
        )
        current = _make_report(
            readiness_scores=current_scores, total=2, runnable=2, blocked=0, overall_score=1.0
        )
        result = CiAnalyzer().compare(baseline, current)
        assert result.new_detections == 1
        assert result.removed_detections == 0

    def test_removed_detections_counted(self) -> None:
        baseline_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.runnable, score=1.0,
            ),
            ReadinessScore(
                detection_id="det-2", detection_name="Det 2",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ]
        current_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ]
        baseline = _make_report(
            readiness_scores=baseline_scores, total=2, runnable=2, blocked=0, overall_score=1.0
        )
        current = _make_report(
            readiness_scores=current_scores, total=1, runnable=1, blocked=0, overall_score=1.0
        )
        result = CiAnalyzer().compare(baseline, current)
        assert result.removed_detections == 1

    def test_score_changes_tracked(self) -> None:
        baseline = _make_report(overall_score=0.6, total=5, runnable=3, blocked=2)
        current = _make_report(overall_score=0.8, total=5, runnable=4, blocked=1)
        policy = CiPolicy(fail_on_regression=False)
        result = CiAnalyzer(policy).compare(baseline, current)
        readiness_change = next(
            sc for sc in result.score_changes if sc.metric == "overall_readiness"
        )
        assert readiness_change.delta > 0
        assert readiness_change.baseline == 0.6
        assert readiness_change.current == 0.8

    def test_allow_regression_policy(self) -> None:
        baseline_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ]
        current_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.partially_runnable, score=0.5,
            ),
        ]
        baseline = _make_report(
            readiness_scores=baseline_scores, total=1, runnable=1, blocked=0, overall_score=1.0
        )
        current = _make_report(
            readiness_scores=current_scores, total=1, runnable=0, blocked=0, overall_score=0.5
        )
        policy = CiPolicy(fail_on_regression=False, fail_on_new_blocked=False)
        result = CiAnalyzer(policy).compare(baseline, current)
        assert result.verdict == CiVerdict.passed
        assert len(result.regressions) == 1  # still tracked, just not a failure

    def test_newly_blocked_detection_fails(self) -> None:
        baseline_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.runnable, score=1.0,
            ),
        ]
        current_scores = [
            ReadinessScore(
                detection_id="det-1", detection_name="Det 1",
                status=ReadinessStatus.blocked, score=0.0,
            ),
        ]
        baseline = _make_report(
            readiness_scores=baseline_scores, total=1, runnable=1, blocked=0, overall_score=1.0
        )
        current = _make_report(
            readiness_scores=current_scores, total=1, runnable=0, blocked=1, overall_score=0.0
        )
        policy = CiPolicy(fail_on_regression=False, fail_on_new_blocked=True)
        result = CiAnalyzer(policy).compare(baseline, current)
        assert result.verdict == CiVerdict.failed
        assert any(v.rule == "no_new_blocked" for v in result.policy_violations)
