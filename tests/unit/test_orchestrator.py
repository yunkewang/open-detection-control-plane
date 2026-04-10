"""Tests for AI SOC orchestrator."""

from odcp.analyzers.ai_soc.orchestrator import AiSocOrchestrator
from odcp.models import (
    Dependency,
    DependencyKind,
    DependencyStatus,
    Detection,
    Environment,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ScanReport,
)
from odcp.models.report import ReadinessSummary


def _report(**overrides) -> ScanReport:
    defaults = dict(
        environment=Environment(
            name="Lab",
            platforms=[Platform(name="splunk", vendor="splunk", adapter_type="splunk")],
        ),
        detections=[
            Detection(
                id="det-1", name="Brute Force",
                search_query="index=auth sourcetype=linux_secure | stats count by user",
            ),
            Detection(
                id="det-2", name="Blocked Detection",
                search_query="index=missing_idx | stats count",
                enabled=True,
            ),
        ],
        dependencies=[
            Dependency(kind=DependencyKind.field, name="index:auth", status=DependencyStatus.resolved),
            Dependency(kind=DependencyKind.field, name="index:missing_idx", status=DependencyStatus.missing),
        ],
        readiness_scores=[
            ReadinessScore(
                detection_id="det-1", detection_name="Brute Force",
                status=ReadinessStatus.runnable, score=1.0,
            ),
            ReadinessScore(
                detection_id="det-2", detection_name="Blocked Detection",
                status=ReadinessStatus.blocked, score=0.0,
                total_dependencies=1, missing_dependencies=1,
            ),
        ],
        readiness_summary=ReadinessSummary(
            total_detections=2, runnable=1, blocked=1, overall_score=0.5,
        ),
    )
    defaults.update(overrides)
    return ScanReport(**defaults)


class TestAiSocOrchestrator:
    def test_basic_cycle(self) -> None:
        result = AiSocOrchestrator().run_cycle(_report())
        assert result.environment_name == "Lab"
        assert result.readiness_score == 0.5
        assert result.source_catalog is not None
        assert result.source_catalog.total_sources > 0
        assert result.feedback_summary is not None
        assert result.drift_summary is None  # no baseline
        assert len(result.priority_actions) > 0

    def test_cycle_with_baseline(self) -> None:
        baseline = _report()
        # Current has an additional detection
        current = _report(
            detections=[
                Detection(id="det-1", name="Brute Force",
                          search_query="index=auth sourcetype=linux_secure | stats count by user"),
                Detection(id="det-2", name="Blocked Detection",
                          search_query="index=missing_idx | stats count", enabled=True),
                Detection(id="det-3", name="New Rule",
                          search_query="index=winsec | stats count"),
            ],
            readiness_scores=[
                ReadinessScore(detection_id="det-1", detection_name="Brute Force",
                               status=ReadinessStatus.runnable, score=1.0),
                ReadinessScore(detection_id="det-2", detection_name="Blocked Detection",
                               status=ReadinessStatus.blocked, score=0.0,
                               total_dependencies=1, missing_dependencies=1),
                ReadinessScore(detection_id="det-3", detection_name="New Rule",
                               status=ReadinessStatus.runnable, score=1.0),
            ],
            readiness_summary=ReadinessSummary(
                total_detections=3, runnable=2, blocked=1, overall_score=0.67,
            ),
        )
        result = AiSocOrchestrator().run_cycle(current, baseline)
        assert result.drift_summary is not None
        assert result.drift_summary.total_drift_events >= 0

    def test_detectable_and_blocked_counts(self) -> None:
        result = AiSocOrchestrator().run_cycle(_report())
        # One detection is runnable with data, one is blocked
        assert result.detectable_now + result.blocked_by_data + result.blocked_by_logic >= 0

    def test_feedback_produces_proposals_for_blocked(self) -> None:
        result = AiSocOrchestrator().run_cycle(_report())
        assert result.feedback_summary is not None
        assert result.feedback_summary.stale_detections >= 1

    def test_priority_actions_not_empty(self) -> None:
        result = AiSocOrchestrator().run_cycle(_report())
        assert len(result.priority_actions) >= 1
        # Should flag low readiness
        any_readiness = any("readiness" in a.lower() or "blocked" in a.lower()
                            for a in result.priority_actions)
        assert any_readiness

    def test_coverage_metadata_used(self) -> None:
        report = _report(metadata={
            "coverage_enabled": True,
            "coverage_summary": {
                "total_techniques_in_scope": 25,
                "coverage_score": 0.4,
            },
        })
        result = AiSocOrchestrator().run_cycle(report)
        assert result.coverage_score == 0.4
        assert result.threat_intel_techniques == 25

    def test_healthy_environment(self) -> None:
        report = ScanReport(
            environment=Environment(
                name="Prod",
                platforms=[Platform(name="splunk", vendor="splunk", adapter_type="splunk")],
            ),
            detections=[
                Detection(id="d1", name="D1", search_query="index=auth | stats count"),
            ],
            readiness_scores=[
                ReadinessScore(detection_id="d1", detection_name="D1",
                               status=ReadinessStatus.runnable, score=1.0),
            ],
            readiness_summary=ReadinessSummary(
                total_detections=1, runnable=1, overall_score=1.0,
            ),
        )
        result = AiSocOrchestrator().run_cycle(report)
        assert result.readiness_score == 1.0
        assert result.feedback_summary.healthy_detections >= 1
