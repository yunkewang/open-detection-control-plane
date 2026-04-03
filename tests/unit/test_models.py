"""Tests for core pydantic models."""

from odcp.models import (
    Dependency,
    DependencyKind,
    DependencyStatus,
    Detection,
    DetectionSeverity,
    Environment,
    Finding,
    FindingCategory,
    FindingSeverity,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ScanReport,
)


class TestModels:
    def test_environment_defaults(self):
        env = Environment(name="test")
        assert env.id
        assert env.name == "test"
        assert env.platforms == []

    def test_detection_creation(self):
        det = Detection(name="my_search", search_query="index=main | stats count")
        assert det.id
        assert det.severity == DetectionSeverity.medium
        assert det.enabled is True
        assert det.references == []

    def test_dependency_creation(self):
        dep = Dependency(kind=DependencyKind.macro, name="my_macro")
        assert dep.status == DependencyStatus.unknown

    def test_finding_creation(self):
        f = Finding(
            detection_id="det1",
            category=FindingCategory.missing_dependency,
            severity=FindingSeverity.high,
            title="Missing macro: foo",
            description="Test finding",
        )
        assert f.id
        assert f.dependency_id is None

    def test_readiness_score_bounds(self):
        sc = ReadinessScore(
            detection_id="d1",
            detection_name="test",
            status=ReadinessStatus.runnable,
            score=1.0,
        )
        assert sc.score == 1.0

    def test_scan_report_serialization(self):
        env = Environment(name="test", platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")])
        report = ScanReport(environment=env)
        data = report.model_dump()
        assert data["environment"]["name"] == "test"

        # Round-trip
        restored = ScanReport.model_validate(data)
        assert restored.environment.name == "test"
