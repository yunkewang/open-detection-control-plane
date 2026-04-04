"""Tests for the RuntimeHealthAnalyzer."""

from odcp.analyzers.runtime import RuntimeHealthAnalyzer
from odcp.collectors.api import RuntimeData
from odcp.core.graph import DependencyGraph
from odcp.models import (
    Dependency,
    DependencyKind,
    DependencyStatus,
    Detection,
    ReadinessScore,
    ReadinessStatus,
)
from odcp.models.runtime import (
    DataModelHealth,
    LookupHealth,
    RuntimeHealthStatus,
    SavedSearchHealth,
)


def _det(name: str, det_id: str = "", refs: list[str] | None = None) -> Detection:
    d = Detection(name=name, search_query="index=main", enabled=True)
    if det_id:
        d.id = det_id
    if refs:
        d.references = refs
    return d


def _dep(dep_id: str, name: str, kind: DependencyKind, status: DependencyStatus) -> Dependency:
    return Dependency(id=dep_id, kind=kind, name=name, status=status)


class TestRuntimeHealthAnalyzer:
    def test_healthy_scheduled_detection(self):
        det = _det("my_search", det_id="d1")
        runtime_data = RuntimeData(
            saved_search_health={
                "my_search": SavedSearchHealth(name="my_search", is_scheduled=True)
            },
            saved_search_history={
                "my_search": [
                    {"sid": "1", "is_failed": False, "dispatch_state": "DONE"},
                ]
            },
        )

        graph = DependencyGraph()
        graph.build_from_scan([det], [])

        analyzer = RuntimeHealthAnalyzer()
        scores, findings = analyzer.analyze([det], [], runtime_data, graph)

        assert len(scores) == 1
        assert scores[0].runtime_status == RuntimeHealthStatus.healthy
        assert scores[0].runtime_score == 1.0
        assert len(findings) == 0

    def test_unscheduled_detection_produces_finding(self):
        det = _det("my_search", det_id="d1")
        runtime_data = RuntimeData(
            saved_search_health={
                "my_search": SavedSearchHealth(name="my_search", is_scheduled=False)
            },
        )

        graph = DependencyGraph()
        graph.build_from_scan([det], [])

        analyzer = RuntimeHealthAnalyzer()
        scores, findings = analyzer.analyze([det], [], runtime_data, graph)

        assert len(scores) == 1
        assert scores[0].runtime_status == RuntimeHealthStatus.degraded
        assert len(findings) == 1
        assert "not scheduled" in findings[0].title.lower()

    def test_failed_runs_produce_finding(self):
        det = _det("failing_search", det_id="d1")
        runtime_data = RuntimeData(
            saved_search_health={
                "failing_search": SavedSearchHealth(name="failing_search", is_scheduled=True)
            },
            saved_search_history={
                "failing_search": [
                    {"sid": "1", "is_failed": True, "dispatch_state": "FAILED"},
                    {"sid": "2", "is_failed": True, "dispatch_state": "FAILED"},
                    {"sid": "3", "is_failed": False, "dispatch_state": "DONE"},
                ]
            },
        )

        graph = DependencyGraph()
        graph.build_from_scan([det], [])

        analyzer = RuntimeHealthAnalyzer()
        scores, findings = analyzer.analyze([det], [], runtime_data, graph)

        assert scores[0].runtime_status == RuntimeHealthStatus.unhealthy
        failure_findings = [f for f in findings if "failure" in f.title.lower()]
        assert len(failure_findings) == 1

    def test_missing_lookup_at_runtime(self):
        dep = _dep("dep1", "threat_list", DependencyKind.lookup, DependencyStatus.resolved)
        det = _det("my_search", det_id="d1", refs=["dep1"])

        runtime_data = RuntimeData(
            saved_search_health={
                "my_search": SavedSearchHealth(name="my_search", is_scheduled=True)
            },
            lookup_health={
                "threat_list": LookupHealth(name="threat_list", exists=False)
            },
        )

        graph = DependencyGraph()
        graph.build_from_scan([det], [dep])

        analyzer = RuntimeHealthAnalyzer()
        scores, findings = analyzer.analyze([det], [dep], runtime_data, graph)

        assert scores[0].runtime_status == RuntimeHealthStatus.unhealthy
        lookup_findings = [f for f in findings if "lookup" in f.title.lower()]
        assert len(lookup_findings) == 1

    def test_healthy_lookup(self):
        dep = _dep("dep1", "threat_list", DependencyKind.lookup, DependencyStatus.resolved)
        det = _det("my_search", det_id="d1", refs=["dep1"])

        runtime_data = RuntimeData(
            saved_search_health={
                "my_search": SavedSearchHealth(name="my_search", is_scheduled=True)
            },
            lookup_health={
                "threat_list": LookupHealth(name="threat_list", exists=True, lookup_type="csv")
            },
        )

        graph = DependencyGraph()
        graph.build_from_scan([det], [dep])

        analyzer = RuntimeHealthAnalyzer()
        scores, findings = analyzer.analyze([det], [dep], runtime_data, graph)

        assert scores[0].runtime_status == RuntimeHealthStatus.healthy

    def test_data_model_acceleration_incomplete(self):
        dep = _dep("dep1", "Network_Traffic", DependencyKind.data_model, DependencyStatus.resolved)
        det = _det("my_search", det_id="d1", refs=["dep1"])

        runtime_data = RuntimeData(
            saved_search_health={
                "my_search": SavedSearchHealth(name="my_search", is_scheduled=True)
            },
            data_model_health={
                "Network_Traffic": DataModelHealth(
                    name="Network_Traffic",
                    exists=True,
                    acceleration_enabled=True,
                    acceleration_complete=False,
                    acceleration_percent=0.3,
                )
            },
        )

        graph = DependencyGraph()
        graph.build_from_scan([det], [dep])

        analyzer = RuntimeHealthAnalyzer()
        scores, findings = analyzer.analyze([det], [dep], runtime_data, graph)

        # Should be unhealthy (< 50% acceleration)
        assert scores[0].runtime_status == RuntimeHealthStatus.unhealthy
        accel_findings = [f for f in findings if "acceleration" in f.title.lower()]
        assert len(accel_findings) == 1

    def test_data_model_not_accelerated(self):
        dep = _dep("dep1", "Endpoint", DependencyKind.data_model, DependencyStatus.resolved)
        det = _det("my_search", det_id="d1", refs=["dep1"])

        runtime_data = RuntimeData(
            saved_search_health={
                "my_search": SavedSearchHealth(name="my_search", is_scheduled=True)
            },
            data_model_health={
                "Endpoint": DataModelHealth(
                    name="Endpoint",
                    exists=True,
                    acceleration_enabled=False,
                )
            },
        )

        graph = DependencyGraph()
        graph.build_from_scan([det], [dep])

        analyzer = RuntimeHealthAnalyzer()
        scores, findings = analyzer.analyze([det], [dep], runtime_data, graph)

        assert scores[0].runtime_status == RuntimeHealthStatus.degraded
        accel_findings = [f for f in findings if "not accelerated" in f.title.lower()]
        assert len(accel_findings) == 1

    def test_unknown_when_no_runtime_data(self):
        det = _det("my_search", det_id="d1")
        runtime_data = RuntimeData()  # empty

        graph = DependencyGraph()
        graph.build_from_scan([det], [])

        analyzer = RuntimeHealthAnalyzer()
        scores, findings = analyzer.analyze([det], [], runtime_data, graph)

        assert scores[0].runtime_status == RuntimeHealthStatus.unknown

    def test_combined_scores(self):
        analyzer = RuntimeHealthAnalyzer()

        from odcp.models.runtime import RuntimeHealthScore

        static_scores = [
            ReadinessScore(
                detection_id="d1",
                detection_name="Search A",
                status=ReadinessStatus.runnable,
                score=1.0,
            ),
            ReadinessScore(
                detection_id="d2",
                detection_name="Search B",
                status=ReadinessStatus.blocked,
                score=0.0,
            ),
        ]
        runtime_scores = [
            RuntimeHealthScore(
                detection_id="d1",
                detection_name="Search A",
                runtime_status=RuntimeHealthStatus.degraded,
                runtime_score=0.5,
            ),
            RuntimeHealthScore(
                detection_id="d2",
                detection_name="Search B",
                runtime_status=RuntimeHealthStatus.healthy,
                runtime_score=1.0,
            ),
        ]

        combined = analyzer.compute_combined_scores(static_scores, runtime_scores)

        assert len(combined) == 2
        # Search A: static=1.0 * 0.5 + runtime=0.5 * 0.5 = 0.75
        assert combined[0].combined_score == 0.75
        assert combined[0].combined_status == "degraded"

        # Search B: static=0.0 * 0.5 + runtime=1.0 * 0.5 = 0.5
        assert combined[1].combined_score == 0.5
        assert combined[1].combined_status == "blocked"

    def test_runtime_summary(self):
        from odcp.models.runtime import RuntimeHealthScore, RuntimeSignal

        analyzer = RuntimeHealthAnalyzer()
        scores = [
            RuntimeHealthScore(
                detection_id="d1",
                detection_name="A",
                runtime_status=RuntimeHealthStatus.healthy,
                runtime_score=1.0,
                signals=[
                    RuntimeSignal(
                        detection_id="d1",
                        signal_type="saved_search",
                        status=RuntimeHealthStatus.healthy,
                        title="OK",
                    )
                ],
            ),
            RuntimeHealthScore(
                detection_id="d2",
                detection_name="B",
                runtime_status=RuntimeHealthStatus.degraded,
                runtime_score=0.5,
                signals=[
                    RuntimeSignal(
                        detection_id="d2",
                        signal_type="saved_search",
                        status=RuntimeHealthStatus.degraded,
                        title="Not scheduled",
                    )
                ],
            ),
        ]

        summary = analyzer.compute_runtime_summary(scores)
        assert summary.total_detections == 2
        assert summary.healthy == 1
        assert summary.degraded == 1
        assert summary.overall_runtime_score == 0.75
