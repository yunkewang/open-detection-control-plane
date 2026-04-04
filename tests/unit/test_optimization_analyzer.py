"""Tests for the OptimizationAnalyzer."""

from odcp.analyzers.coverage import OptimizationAnalyzer
from odcp.core.graph import DependencyGraph
from odcp.models import (
    Dependency,
    DependencyKind,
    DependencyStatus,
    Detection,
    ReadinessScore,
    ReadinessStatus,
)


def _det(name: str, det_id: str, refs: list[str] | None = None) -> Detection:
    d = Detection(id=det_id, name=name, search_query="index=main")
    if refs:
        d.references = refs
    return d


def _dep(dep_id: str, name: str, kind: DependencyKind, status: DependencyStatus) -> Dependency:
    return Dependency(id=dep_id, kind=kind, name=name, status=status)


def _score(
    det_id: str, name: str, status: ReadinessStatus, score: float,
    total: int = 1, resolved: int = 0, missing: int = 0,
) -> ReadinessScore:
    return ReadinessScore(
        detection_id=det_id, detection_name=name,
        status=status, score=score,
        total_dependencies=total,
        resolved_dependencies=resolved,
        missing_dependencies=missing,
    )


class TestOptimizationAnalyzer:
    def test_single_missing_dependency(self):
        dep = _dep("dep1", "missing_macro", DependencyKind.macro, DependencyStatus.missing)
        det = _det("Search A", "d1", refs=["dep1"])
        score = _score(
            "d1", "Search A", ReadinessStatus.blocked, 0.0,
            total=1, resolved=0, missing=1,
        )

        graph = DependencyGraph()
        graph.build_from_scan([det], [dep])

        analyzer = OptimizationAnalyzer()
        summary, findings = analyzer.analyze([det], [dep], [score], graph)

        assert summary.total_blocked_detections == 1
        assert summary.total_missing_dependencies == 1
        assert len(summary.top_remediations) == 1
        assert summary.top_remediations[0].dependency_name == "missing_macro"
        assert summary.top_remediations[0].blocked_detections_unblocked == 1

    def test_shared_missing_dependency(self):
        """A single missing dependency blocks multiple detections."""
        dep1 = _dep("dep1a", "shared_lookup", DependencyKind.lookup, DependencyStatus.missing)
        dep2 = _dep("dep1b", "shared_lookup", DependencyKind.lookup, DependencyStatus.missing)
        det1 = _det("Search A", "d1", refs=["dep1a"])
        det2 = _det("Search B", "d2", refs=["dep1b"])

        score1 = _score("d1", "Search A", ReadinessStatus.blocked, 0.0, 1, 0, 1)
        score2 = _score("d2", "Search B", ReadinessStatus.blocked, 0.0, 1, 0, 1)

        graph = DependencyGraph()
        graph.build_from_scan([det1, det2], [dep1, dep2])

        analyzer = OptimizationAnalyzer()
        summary, findings = analyzer.analyze(
            [det1, det2], [dep1, dep2], [score1, score2], graph,
        )

        assert summary.total_blocked_detections == 2
        # The shared dependency should be ranked highest
        top = summary.top_remediations[0]
        assert top.dependency_name == "shared_lookup"
        assert top.affected_detection_count == 2

    def test_what_if_analysis(self):
        dep = _dep("dep1", "missing_macro", DependencyKind.macro, DependencyStatus.missing)
        dep_ok = _dep("dep2", "good_macro", DependencyKind.macro, DependencyStatus.resolved)
        det1 = _det("Search A", "d1", refs=["dep1"])
        det2 = _det("Search B", "d2", refs=["dep2"])

        score1 = _score("d1", "Search A", ReadinessStatus.blocked, 0.0, 1, 0, 1)
        score2 = _score("d2", "Search B", ReadinessStatus.runnable, 1.0, 1, 1, 0)

        graph = DependencyGraph()
        graph.build_from_scan([det1, det2], [dep, dep_ok])

        analyzer = OptimizationAnalyzer()
        summary, _ = analyzer.analyze(
            [det1, det2], [dep, dep_ok], [score1, score2], graph,
        )

        assert len(summary.what_if_results) >= 1
        wif = summary.what_if_results[0]
        assert wif.fixed_dependency_name == "missing_macro"
        assert len(wif.detections_unblocked) == 1
        assert wif.score_improvement > 0

    def test_max_achievable_score(self):
        dep = _dep("dep1", "missing_macro", DependencyKind.macro, DependencyStatus.missing)
        det = _det("Search A", "d1", refs=["dep1"])
        score = _score("d1", "Search A", ReadinessStatus.blocked, 0.0, 1, 0, 1)

        graph = DependencyGraph()
        graph.build_from_scan([det], [dep])

        analyzer = OptimizationAnalyzer()
        summary, _ = analyzer.analyze([det], [dep], [score], graph)

        # If we fix the only missing dep, max score should be 1.0
        assert summary.max_achievable_score == 1.0
        assert summary.current_score == 0.0

    def test_no_missing_dependencies(self):
        dep = _dep("dep1", "good_macro", DependencyKind.macro, DependencyStatus.resolved)
        det = _det("Search A", "d1", refs=["dep1"])
        score = _score("d1", "Search A", ReadinessStatus.runnable, 1.0, 1, 1, 0)

        graph = DependencyGraph()
        graph.build_from_scan([det], [dep])

        analyzer = OptimizationAnalyzer()
        summary, findings = analyzer.analyze([det], [dep], [score], graph)

        assert summary.total_blocked_detections == 0
        assert summary.total_missing_dependencies == 0
        assert len(summary.top_remediations) == 0
        assert len(findings) == 0

    def test_generates_optimization_findings(self):
        dep = _dep("dep1", "critical_lookup", DependencyKind.lookup, DependencyStatus.missing)
        det1 = _det("Search A", "d1", refs=["dep1"])
        det2 = _det("Search B", "d2", refs=["dep1"])
        # Use separate dep objects but same name
        dep2 = _dep("dep1b", "critical_lookup", DependencyKind.lookup, DependencyStatus.missing)
        det2.references = ["dep1b"]

        score1 = _score("d1", "Search A", ReadinessStatus.blocked, 0.0, 1, 0, 1)
        score2 = _score("d2", "Search B", ReadinessStatus.blocked, 0.0, 1, 0, 1)

        graph = DependencyGraph()
        graph.build_from_scan([det1, det2], [dep, dep2])

        analyzer = OptimizationAnalyzer()
        _, findings = analyzer.analyze(
            [det1, det2], [dep, dep2], [score1, score2], graph,
        )

        opt_findings = [
            f for f in findings
            if f.category.value == "optimization_opportunity"
        ]
        assert len(opt_findings) >= 1
        assert "critical_lookup" in opt_findings[0].title
