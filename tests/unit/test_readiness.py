"""Tests for readiness classification."""

import pytest

from odcp.analyzers.readiness import ReadinessAnalyzer
from odcp.core.graph import DependencyGraph
from odcp.models import (
    Dependency,
    DependencyKind,
    DependencyStatus,
    Detection,
    ReadinessStatus,
)


def _make_detection(name: str, refs: list[str] | None = None) -> Detection:
    det = Detection(name=name, search_query="index=main")
    if refs:
        det.references = refs
    return det


def _make_dep(dep_id: str, name: str, kind: DependencyKind, status: DependencyStatus) -> Dependency:
    return Dependency(id=dep_id, kind=kind, name=name, status=status)


class TestReadinessAnalyzer:
    def test_runnable_all_resolved(self):
        dep = _make_dep("d1", "my_macro", DependencyKind.macro, DependencyStatus.resolved)
        det = _make_detection("test_search", refs=["d1"])

        graph = DependencyGraph()
        graph.build_from_scan([det], [dep])

        analyzer = ReadinessAnalyzer()
        scores, findings = analyzer.analyze([det], [dep], graph)

        assert len(scores) == 1
        assert scores[0].status == ReadinessStatus.runnable
        assert scores[0].score == 1.0
        assert len(findings) == 0

    def test_blocked_missing_dependency(self):
        dep = _make_dep("d1", "missing_macro", DependencyKind.macro, DependencyStatus.missing)
        det = _make_detection("test_search", refs=["d1"])

        graph = DependencyGraph()
        graph.build_from_scan([det], [dep])

        analyzer = ReadinessAnalyzer()
        scores, findings = analyzer.analyze([det], [dep], graph)

        assert len(scores) == 1
        assert scores[0].status == ReadinessStatus.blocked
        assert scores[0].missing_dependencies == 1
        assert len(findings) == 1
        assert "Missing" in findings[0].title

    def test_partially_runnable(self):
        dep1 = _make_dep("d1", "good_macro", DependencyKind.macro, DependencyStatus.resolved)
        dep2 = _make_dep("d2", "iffy_lookup", DependencyKind.lookup, DependencyStatus.degraded)
        det = _make_detection("test_search", refs=["d1", "d2"])

        graph = DependencyGraph()
        graph.build_from_scan([det], [dep1, dep2])

        analyzer = ReadinessAnalyzer()
        scores, findings = analyzer.analyze([det], [dep1, dep2], graph)

        assert scores[0].status == ReadinessStatus.partially_runnable
        assert 0 < scores[0].score < 1.0

    def test_unknown_no_dependencies(self):
        det = _make_detection("simple_search")

        graph = DependencyGraph()
        graph.build_from_scan([det], [])

        analyzer = ReadinessAnalyzer()
        scores, findings = analyzer.analyze([det], [], graph)

        assert scores[0].status == ReadinessStatus.unknown
        assert scores[0].score == 1.0

    def test_mixed_detections(self):
        dep1 = _make_dep("d1", "macro_a", DependencyKind.macro, DependencyStatus.resolved)
        dep2 = _make_dep("d2", "macro_b", DependencyKind.macro, DependencyStatus.missing)

        det1 = _make_detection("good_search", refs=["d1"])
        det2 = _make_detection("bad_search", refs=["d2"])

        graph = DependencyGraph()
        graph.build_from_scan([det1, det2], [dep1, dep2])

        analyzer = ReadinessAnalyzer()
        scores, findings = analyzer.analyze([det1, det2], [dep1, dep2], graph)

        statuses = {s.detection_name: s.status for s in scores}
        assert statuses["good_search"] == ReadinessStatus.runnable
        assert statuses["bad_search"] == ReadinessStatus.blocked
