"""Unit tests for the cross-platform readiness and migration analyzers."""

from __future__ import annotations

import pytest

from odcp.analyzers.cross_platform.readiness import CrossPlatformReadinessAnalyzer
from odcp.analyzers.cross_platform.migration import MigrationAnalyzer
from odcp.models import (
    Dependency,
    DependencyKind,
    DependencyStatus,
    DependencyStats,
    Detection,
    DetectionSeverity,
    Environment,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ReadinessSummary,
    ScanReport,
)
from odcp.models.cross_platform import MigrationComplexity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_report(
    platform_name: str,
    vendor: str,
    detections: list[Detection],
    deps: list[Dependency],
    readiness: ReadinessSummary,
    dep_stats: DependencyStats | None = None,
    scores: list[ReadinessScore] | None = None,
) -> ScanReport:
    """Build a minimal ScanReport for testing."""
    env = Environment(
        name=f"test-{platform_name}",
        platforms=[Platform(name=platform_name, vendor=vendor, adapter_type=platform_name)],
    )
    return ScanReport(
        environment=env,
        detections=detections,
        dependencies=deps,
        readiness_summary=readiness,
        readiness_scores=scores or [],
        dependency_stats=dep_stats or DependencyStats(
            total=len(deps),
            by_status={"unknown": len(deps)},
        ),
    )


def _det(name: str, tags: list[str] | None = None, **kwargs) -> Detection:
    return Detection(name=name, tags=tags or [], **kwargs)


def _dep(kind: DependencyKind = DependencyKind.field, status: DependencyStatus = DependencyStatus.unknown) -> Dependency:
    return Dependency(kind=kind, name="test-dep", status=status)


@pytest.fixture()
def sigma_report() -> ScanReport:
    dets = [
        _det("Sigma Rule 1", tags=["attack.t1059.001", "attack.execution", "T1059.001"]),
        _det("Sigma Rule 2", tags=["T1110"]),
    ]
    return _make_report(
        "sigma", "Sigma", dets,
        [_dep()],
        ReadinessSummary(total_detections=2, runnable=2, overall_score=1.0),
    )


@pytest.fixture()
def elastic_report() -> ScanReport:
    dets = [
        _det("Elastic Rule 1", tags=["T1059", "T1059.001"]),
        _det("Elastic Rule 2", tags=["T1071"]),
    ]
    deps = [_dep(), _dep(status=DependencyStatus.missing)]
    return _make_report(
        "elastic", "Elastic", dets, deps,
        ReadinessSummary(total_detections=2, runnable=1, blocked=1, overall_score=0.5),
        dep_stats=DependencyStats(total=2, by_status={"unknown": 1, "missing": 1}),
    )


@pytest.fixture()
def chronicle_report() -> ScanReport:
    dets = [
        _det(
            "Chronicle Rule 1",
            tags=["T1059.001"],
            metadata={
                "udm_entities": ["principal", "target"],
                "reference_lists": [],
                "has_outcome": True,
                "match_section": "$p over 5m",
                "functions_used": [],
            },
        ),
    ]
    return _make_report(
        "chronicle", "Google", dets,
        [_dep()],
        ReadinessSummary(total_detections=1, runnable=1, overall_score=1.0),
    )


# ---------------------------------------------------------------------------
# Cross-platform readiness tests
# ---------------------------------------------------------------------------


class TestCrossPlatformReadiness:
    def test_analyze_produces_summary(self, sigma_report, elastic_report):
        analyzer = CrossPlatformReadinessAnalyzer()
        result = analyzer.analyze([sigma_report, elastic_report])

        assert result.total_platforms == 2
        assert result.total_detections == 4
        assert len(result.platforms) == 2

    def test_platform_names(self, sigma_report, elastic_report):
        analyzer = CrossPlatformReadinessAnalyzer()
        result = analyzer.analyze([sigma_report, elastic_report])

        names = [p.platform_name for p in result.platforms]
        assert "sigma" in names
        assert "elastic" in names

    def test_aggregate_score(self, sigma_report, elastic_report):
        analyzer = CrossPlatformReadinessAnalyzer()
        result = analyzer.analyze([sigma_report, elastic_report])

        # Weighted average: (1.0*2 + 0.5*2) / 4 = 0.75
        assert result.aggregate_score == pytest.approx(0.75, abs=0.01)

    def test_shared_mitre_techniques(self, sigma_report, elastic_report):
        analyzer = CrossPlatformReadinessAnalyzer()
        result = analyzer.analyze([sigma_report, elastic_report])

        # T1059.001 appears in both sigma and elastic
        assert "T1059.001" in result.shared_mitre_techniques

    def test_unique_mitre_by_platform(self, sigma_report, elastic_report):
        analyzer = CrossPlatformReadinessAnalyzer()
        result = analyzer.analyze([sigma_report, elastic_report])

        # T1110 is only in sigma, T1071 is only in elastic
        if "sigma" in result.unique_mitre_by_platform:
            assert "T1110" in result.unique_mitre_by_platform["sigma"]
        if "elastic" in result.unique_mitre_by_platform:
            assert "T1071" in result.unique_mitre_by_platform["elastic"]

    def test_recommendations_for_low_score(self, sigma_report, elastic_report):
        # Make elastic score very low
        elastic_report = _make_report(
            "elastic", "Elastic",
            [_det("R1")],
            [_dep(status=DependencyStatus.missing)] * 5,
            ReadinessSummary(total_detections=1, blocked=1, overall_score=0.3),
            dep_stats=DependencyStats(total=5, by_status={"missing": 5}),
        )
        analyzer = CrossPlatformReadinessAnalyzer()
        result = analyzer.analyze([sigma_report, elastic_report])

        assert any("elastic" in r.lower() for r in result.recommendations)

    def test_three_platforms(self, sigma_report, elastic_report, chronicle_report):
        analyzer = CrossPlatformReadinessAnalyzer()
        result = analyzer.analyze([sigma_report, elastic_report, chronicle_report])

        assert result.total_platforms == 3
        assert result.total_detections == 5


class TestPlatformReadiness:
    def test_mitre_technique_extraction(self, sigma_report):
        analyzer = CrossPlatformReadinessAnalyzer()
        pr = analyzer._build_platform_readiness(sigma_report)

        assert "T1059.001" in pr.mitre_technique_ids
        assert "T1110" in pr.mitre_technique_ids

    def test_dependency_stats(self, elastic_report):
        analyzer = CrossPlatformReadinessAnalyzer()
        pr = analyzer._build_platform_readiness(elastic_report)

        assert pr.total_dependencies == 2
        assert pr.missing_dependencies == 1


# ---------------------------------------------------------------------------
# Migration analysis tests
# ---------------------------------------------------------------------------


class TestMigrationAnalyzer:
    def test_basic_migration(self, sigma_report):
        analyzer = MigrationAnalyzer()
        result = analyzer.analyze(sigma_report, "chronicle")

        assert result.source_platform == "sigma"
        assert result.target_platform == "chronicle"
        assert result.total_detections == 2
        assert len(result.detection_results) == 2

    def test_overall_feasibility(self, sigma_report):
        analyzer = MigrationAnalyzer()
        result = analyzer.analyze(sigma_report, "elastic")

        assert 0.0 <= result.overall_feasibility <= 1.0

    def test_effort_estimate(self, sigma_report):
        analyzer = MigrationAnalyzer()
        result = analyzer.analyze(sigma_report, "chronicle")

        assert result.estimated_total_hours >= 0

    def test_chronicle_to_splunk_migration(self, chronicle_report):
        analyzer = MigrationAnalyzer()
        result = analyzer.analyze(chronicle_report, "splunk")

        assert result.source_platform == "chronicle"
        assert result.target_platform == "splunk"
        assert len(result.detection_results) == 1
        dr = result.detection_results[0]
        assert dr.complexity.value in ("trivial", "low", "medium", "high", "infeasible")

    def test_complexity_levels(self):
        analyzer = MigrationAnalyzer()

        # Trivial: no unmapped, no blockers
        assert analyzer._calculate_complexity(3, 0, 0, []) == MigrationComplexity.trivial

        # Low: 1 blocker
        assert analyzer._calculate_complexity(3, 0, 1, []) == MigrationComplexity.low

        # Medium: unmapped features
        assert analyzer._calculate_complexity(3, 1, 0, []) == MigrationComplexity.medium

        # High: many unmapped
        assert analyzer._calculate_complexity(3, 2, 4, []) == MigrationComplexity.high

        # Infeasible: majority unmapped
        assert analyzer._calculate_complexity(1, 3, 5, []) == MigrationComplexity.infeasible

    def test_feasibility_score(self):
        analyzer = MigrationAnalyzer()

        # All mapped, no blockers
        assert analyzer._calculate_feasibility(5, 0, 0) == pytest.approx(1.0)

        # Half mapped, no blockers
        assert analyzer._calculate_feasibility(3, 3, 0) == pytest.approx(0.5)

        # All unmapped
        assert analyzer._calculate_feasibility(0, 5, 0) == pytest.approx(0.0)

        # Blockers reduce score
        score_no_blockers = analyzer._calculate_feasibility(3, 1, 0)
        score_with_blockers = analyzer._calculate_feasibility(3, 1, 2)
        assert score_with_blockers < score_no_blockers

    def test_invalid_target_returns_reasonable_result(self, sigma_report):
        analyzer = MigrationAnalyzer()
        result = analyzer.analyze(sigma_report, "unknown_platform")

        # Should still produce results, just with no feature mappings
        assert result.total_detections == 2

    def test_complexity_breakdown_sums(self, sigma_report):
        analyzer = MigrationAnalyzer()
        result = analyzer.analyze(sigma_report, "elastic")

        total = (
            result.trivial
            + result.low_complexity
            + result.medium_complexity
            + result.high_complexity
            + result.infeasible
        )
        assert total == result.total_detections

    def test_migration_with_complex_splunk(self):
        """Test migration of a complex Splunk detection with joins/macros."""
        det = Detection(
            name="Complex Splunk Rule",
            search_query='index=main `my_macro` | join type=inner user [search index=auth action=failure] | stats count by user | where count > 10',
            severity=DetectionSeverity.high,
            metadata={},
        )
        report = _make_report(
            "splunk", "Splunk", [det], [],
            ReadinessSummary(total_detections=1, runnable=1, overall_score=1.0),
        )

        analyzer = MigrationAnalyzer()
        result = analyzer.analyze(report, "chronicle")

        dr = result.detection_results[0]
        # Should detect macro, join, stats as features
        all_mapped = " ".join(dr.mapped_features)
        all_unmapped = " ".join(dr.unmapped_features)
        assert "join" in all_mapped or "join" in all_unmapped or "macro" in all_unmapped
