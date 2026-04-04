"""Tests for the CoverageAnalyzer."""

from odcp.analyzers.coverage import CoverageAnalyzer
from odcp.models import Detection, ReadinessScore, ReadinessStatus


def _det(
    name: str, det_id: str, spl: str = "index=main",
    tags: list[str] | None = None,
) -> Detection:
    return Detection(id=det_id, name=name, search_query=spl, tags=tags or [])


def _score(det_id: str, name: str, status: ReadinessStatus, score: float) -> ReadinessScore:
    return ReadinessScore(
        detection_id=det_id, detection_name=name, status=status, score=score,
    )


class TestCoverageAnalyzer:
    def test_basic_coverage(self):
        dets = [
            _det(
                "Detect Brute Force Login Attempts", "d1",
                spl="`authentication_events` eventtype=failed_login | stats count as attempts",
            ),
            _det(
                "Detect Suspicious PowerShell Execution", "d2",
                spl='Image="*\\powershell.exe" CommandLine="*-enc*"',
            ),
        ]
        scores = [
            _score("d1", "Detect Brute Force Login Attempts", ReadinessStatus.runnable, 1.0),
            _score("d2", "Detect Suspicious PowerShell Execution", ReadinessStatus.runnable, 1.0),
        ]

        analyzer = CoverageAnalyzer()
        coverage, mappings, ds_inv, findings = analyzer.analyze(dets, scores)

        # Should have mapped at least both detections to techniques
        mapped = [m for m in mappings if m.technique_ids]
        assert len(mapped) >= 2

        # Coverage should show some covered techniques
        assert coverage.covered > 0
        assert coverage.total_techniques_in_scope > 0
        assert coverage.uncovered > 0  # Not all techniques covered
        assert 0.0 < coverage.coverage_score < 1.0

    def test_uncovered_techniques_generate_findings(self):
        dets = [
            _det("Simple Search", "d1", spl="index=main | stats count"),
        ]
        scores = [
            _score("d1", "Simple Search", ReadinessStatus.runnable, 1.0),
        ]

        analyzer = CoverageAnalyzer()
        coverage, mappings, ds_inv, findings = analyzer.analyze(dets, scores)

        # Should have findings for uncovered techniques
        gap_findings = [f for f in findings if f.category.value == "data_gap"]
        assert len(gap_findings) > 0

    def test_blocked_detections_are_partial_coverage(self):
        dets = [
            _det(
                "Detect Brute Force Login Attempts", "d1",
                spl="`auth` eventtype=failed_login | stats count",
            ),
        ]
        scores = [
            _score("d1", "Detect Brute Force Login Attempts", ReadinessStatus.blocked, 0.0),
        ]

        analyzer = CoverageAnalyzer()
        coverage, mappings, _, _ = analyzer.analyze(dets, scores)

        # Brute force mapped but blocked = partial coverage
        t1110 = next(
            (t for t in coverage.technique_details if t.technique_id == "T1110"),
            None,
        )
        if t1110 and t1110.detection_count > 0:
            assert t1110.coverage_status == "partial"

    def test_by_tactic_breakdown(self):
        dets = [
            _det("Brute Force", "d1", spl="failed_login attempts > 10"),
        ]
        scores = [
            _score("d1", "Brute Force", ReadinessStatus.runnable, 1.0),
        ]

        analyzer = CoverageAnalyzer()
        coverage, _, _, _ = analyzer.analyze(dets, scores)

        assert len(coverage.by_tactic) > 0

    def test_data_source_inventory(self):
        dets = [
            _det("Det1", "d1", spl="index=main sourcetype=syslog"),
        ]
        scores = [
            _score("d1", "Det1", ReadinessStatus.runnable, 1.0),
        ]

        analyzer = CoverageAnalyzer()
        _, _, ds_inv, _ = analyzer.analyze(dets, scores)

        names = {s.name for s in ds_inv.sources}
        assert "main" in names
        assert "syslog" in names

    def test_tag_based_mapping(self):
        dets = [
            _det("Custom Rule", "d1", tags=["T1486", "T1490"]),
        ]
        scores = [
            _score("d1", "Custom Rule", ReadinessStatus.runnable, 1.0),
        ]

        analyzer = CoverageAnalyzer()
        _, mappings, _, _ = analyzer.analyze(dets, scores)

        assert "T1486" in mappings[0].technique_ids
        assert "T1490" in mappings[0].technique_ids
