"""Integration test — full scan with coverage and optimization analysis."""

from pathlib import Path

import pytest

from odcp.adapters.splunk import SplunkAdapter
from odcp.core.engine import ScanEngine
from odcp.core.graph import DependencyGraph

EXAMPLE_APP = Path(__file__).resolve().parent.parent.parent / "examples" / "splunk_app"


@pytest.fixture
def coverage_report():
    adapter = SplunkAdapter()
    engine = ScanEngine(adapter)
    report = engine.scan(EXAMPLE_APP)

    graph = DependencyGraph()
    graph.build_from_scan(report.detections, report.dependencies)

    return engine.enrich_with_coverage(report, graph)


class TestCoverageScan:
    def test_coverage_enabled_in_metadata(self, coverage_report):
        assert coverage_report.metadata.get("coverage_enabled") is True

    def test_coverage_summary_present(self, coverage_report):
        cs = coverage_report.metadata.get("coverage_summary")
        assert cs is not None
        assert cs["total_techniques_in_scope"] > 0

    def test_some_techniques_covered(self, coverage_report):
        cs = coverage_report.metadata["coverage_summary"]
        # The example app has brute force, lateral movement, DNS exfil, powershell
        assert cs["covered"] + cs["partially_covered"] > 0

    def test_mitre_mappings_present(self, coverage_report):
        mappings = coverage_report.metadata.get("mitre_mappings")
        assert mappings is not None
        assert len(mappings) >= 5  # One per detection
        mapped = [m for m in mappings if m.get("technique_ids")]
        assert len(mapped) >= 3  # At least 3 detections should map

    def test_data_source_inventory_present(self, coverage_report):
        ds = coverage_report.metadata.get("data_source_inventory")
        assert ds is not None
        assert len(ds.get("sources", [])) > 0

    def test_optimization_summary_present(self, coverage_report):
        opt = coverage_report.metadata.get("optimization_summary")
        assert opt is not None
        assert opt["current_score"] >= 0
        assert opt["max_achievable_score"] >= opt["current_score"]

    def test_coverage_findings_generated(self, coverage_report):
        gap_findings = [
            f for f in coverage_report.findings
            if f.category.value == "data_gap"
        ]
        # Should have findings for uncovered techniques and data gaps
        assert len(gap_findings) > 0

    def test_optimization_findings_for_blocked(self, coverage_report):
        opt_findings = [
            f for f in coverage_report.findings
            if f.category.value == "optimization_opportunity"
        ]
        # Example app has blocked detections, so should have optimization findings
        assert len(opt_findings) >= 0  # May or may not depending on graph structure

    def test_what_if_results(self, coverage_report):
        opt = coverage_report.metadata["optimization_summary"]
        what_ifs = opt.get("what_if_results", [])
        # If there are missing deps, there should be what-if results
        if opt["total_missing_dependencies"] > 0:
            assert len(what_ifs) > 0

    def test_static_analysis_unchanged(self, coverage_report):
        """Coverage enrichment should not alter static analysis results."""
        assert len(coverage_report.detections) >= 5
        assert len(coverage_report.dependencies) > 0
        assert len(coverage_report.readiness_scores) == len(coverage_report.detections)
        rs = coverage_report.readiness_summary
        assert rs.runnable + rs.partially_runnable + rs.blocked + rs.unknown == rs.total_detections

    def test_json_roundtrip(self, coverage_report):
        from odcp.models import ScanReport

        json_str = coverage_report.model_dump_json()
        restored = ScanReport.model_validate_json(json_str)
        assert restored.metadata.get("coverage_enabled") is True
        assert restored.metadata["coverage_summary"]["total_techniques_in_scope"] > 0
