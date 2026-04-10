"""Integration tests for scanning Chronicle YARA-L example rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from odcp.core.engine import ScanEngine

EXAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "examples"


class TestChronicleScan:
    """Integration test: scan the Chronicle example rules directory."""

    @pytest.fixture()
    def report(self):
        from odcp.adapters.chronicle import ChronicleAdapter

        adapter = ChronicleAdapter()
        engine = ScanEngine(adapter)
        return engine.scan(EXAMPLES_DIR / "chronicle_rules")

    def test_detections_parsed(self, report):
        # 5 YARAL files, 1 deprecated
        assert len(report.detections) >= 4

    def test_environment(self, report):
        assert "chronicle" in report.environment.description.lower()
        assert report.environment.platforms[0].name == "chronicle"
        assert report.environment.platforms[0].vendor == "Google"

    def test_dependencies_resolved(self, report):
        assert len(report.dependencies) > 0

    def test_readiness_scores(self, report):
        assert len(report.readiness_scores) > 0

    def test_disabled_detection(self, report):
        deprecated = [d for d in report.detections if not d.enabled]
        assert len(deprecated) >= 1

    def test_udm_entities_present(self, report):
        all_entities = []
        for d in report.detections:
            all_entities.extend(d.metadata.get("udm_entities", []))
        assert len(all_entities) > 0

    def test_reference_list_detected(self, report):
        ref_lists = []
        for d in report.detections:
            ref_lists.extend(d.metadata.get("reference_lists", []))
        assert "malicious_ips" in ref_lists

    def test_mitre_tags_present(self, report):
        all_tags = []
        for d in report.detections:
            all_tags.extend(d.tags)
        technique_tags = [t for t in all_tags if t.startswith("T")]
        assert len(technique_tags) > 0

    def test_outcome_detected(self, report):
        with_outcome = [
            d for d in report.detections
            if d.metadata.get("has_outcome")
        ]
        assert len(with_outcome) >= 1

    def test_match_variables_detected(self, report):
        all_vars = []
        for d in report.detections:
            all_vars.extend(d.metadata.get("match_variables", []))
        assert len(all_vars) > 0


class TestChronicleCrossPlatformIntegration:
    """Integration test: cross-platform analysis with Chronicle."""

    def test_cross_platform_with_chronicle(self):
        from odcp.adapters.chronicle import ChronicleAdapter
        from odcp.adapters.sigma import SigmaAdapter
        from odcp.analyzers.cross_platform import CrossPlatformReadinessAnalyzer

        # Scan both platforms
        chronicle_adapter = ChronicleAdapter()
        sigma_adapter = SigmaAdapter()
        engine_c = ScanEngine(chronicle_adapter)
        engine_s = ScanEngine(sigma_adapter)

        chronicle_report = engine_c.scan(EXAMPLES_DIR / "chronicle_rules")
        sigma_report = engine_s.scan(EXAMPLES_DIR / "sigma_rules")

        # Cross-platform analysis
        analyzer = CrossPlatformReadinessAnalyzer()
        summary = analyzer.analyze([chronicle_report, sigma_report])

        assert summary.total_platforms == 2
        assert summary.total_detections > 0
        platform_names = [p.platform_name for p in summary.platforms]
        assert "chronicle" in platform_names
        assert "sigma" in platform_names

    def test_migration_from_sigma_to_chronicle(self):
        from odcp.adapters.sigma import SigmaAdapter
        from odcp.analyzers.cross_platform import MigrationAnalyzer

        adapter = SigmaAdapter()
        engine = ScanEngine(adapter)
        report = engine.scan(EXAMPLES_DIR / "sigma_rules")

        analyzer = MigrationAnalyzer()
        migration = analyzer.analyze(report, "chronicle")

        assert migration.source_platform == "sigma"
        assert migration.target_platform == "chronicle"
        assert migration.total_detections > 0
        assert migration.overall_feasibility > 0.0
