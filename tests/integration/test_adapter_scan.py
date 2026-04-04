"""Integration tests for scanning example rule directories with all adapters."""

from __future__ import annotations

from pathlib import Path

import pytest

from odcp.core.engine import ScanEngine

EXAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "examples"


class TestSigmaScan:
    """Integration test: scan the Sigma example rules directory."""

    @pytest.fixture()
    def report(self):
        from odcp.adapters.sigma import SigmaAdapter

        adapter = SigmaAdapter()
        engine = ScanEngine(adapter)
        return engine.scan(EXAMPLES_DIR / "sigma_rules")

    def test_detections_parsed(self, report):
        # 5 YAML files, but 1 is deprecated (still parsed, just disabled)
        assert len(report.detections) >= 4

    def test_environment(self, report):
        assert "sigma" in report.environment.description.lower()

    def test_dependencies_resolved(self, report):
        assert len(report.dependencies) > 0

    def test_readiness_scores(self, report):
        assert len(report.readiness_scores) > 0

    def test_disabled_detection(self, report):
        deprecated = [
            d for d in report.detections if not d.enabled
        ]
        assert len(deprecated) >= 1


class TestElasticScan:
    """Integration test: scan the Elastic example rules directory."""

    @pytest.fixture()
    def report(self):
        from odcp.adapters.elastic import ElasticAdapter

        adapter = ElasticAdapter()
        engine = ScanEngine(adapter)
        return engine.scan(EXAMPLES_DIR / "elastic_rules")

    def test_detections_parsed(self, report):
        assert len(report.detections) >= 3

    def test_environment(self, report):
        assert "elastic" in report.environment.description.lower()

    def test_dependencies_resolved(self, report):
        assert len(report.dependencies) > 0

    def test_readiness_scores(self, report):
        assert len(report.readiness_scores) > 0

    def test_disabled_detection(self, report):
        disabled = [d for d in report.detections if not d.enabled]
        assert len(disabled) >= 1

    def test_mitre_tags_present(self, report):
        all_tags = []
        for d in report.detections:
            all_tags.extend(d.tags)
        technique_tags = [t for t in all_tags if t.startswith("T")]
        assert len(technique_tags) > 0


class TestSentinelScan:
    """Integration test: scan the Sentinel example rules directory."""

    @pytest.fixture()
    def report(self):
        from odcp.adapters.sentinel import SentinelAdapter

        adapter = SentinelAdapter()
        engine = ScanEngine(adapter)
        return engine.scan(EXAMPLES_DIR / "sentinel_rules")

    def test_detections_parsed(self, report):
        assert len(report.detections) >= 3

    def test_environment(self, report):
        assert "sentinel" in report.environment.description.lower()

    def test_dependencies_resolved(self, report):
        assert len(report.dependencies) > 0

    def test_readiness_scores(self, report):
        assert len(report.readiness_scores) > 0

    def test_disabled_detection(self, report):
        disabled = [d for d in report.detections if not d.enabled]
        assert len(disabled) >= 1

    def test_kql_tables_extracted(self, report):
        all_tables = []
        for d in report.detections:
            all_tables.extend(d.metadata.get("required_tables", []))
        assert len(all_tables) > 0
        assert "SigninLogs" in all_tables or "SecurityEvent" in all_tables
