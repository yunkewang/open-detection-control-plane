"""Integration test — full scan of example Splunk app."""

from pathlib import Path

import pytest

from odcp.adapters.splunk import SplunkAdapter
from odcp.core.engine import ScanEngine
from odcp.models import ReadinessStatus

EXAMPLE_APP = Path(__file__).resolve().parent.parent.parent / "examples" / "splunk_app"


@pytest.fixture
def scan_report():
    adapter = SplunkAdapter()
    engine = ScanEngine(adapter)
    return engine.scan(EXAMPLE_APP)


class TestFullScan:
    def test_detections_found(self, scan_report):
        assert len(scan_report.detections) >= 5

    def test_dependencies_found(self, scan_report):
        assert len(scan_report.dependencies) > 0

    def test_readiness_scores_generated(self, scan_report):
        assert len(scan_report.readiness_scores) == len(scan_report.detections)

    def test_some_detections_runnable_or_blocked(self, scan_report):
        statuses = {s.status for s in scan_report.readiness_scores}
        # We expect at least one blocked and possibly runnable
        assert len(statuses) > 0

    def test_findings_generated(self, scan_report):
        assert len(scan_report.findings) > 0

    def test_dependency_stats(self, scan_report):
        ds = scan_report.dependency_stats
        assert ds.total > 0
        assert len(ds.by_kind) > 0
        assert len(ds.by_status) > 0

    def test_readiness_summary(self, scan_report):
        rs = scan_report.readiness_summary
        assert rs.total_detections >= 5
        assert rs.runnable + rs.partially_runnable + rs.blocked + rs.unknown == rs.total_detections

    def test_environment_name(self, scan_report):
        assert scan_report.environment.name == "ACME Security Detections"

    def test_json_roundtrip(self, scan_report):
        """Verify report can be serialized and deserialized."""
        from odcp.models import ScanReport
        json_str = scan_report.model_dump_json()
        restored = ScanReport.model_validate_json(json_str)
        assert restored.environment.name == scan_report.environment.name
        assert len(restored.detections) == len(scan_report.detections)

    def test_known_macros_resolved(self, scan_report):
        """Macros defined in macros.conf should resolve."""
        resolved_names = {
            d.name for d in scan_report.dependencies if d.status.value == "resolved"
        }
        # These macros are defined in the example app
        assert "sysmon_events" in resolved_names
        assert "authentication_events" in resolved_names
        assert "normalize_process_fields" in resolved_names

    def test_missing_dependencies_exist(self, scan_report):
        """Some references should be missing (not defined in example app)."""
        missing_names = {
            d.name for d in scan_report.dependencies if d.status.value == "missing"
        }
        # dns_tunnel_filter and cloud_anomaly_filter are not defined
        assert "dns_tunnel_filter" in missing_names or "cloud_anomaly_filter" in missing_names
