"""Integration test — combined static + runtime scan with mocked API."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from odcp.adapters.splunk import SplunkAdapter
from odcp.adapters.splunk.api_client import SplunkAPIClient
from odcp.collectors.api import APICollector
from odcp.core.engine import ScanEngine
from odcp.models.runtime import (
    DataModelHealth,
    LookupHealth,
    SavedSearchHealth,
)

EXAMPLE_APP = Path(__file__).resolve().parent.parent.parent / "examples" / "splunk_app"


def _build_mock_client(detections: list[str]) -> SplunkAPIClient:
    """Build a mock API client with sensible defaults for the example app."""
    client = MagicMock(spec=SplunkAPIClient)
    client.test_connection.return_value = {
        "serverName": "test-splunk",
        "version": "9.2.0",
        "os_name": "Linux",
    }

    def get_ss_health(name: str) -> SavedSearchHealth:
        # Simulate: some searches scheduled, some not
        return SavedSearchHealth(
            name=name,
            is_scheduled=name in detections[:3],  # first 3 are scheduled
        )

    def get_ss_history(name: str, count: int = 5) -> list[dict]:
        if name in detections[:3]:
            return [
                {"sid": f"{name}_1", "is_failed": False, "dispatch_state": "DONE"},
                {"sid": f"{name}_2", "is_failed": False, "dispatch_state": "DONE"},
            ]
        return []

    def get_lookup_health(name: str) -> LookupHealth:
        # threat_intel_lookup doesn't exist; others do
        if "threat" in name.lower():
            return LookupHealth(name=name, exists=False)
        return LookupHealth(name=name, exists=True, lookup_type="csv")

    def get_dm_health(name: str) -> DataModelHealth:
        return DataModelHealth(
            name=name,
            exists=True,
            acceleration_enabled=True,
            acceleration_complete=False,
            acceleration_percent=0.6,
        )

    client.get_saved_search_health.side_effect = get_ss_health
    client.get_saved_search_history.side_effect = get_ss_history
    client.get_lookup_health.side_effect = get_lookup_health
    client.get_data_model_health.side_effect = get_dm_health

    return client


class TestRuntimeScan:
    @pytest.fixture
    def runtime_report(self):
        adapter = SplunkAdapter()
        engine = ScanEngine(adapter)

        # First do a static scan to get detection names
        static_report = engine.scan(EXAMPLE_APP)
        det_names = [d.name for d in static_report.detections]

        # Now do combined scan with mocked API
        client = _build_mock_client(det_names)
        collector = APICollector(client)
        return engine.scan_with_runtime(EXAMPLE_APP, collector)

    def test_runtime_metadata_present(self, runtime_report):
        assert runtime_report.metadata.get("runtime_enabled") is True

    def test_runtime_summary_in_metadata(self, runtime_report):
        rs = runtime_report.metadata.get("runtime_summary")
        assert rs is not None
        assert rs["total_detections"] >= 5

    def test_combined_scores_in_metadata(self, runtime_report):
        combined = runtime_report.metadata.get("combined_scores")
        assert combined is not None
        assert len(combined) >= 5

    def test_combined_scores_have_both_dimensions(self, runtime_report):
        for c in runtime_report.metadata["combined_scores"]:
            assert "static_score" in c
            assert "runtime_score" in c
            assert "combined_score" in c
            assert 0.0 <= c["combined_score"] <= 1.0

    def test_runtime_findings_generated(self, runtime_report):
        """Should have at least some runtime-specific findings."""
        runtime_categories = {"runtime_health", "stale_execution", "acceleration_issue"}
        runtime_findings = [
            f for f in runtime_report.findings if f.category.value in runtime_categories
        ]
        # We expect findings for unscheduled searches and acceleration issues
        assert len(runtime_findings) > 0

    def test_static_analysis_still_present(self, runtime_report):
        """Runtime scan should still include all static analysis results."""
        assert len(runtime_report.detections) >= 5
        assert len(runtime_report.dependencies) > 0
        assert len(runtime_report.readiness_scores) == len(runtime_report.detections)

    def test_server_info_captured(self, runtime_report):
        info = runtime_report.metadata.get("server_info")
        assert info is not None
        assert info["serverName"] == "test-splunk"

    def test_json_roundtrip_with_runtime(self, runtime_report):
        from odcp.models import ScanReport

        json_str = runtime_report.model_dump_json()
        restored = ScanReport.model_validate_json(json_str)
        assert restored.metadata.get("runtime_enabled") is True
        assert len(restored.metadata.get("combined_scores", [])) > 0
