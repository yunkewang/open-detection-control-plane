"""Tests for the Splunk API client and API collector."""

from __future__ import annotations

from unittest.mock import MagicMock

from odcp.adapters.splunk.api_client import SplunkAPIClient, SplunkAPIError, _parse_splunk_time
from odcp.collectors.api import APICollector, RuntimeData
from odcp.models import Dependency, DependencyKind, DependencyStatus, Detection


class TestSplunkAPIClient:
    def test_init_with_token(self):
        client = SplunkAPIClient(base_url="https://localhost:8089", token="my-token")
        assert client.base_url == "https://localhost:8089"
        assert client.token == "my-token"

    def test_init_with_credentials(self):
        client = SplunkAPIClient(
            base_url="https://localhost:8089/",
            username="admin",
            password="changeme",
        )
        # Trailing slash should be stripped
        assert client.base_url == "https://localhost:8089"
        assert client.username == "admin"

    def test_init_ssl_disabled_by_default(self):
        client = SplunkAPIClient(base_url="https://localhost:8089", token="t")
        assert client._ssl_ctx is not None

    def test_init_ssl_enabled(self):
        client = SplunkAPIClient(
            base_url="https://localhost:8089", token="t", verify_ssl=True
        )
        assert client._ssl_ctx is None


class TestParseSplunkTime:
    def test_iso_format(self):
        dt = _parse_splunk_time("2025-01-15T10:30:00+00:00")
        assert dt is not None
        assert dt.year == 2025

    def test_epoch_format(self):
        dt = _parse_splunk_time("1705312200.0")
        assert dt is not None

    def test_none_input(self):
        assert _parse_splunk_time(None) is None

    def test_empty_string(self):
        assert _parse_splunk_time("") is None

    def test_na_string(self):
        assert _parse_splunk_time("N/A") is None

    def test_invalid_string(self):
        assert _parse_splunk_time("not-a-date") is None


class TestAPICollector:
    def test_collect_with_connection_failure(self):
        client = MagicMock(spec=SplunkAPIClient)
        client.test_connection.side_effect = SplunkAPIError("Connection refused")

        collector = APICollector(client)
        det = Detection(name="test_search", search_query="index=main")
        dep = Dependency(
            kind=DependencyKind.lookup,
            name="my_lookup",
            status=DependencyStatus.resolved,
        )

        result = collector.collect([det], [dep])

        assert isinstance(result, RuntimeData)
        assert len(result.errors) == 1
        assert "Connection failed" in result.errors[0]
        # Should not have tried to collect health data after connection failure
        assert len(result.saved_search_health) == 0

    def test_collect_saved_search_health(self):
        from odcp.models.runtime import SavedSearchHealth

        client = MagicMock(spec=SplunkAPIClient)
        client.test_connection.return_value = {"serverName": "test", "version": "9.0.0"}
        client.get_saved_search_health.return_value = SavedSearchHealth(
            name="my_search", is_scheduled=True
        )
        client.get_saved_search_history.return_value = []

        collector = APICollector(client)
        det = Detection(name="my_search", search_query="index=main")

        result = collector.collect([det], [])

        assert "my_search" in result.saved_search_health
        assert result.saved_search_health["my_search"].is_scheduled is True

    def test_collect_lookup_health(self):
        from odcp.models.runtime import LookupHealth

        client = MagicMock(spec=SplunkAPIClient)
        client.test_connection.return_value = {"serverName": "test", "version": "9.0.0"}
        client.get_saved_search_health.return_value = MagicMock()
        client.get_saved_search_history.return_value = []
        client.get_lookup_health.return_value = LookupHealth(
            name="threat_list", exists=True, lookup_type="csv"
        )

        collector = APICollector(client)
        det = Detection(name="test_search", search_query="index=main")
        dep = Dependency(
            kind=DependencyKind.lookup,
            name="threat_list",
            status=DependencyStatus.resolved,
        )

        result = collector.collect([det], [dep])

        assert "threat_list" in result.lookup_health
        assert result.lookup_health["threat_list"].exists is True

    def test_collect_data_model_health(self):
        from odcp.models.runtime import DataModelHealth

        client = MagicMock(spec=SplunkAPIClient)
        client.test_connection.return_value = {"serverName": "test", "version": "9.0.0"}
        client.get_saved_search_health.return_value = MagicMock()
        client.get_saved_search_history.return_value = []
        client.get_data_model_health.return_value = DataModelHealth(
            name="Network_Traffic", exists=True, acceleration_enabled=True
        )

        collector = APICollector(client)
        det = Detection(name="test_search", search_query="index=main")
        dep = Dependency(
            kind=DependencyKind.data_model,
            name="Network_Traffic",
            status=DependencyStatus.resolved,
        )

        result = collector.collect([det], [dep])

        assert "Network_Traffic" in result.data_model_health
        assert result.data_model_health["Network_Traffic"].acceleration_enabled is True

    def test_collect_index_health(self):
        from odcp.models.runtime import IndexHealth

        client = MagicMock(spec=SplunkAPIClient)
        client.get_index_health.return_value = IndexHealth(
            name="main", exists=True, total_event_count=1000000
        )

        collector = APICollector(client)
        data = RuntimeData()
        collector.collect_index_health(["main"], data)

        assert "main" in data.index_health
        assert data.index_health["main"].total_event_count == 1000000

    def test_collect_handles_individual_errors_gracefully(self):
        """Individual API failures should not abort the entire collection."""
        from odcp.models.runtime import SavedSearchHealth

        client = MagicMock(spec=SplunkAPIClient)
        client.test_connection.return_value = {"serverName": "test", "version": "9.0.0"}
        client.get_saved_search_health.return_value = SavedSearchHealth(
            name="search1", is_scheduled=True
        )
        client.get_saved_search_history.return_value = []
        # Lookup fails
        client.get_lookup_health.side_effect = SplunkAPIError("404 Not Found", status_code=404)

        collector = APICollector(client)
        det = Detection(name="search1", search_query="index=main")
        dep = Dependency(
            kind=DependencyKind.lookup,
            name="bad_lookup",
            status=DependencyStatus.resolved,
        )

        result = collector.collect([det], [dep])

        # Should still have saved search data despite lookup failure
        assert "search1" in result.saved_search_health
        assert len(result.errors) == 1
