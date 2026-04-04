"""Unit tests for the Sentinel adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from odcp.adapters.sentinel.adapter import SentinelAdapter
from odcp.models import DetectionSeverity


@pytest.fixture()
def adapter():
    return SentinelAdapter()


@pytest.fixture()
def sample_rule() -> dict:
    return {
        "id": "s1001",
        "name": "Brute Force Sign-In Attempts",
        "description": "Detects multiple failed sign-in attempts",
        "severity": "Medium",
        "status": "Available",
        "tactics": ["CredentialAccess"],
        "relevantTechniques": ["T1110"],
        "requiredDataConnectors": [
            {
                "connectorId": "AzureActiveDirectory",
                "dataTypes": ["SigninLogs"],
            }
        ],
        "query": (
            "SigninLogs\n"
            "| where ResultType != \"0\"\n"
            "| summarize FailedAttempts = count() by IPAddress\n"
            "| where FailedAttempts > 10"
        ),
        "queryFrequency": "PT5M",
        "queryPeriod": "PT1H",
        "triggerOperator": "gt",
        "triggerThreshold": 0,
        "enabled": True,
        "kind": "Scheduled",
        "author": "Test Author",
    }


class TestSentinelParseRule:
    def test_basic_fields(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.yaml"))
        assert det is not None
        assert det.name == "Brute Force Sign-In Attempts"
        assert det.severity == DetectionSeverity.medium
        assert det.enabled is True
        assert det.source_app == "Test Author"

    def test_mitre_tags(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.yaml"))
        assert "T1110" in det.tags

    def test_metadata_populated(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.yaml"))
        assert det.metadata["rule_id"] == "s1001"
        assert det.metadata["kind"] == "Scheduled"
        assert det.metadata["query_frequency"] == "PT5M"
        assert det.metadata["tactics"] == ["CredentialAccess"]
        assert "AzureActiveDirectory" in det.metadata["data_connectors"]

    def test_available_status_sets_enabled(self, adapter):
        rule = {
            "name": "Test",
            "status": "Available",
            "enabled": False,
        }
        det = adapter._parse_rule(rule, Path("test.yaml"))
        assert det.enabled is True

    def test_disabled_rule(self, adapter):
        rule = {
            "name": "Disabled",
            "severity": "Low",
            "enabled": False,
            "status": "Test",
        }
        det = adapter._parse_rule(rule, Path("test.yaml"))
        assert det.enabled is False

    def test_no_name_returns_none(self, adapter):
        rule = {"severity": "Low", "query": "test"}
        assert adapter._parse_rule(rule, Path("x.yaml")) is None


class TestSentinelKQLExtraction:
    def test_extract_simple_table(self):
        query = "SigninLogs\n| where ResultType != \"0\""
        tables = SentinelAdapter._extract_kql_tables(query)
        assert "SigninLogs" in tables

    def test_extract_join_tables(self):
        query = (
            "SecurityEvent\n"
            "| join kind=inner (\n"
            "    WindowsFirewall\n"
            "    | where DestinationPort == 3389\n"
            ") on SourceAddress"
        )
        tables = SentinelAdapter._extract_kql_tables(query)
        assert "SecurityEvent" in tables
        assert "WindowsFirewall" in tables

    def test_empty_query(self):
        assert SentinelAdapter._extract_kql_tables("") == []

    def test_filters_kql_keywords(self):
        query = "SecurityEvent\n| where EventID == 4688"
        tables = SentinelAdapter._extract_kql_tables(query)
        assert "SecurityEvent" in tables
        # "where" should be filtered out
        assert "where" not in [t.lower() for t in tables]


class TestSentinelDependencies:
    def test_table_and_connector_deps(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.yaml"))
        deps = adapter.resolve_dependencies([det], [])
        names = [d.name for d in deps]
        assert "table:SigninLogs" in names
        assert "connector:AzureActiveDirectory" in names
        assert len(det.references) == len(deps)

    def test_no_deps_when_empty(self, adapter):
        rule = {"name": "Minimal", "severity": "Low"}
        det = adapter._parse_rule(rule, Path("test.yaml"))
        deps = adapter.resolve_dependencies([det], [])
        assert deps == []


class TestSentinelEnvironment:
    def test_parse_environment(self, adapter, tmp_path):
        (tmp_path / "rule.yaml").write_text("name: Test\nseverity: Low\n")
        env = adapter.parse_environment(tmp_path)
        assert env.name == tmp_path.name
        assert "1 rules" in env.description
        assert env.platforms[0].name == "sentinel"

    def test_single_file(self, adapter, tmp_path):
        f = tmp_path / "rule.yaml"
        f.write_text("name: Test\nseverity: Low\n")
        files = adapter._find_rule_files(f)
        assert len(files) == 1

    def test_ignores_non_rule_files(self, adapter, tmp_path):
        (tmp_path / "readme.txt").write_text("not a rule")
        files = adapter._find_rule_files(tmp_path)
        assert len(files) == 0
