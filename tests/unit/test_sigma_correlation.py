"""Unit tests for Sigma correlation meta-rules and filters."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from odcp.adapters.sigma.adapter import SigmaAdapter
from odcp.models.correlation import CorrelationRule, CorrelationType, SigmaFilter


@pytest.fixture()
def adapter():
    return SigmaAdapter()


@pytest.fixture()
def corr_rule_event_count() -> dict:
    return {
        "title": "Brute Force Correlation",
        "id": "corr-001",
        "type": "correlation",
        "status": "test",
        "description": "Multiple failed logins",
        "correlation": {
            "type": "event_count",
            "rules": ["win_brute_force"],
            "group-by": ["TargetUserName", "SourceAddress"],
            "timespan": "5m",
            "condition": {"gte": 10},
        },
        "level": "high",
    }


@pytest.fixture()
def corr_rule_temporal() -> dict:
    return {
        "title": "Lateral Then Execute",
        "id": "corr-002",
        "type": "correlation",
        "status": "test",
        "correlation": {
            "type": "temporal",
            "rules": ["proc_psexec", "proc_powershell"],
            "group-by": "ComputerName",
            "timespan": "10m",
        },
    }


@pytest.fixture()
def corr_rule_value_count() -> dict:
    return {
        "title": "Unique Destinations",
        "id": "corr-003",
        "type": "correlation",
        "status": "test",
        "correlation": {
            "type": "value_count",
            "rules": ["network_conn"],
            "group-by": ["SourceAddress"],
            "timespan": "15m",
            "condition": {"gte": 50},
        },
    }


@pytest.fixture()
def filter_rule() -> dict:
    return {
        "title": "Exclude Scanners",
        "id": "filter-001",
        "type": "filter",
        "status": "test",
        "logsource": {"category": "network_connection", "product": "windows"},
        "rules": ["*"],
        "detection": {
            "filter": {"SourceAddress|contains": ["10.0.100.", "10.0.101."]},
            "condition": "not filter",
        },
    }


class TestCorrelationParsing:
    def test_event_count_correlation(self, adapter, corr_rule_event_count):
        corr = adapter._parse_correlation(corr_rule_event_count, Path("test.yml"))
        assert corr is not None
        assert corr.name == "Brute Force Correlation"
        assert corr.correlation_type == CorrelationType.event_count
        assert corr.rule_references == ["win_brute_force"]
        assert corr.group_by == ["TargetUserName", "SourceAddress"]
        assert corr.timespan == "5m"
        assert ">= 10" in corr.condition

    def test_temporal_correlation(self, adapter, corr_rule_temporal):
        corr = adapter._parse_correlation(corr_rule_temporal, Path("test.yml"))
        assert corr is not None
        assert corr.correlation_type == CorrelationType.temporal
        assert len(corr.rule_references) == 2
        assert corr.group_by == ["ComputerName"]
        assert corr.timespan == "10m"
        assert corr.condition is None

    def test_value_count_correlation(self, adapter, corr_rule_value_count):
        corr = adapter._parse_correlation(corr_rule_value_count, Path("test.yml"))
        assert corr is not None
        assert corr.correlation_type == CorrelationType.value_count
        assert corr.timespan == "15m"

    def test_string_group_by_normalized_to_list(self, adapter, corr_rule_temporal):
        corr = adapter._parse_correlation(corr_rule_temporal, Path("test.yml"))
        assert isinstance(corr.group_by, list)
        assert corr.group_by == ["ComputerName"]

    def test_missing_name_returns_none(self, adapter):
        assert adapter._parse_correlation({}, Path("x.yml")) is None

    def test_non_dict_returns_none(self, adapter):
        assert adapter._parse_correlation("bad", Path("x.yml")) is None

    def test_deprecated_correlation_disabled(self, adapter):
        rule = {
            "title": "Old",
            "type": "correlation",
            "status": "deprecated",
            "correlation": {"type": "event_count", "rules": []},
        }
        corr = adapter._parse_correlation(rule, Path("x.yml"))
        assert corr is not None
        assert corr.enabled is False

    def test_string_condition(self, adapter):
        rule = {
            "title": "Test",
            "type": "correlation",
            "correlation": {
                "type": "event_count",
                "rules": ["r1"],
                "condition": ">= 5",
            },
        }
        corr = adapter._parse_correlation(rule, Path("x.yml"))
        assert corr.condition == ">= 5"


class TestFilterParsing:
    def test_basic_filter(self, adapter, filter_rule):
        filt = adapter._parse_filter(filter_rule, Path("test.yml"))
        assert filt is not None
        assert filt.name == "Exclude Scanners"
        assert filt.target_rules == ["*"]
        assert filt.logsource_filter == {
            "category": "network_connection",
            "product": "windows",
        }
        assert "filter" in filt.conditions

    def test_string_target_rules_normalized(self, adapter):
        rule = {
            "title": "Single Target",
            "type": "filter",
            "rules": "specific_rule_id",
            "detection": {},
        }
        filt = adapter._parse_filter(rule, Path("x.yml"))
        assert filt.target_rules == ["specific_rule_id"]

    def test_missing_name_returns_none(self, adapter):
        assert adapter._parse_filter({}, Path("x.yml")) is None

    def test_non_dict_returns_none(self, adapter):
        assert adapter._parse_filter("bad", Path("x.yml")) is None

    def test_no_logsource_filter(self, adapter):
        rule = {
            "title": "Global Filter",
            "type": "filter",
            "rules": ["*"],
            "detection": {"condition": "not filter"},
        }
        filt = adapter._parse_filter(rule, Path("x.yml"))
        assert filt.logsource_filter is None


class TestParseDetectionsWithMixedTypes:
    def test_mixed_rules_separated(self, adapter, tmp_path):
        """Detection, correlation, and filter rules in one directory are separated."""
        # Detection rule
        (tmp_path / "detection.yml").write_text(yaml.dump({
            "title": "Test Detection",
            "level": "medium",
            "logsource": {"category": "process_creation"},
            "detection": {"selection": {"field": "val"}, "condition": "selection"},
        }))
        # Correlation rule
        (tmp_path / "correlation.yml").write_text(yaml.dump({
            "title": "Test Correlation",
            "type": "correlation",
            "correlation": {
                "type": "event_count",
                "rules": ["Test Detection"],
                "timespan": "5m",
                "condition": {"gte": 3},
            },
        }))
        # Filter rule
        (tmp_path / "filter.yml").write_text(yaml.dump({
            "title": "Test Filter",
            "type": "filter",
            "rules": ["*"],
            "detection": {"filter": {"field": "value"}, "condition": "not filter"},
        }))

        detections = adapter.parse_detections(tmp_path)
        assert len(detections) == 1
        assert detections[0].name == "Test Detection"
        assert len(adapter.correlations) == 1
        assert adapter.correlations[0].name == "Test Correlation"
        assert len(adapter.filters) == 1
        assert adapter.filters[0].name == "Test Filter"

    def test_empty_dir_no_errors(self, adapter, tmp_path):
        detections = adapter.parse_detections(tmp_path)
        assert detections == []
        assert adapter.correlations == []
        assert adapter.filters == []


class TestCorrelationModel:
    def test_model_serialization(self):
        corr = CorrelationRule(
            name="Test",
            correlation_type=CorrelationType.temporal,
            rule_references=["r1", "r2"],
            group_by=["host"],
            timespan="5m",
        )
        data = corr.model_dump()
        assert data["correlation_type"] == "temporal"
        assert data["rule_references"] == ["r1", "r2"]

    def test_model_from_dict(self):
        data = {
            "name": "Test",
            "correlation_type": "value_count",
            "rule_references": ["r1"],
        }
        corr = CorrelationRule(**data)
        assert corr.correlation_type == CorrelationType.value_count


class TestSigmaFilterModel:
    def test_model_serialization(self):
        filt = SigmaFilter(
            name="Test Filter",
            target_rules=["*"],
            conditions={"filter": {"ip": "10.0.0.1"}},
        )
        data = filt.model_dump()
        assert data["target_rules"] == ["*"]
        assert "filter" in data["conditions"]
