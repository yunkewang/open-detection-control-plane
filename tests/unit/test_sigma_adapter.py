"""Unit tests for the Sigma adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from odcp.adapters.sigma.adapter import SigmaAdapter
from odcp.models import DetectionSeverity


@pytest.fixture()
def adapter():
    return SigmaAdapter()


@pytest.fixture()
def sample_rule() -> dict:
    return {
        "title": "Suspicious PowerShell Encoded Command",
        "id": "abc-123",
        "status": "test",
        "level": "high",
        "description": "Detects encoded PowerShell commands",
        "author": "Test Author",
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection": {
                "CommandLine|contains": "-enc",
                "Image|endswith": "powershell.exe",
            },
            "condition": "selection",
        },
        "tags": [
            "attack.execution",
            "attack.t1059.001",
        ],
    }


class TestSigmaParseRule:
    def test_basic_fields(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.yml"))
        assert det is not None
        assert det.name == "Suspicious PowerShell Encoded Command"
        assert det.severity == DetectionSeverity.high
        assert det.enabled is True
        assert det.source_file == "test.yml"
        assert det.source_app == "Test Author"

    def test_mitre_tags_extracted(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.yml"))
        assert "T1059.001" in det.tags
        assert "attack.execution" in det.tags

    def test_metadata_populated(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.yml"))
        assert det.metadata["sigma_id"] == "abc-123"
        assert det.metadata["logsource"]["category"] == "process_creation"
        assert det.metadata["logsource"]["product"] == "windows"

    def test_deprecated_rule_disabled(self, adapter):
        rule = {
            "title": "Old Rule",
            "status": "deprecated",
            "level": "low",
        }
        det = adapter._parse_rule(rule, Path("old.yml"))
        assert det is not None
        assert det.enabled is False

    def test_no_title_returns_none(self, adapter):
        rule = {"level": "low", "description": "No title"}
        assert adapter._parse_rule(rule, Path("x.yml")) is None

    def test_invalid_input_returns_none(self, adapter):
        assert adapter._parse_rule("not a dict", Path("x.yml")) is None


class TestSigmaDetectionToQuery:
    def test_simple_condition(self, adapter):
        detection = {
            "condition": "selection",
            "selection": {"field": "value"},
        }
        query = adapter._detection_to_query(detection)
        assert "condition: selection" in query
        assert "field=value" in query

    def test_list_values(self, adapter):
        detection = {
            "condition": "1 of them",
            "keywords": ["bad", "evil"],
        }
        query = adapter._detection_to_query(detection)
        assert "bad OR evil" in query


class TestSigmaDependencies:
    def test_logsource_deps(self, adapter):
        logsource = {
            "category": "process_creation",
            "product": "windows",
            "service": "sysmon",
        }
        deps = adapter._extract_logsource_deps(logsource)
        names = [d.name for d in deps]
        assert "logsource:process_creation" in names
        assert "product:windows" in names
        assert "service:sysmon" in names

    def test_empty_logsource(self, adapter):
        deps = adapter._extract_logsource_deps({})
        assert deps == []

    def test_resolve_links_deps_to_detections(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.yml"))
        deps = adapter.resolve_dependencies([det], [])
        assert len(deps) == 2  # category + product
        assert len(det.references) == 2


class TestSigmaEnvironment:
    def test_parse_environment(self, adapter, tmp_path):
        (tmp_path / "rule.yml").write_text("title: Test\nlevel: low\n")
        env = adapter.parse_environment(tmp_path)
        assert env.name == tmp_path.name
        assert "1 rules" in env.description
        assert env.platforms[0].name == "sigma"
