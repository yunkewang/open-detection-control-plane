"""Unit tests for the Elastic adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from odcp.adapters.elastic.adapter import ElasticAdapter
from odcp.models import DetectionSeverity


@pytest.fixture()
def adapter():
    return ElasticAdapter()


@pytest.fixture()
def sample_rule() -> dict:
    return {
        "name": "Suspicious PowerShell Execution",
        "description": "Detects suspicious PowerShell",
        "rule_id": "e1001",
        "type": "query",
        "language": "kuery",
        "severity": "high",
        "risk_score": 73,
        "query": "process.name:powershell.exe AND process.args:(-enc OR -encoded)",
        "index": ["winlogbeat-*", "logs-endpoint.events.*"],
        "required_fields": ["process.name", "process.args"],
        "tags": ["Elastic", "Windows"],
        "threat": [
            {
                "framework": "MITRE ATT&CK",
                "tactic": {"id": "TA0002", "name": "Execution"},
                "technique": [
                    {
                        "id": "T1059",
                        "name": "Command and Scripting Interpreter",
                        "subtechnique": [
                            {"id": "T1059.001", "name": "PowerShell"}
                        ],
                    }
                ],
            }
        ],
        "author": ["ODCP Example"],
        "enabled": True,
    }


class TestElasticParseRule:
    def test_basic_fields(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.json"))
        assert det is not None
        assert det.name == "Suspicious PowerShell Execution"
        assert det.severity == DetectionSeverity.high
        assert det.enabled is True
        assert det.source_app == "ODCP Example"

    def test_mitre_tags_extracted(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.json"))
        assert "T1059" in det.tags
        assert "T1059.001" in det.tags

    def test_metadata_populated(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.json"))
        assert det.metadata["rule_id"] == "e1001"
        assert det.metadata["type"] == "query"
        assert det.metadata["risk_score"] == 73
        assert "winlogbeat-*" in det.metadata["index_patterns"]

    def test_nested_rule_format(self, adapter):
        nested = {
            "rule": {
                "name": "Nested Rule",
                "severity": "low",
                "query": "test query",
                "author": ["Author"],
                "enabled": True,
            }
        }
        det = adapter._parse_rule(nested, Path("nested.json"))
        assert det is not None
        assert det.name == "Nested Rule"

    def test_disabled_rule(self, adapter):
        rule = {
            "name": "Disabled Rule",
            "severity": "low",
            "enabled": False,
        }
        det = adapter._parse_rule(rule, Path("test.json"))
        assert det is not None
        assert det.enabled is False

    def test_no_name_returns_none(self, adapter):
        rule = {"severity": "low", "query": "test"}
        assert adapter._parse_rule(rule, Path("x.json")) is None


class TestElasticDependencies:
    def test_index_and_field_deps(self, adapter, sample_rule):
        det = adapter._parse_rule(sample_rule, Path("test.json"))
        deps = adapter.resolve_dependencies([det], [])
        names = [d.name for d in deps]
        assert "index:winlogbeat-*" in names
        assert "field:process.name" in names
        assert "field:process.args" in names
        # 2 index patterns + 2 required fields
        assert len(deps) == 4
        assert len(det.references) == 4

    def test_no_deps_when_empty(self, adapter):
        rule = {"name": "Minimal", "severity": "low"}
        det = adapter._parse_rule(rule, Path("test.json"))
        deps = adapter.resolve_dependencies([det], [])
        assert deps == []


class TestElasticEnvironment:
    def test_parse_environment(self, adapter, tmp_path):
        (tmp_path / "rule.json").write_text('{"name": "Test"}')
        env = adapter.parse_environment(tmp_path)
        assert env.name == tmp_path.name
        assert "1 rules" in env.description
        assert env.platforms[0].name == "elastic"
