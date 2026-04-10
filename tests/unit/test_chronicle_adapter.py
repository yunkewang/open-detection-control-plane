"""Unit tests for the Chronicle YARA-L adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from odcp.adapters.chronicle.adapter import ChronicleAdapter
from odcp.models import DetectionSeverity


@pytest.fixture()
def adapter():
    return ChronicleAdapter()


@pytest.fixture()
def sample_rule_text() -> str:
    return '''rule suspicious_powershell {

  meta:
    author = "Test Author"
    description = "Detects encoded PowerShell commands"
    severity = "high"
    mitre_attack_tactic = "Execution"
    mitre_attack_technique = "T1059.001"
    status = "active"

  events:
    $process.metadata.event_type = "PROCESS_LAUNCH"
    $process.principal.process.command_line = /.*powershell.*-enc.*/i
    $process.target.process.file.full_path = /.*powershell\\.exe/i

  match:
    $process over 5m

  outcome:
    $risk_score = max(85)

  condition:
    $process
}
'''


class TestChronicleParseRule:
    def test_basic_fields(self, adapter, sample_rule_text):
        det = adapter._parse_rule(sample_rule_text, Path("test.yaral"))
        assert det is not None
        assert det.name == "suspicious_powershell"
        assert det.severity == DetectionSeverity.high
        assert det.enabled is True
        assert det.source_file == "test.yaral"
        assert det.source_app == "Test Author"

    def test_mitre_tags_extracted(self, adapter, sample_rule_text):
        det = adapter._parse_rule(sample_rule_text, Path("test.yaral"))
        assert "T1059.001" in det.tags
        assert "attack.execution" in det.tags

    def test_metadata_populated(self, adapter, sample_rule_text):
        det = adapter._parse_rule(sample_rule_text, Path("test.yaral"))
        assert det.metadata["rule_name"] == "suspicious_powershell"
        assert det.metadata["meta"]["author"] == "Test Author"
        assert det.metadata["meta"]["severity"] == "high"
        assert det.metadata["has_outcome"] is True

    def test_udm_entities_extracted(self, adapter, sample_rule_text):
        det = adapter._parse_rule(sample_rule_text, Path("test.yaral"))
        entities = det.metadata["udm_entities"]
        assert "metadata" in entities
        assert "principal" in entities
        assert "target" in entities

    def test_udm_fields_extracted(self, adapter, sample_rule_text):
        det = adapter._parse_rule(sample_rule_text, Path("test.yaral"))
        fields = det.metadata["udm_fields"]
        assert any("metadata.event_type" in f for f in fields)
        assert any("principal.process.command_line" in f for f in fields)

    def test_match_variables_extracted(self, adapter, sample_rule_text):
        det = adapter._parse_rule(sample_rule_text, Path("test.yaral"))
        assert "process" in det.metadata["match_variables"]

    def test_deprecated_rule_disabled(self, adapter):
        rule = '''rule old_rule {
  meta:
    description = "Old rule"
    severity = "low"
    status = "deprecated"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
  condition:
    $e
}
'''
        det = adapter._parse_rule(rule, Path("old.yaral"))
        assert det is not None
        assert det.enabled is False

    def test_no_rule_keyword_returns_none(self, adapter):
        assert adapter._parse_rule("not a rule", Path("x.yaral")) is None

    def test_search_query_built(self, adapter, sample_rule_text):
        det = adapter._parse_rule(sample_rule_text, Path("test.yaral"))
        assert "events:" in det.search_query
        assert "condition:" in det.search_query


class TestChronicleReferenceList:
    def test_reference_list_extraction(self, adapter):
        rule = '''rule ref_list_check {
  meta:
    description = "Uses reference lists"
    severity = "critical"
  events:
    $e.target.ip = $ip
    $ip = %malicious_ips
    $e.principal.hostname = %trusted_hosts
  condition:
    $e
}
'''
        det = adapter._parse_rule(rule, Path("test.yaral"))
        assert det is not None
        ref_lists = det.metadata["reference_lists"]
        assert "malicious_ips" in ref_lists
        assert "trusted_hosts" in ref_lists


class TestChronicleSplitRules:
    def test_single_rule(self, adapter, sample_rule_text):
        rules = adapter._split_rules(sample_rule_text)
        assert len(rules) == 1

    def test_multiple_rules(self, adapter):
        text = '''rule first_rule {
  meta:
    description = "First"
  events:
    $e.metadata.event_type = "TEST"
  condition:
    $e
}

rule second_rule {
  meta:
    description = "Second"
  events:
    $e.metadata.event_type = "TEST2"
  condition:
    $e
}
'''
        rules = adapter._split_rules(text)
        assert len(rules) == 2


class TestChronicleParseSections:
    def test_all_sections(self, adapter, sample_rule_text):
        sections = adapter._parse_sections(sample_rule_text)
        assert "meta" in sections
        assert "events" in sections
        assert "match" in sections
        assert "outcome" in sections
        assert "condition" in sections

    def test_meta_parsing(self, adapter):
        meta_text = '''
    author = "Test"
    description = "A test rule"
    severity = "high"
'''
        result = adapter._parse_meta(meta_text)
        assert result["author"] == "Test"
        assert result["description"] == "A test rule"
        assert result["severity"] == "high"


class TestChronicleDependencies:
    def test_udm_entity_deps(self, adapter, sample_rule_text):
        det = adapter._parse_rule(sample_rule_text, Path("test.yaral"))
        deps = adapter.resolve_dependencies([det], [])

        dep_names = [d.name for d in deps]
        entity_deps = [n for n in dep_names if n.startswith("udm_entity:")]
        assert len(entity_deps) > 0
        assert "udm_entity:principal" in dep_names or "udm_entity:metadata" in dep_names

    def test_reference_list_deps(self, adapter):
        rule = '''rule ref_check {
  meta:
    severity = "medium"
  events:
    $e.target.ip = %bad_ips
  condition:
    $e
}
'''
        det = adapter._parse_rule(rule, Path("test.yaral"))
        deps = adapter.resolve_dependencies([det], [])

        dep_names = [d.name for d in deps]
        assert "reference_list:bad_ips" in dep_names

    def test_deps_linked_to_detection(self, adapter, sample_rule_text):
        det = adapter._parse_rule(sample_rule_text, Path("test.yaral"))
        deps = adapter.resolve_dependencies([det], [])
        assert len(deps) > 0
        assert len(det.references) == len(deps)

    def test_udm_field_deps(self, adapter, sample_rule_text):
        det = adapter._parse_rule(sample_rule_text, Path("test.yaral"))
        deps = adapter.resolve_dependencies([det], [])

        field_deps = [d for d in deps if d.name.startswith("udm_field:")]
        assert len(field_deps) > 0


class TestChronicleEnvironment:
    def test_parse_environment(self, adapter, tmp_path):
        (tmp_path / "rule.yaral").write_text('rule test { meta: events: condition: $e }')
        env = adapter.parse_environment(tmp_path)
        assert env.name == tmp_path.name
        assert "1 rules" in env.description
        assert env.platforms[0].name == "chronicle"
        assert env.platforms[0].vendor == "Google"

    def test_knowledge_objects_empty(self, adapter, tmp_path):
        objs = adapter.parse_knowledge_objects(tmp_path)
        assert objs == []


class TestChronicleFileDiscovery:
    def test_find_yaral_files(self, adapter, tmp_path):
        (tmp_path / "rule1.yaral").write_text("rule a { condition: $e }")
        (tmp_path / "rule2.yar").write_text("rule b { condition: $e }")
        (tmp_path / "not_a_rule.txt").write_text("nothing")

        files = adapter._find_rule_files(tmp_path)
        assert len(files) == 2
        suffixes = {f.suffix for f in files}
        assert ".yaral" in suffixes
        assert ".yar" in suffixes

    def test_single_file(self, adapter, tmp_path):
        f = tmp_path / "single.yaral"
        f.write_text("rule test { condition: $e }")
        files = adapter._find_rule_files(f)
        assert len(files) == 1
