"""Unit tests for RuleGenerator (scoring and parsing — no LLM calls)."""

from __future__ import annotations

import pytest

from odcp.agent.rule_generator import RuleGenerator, RuleQualityScore


_SIGMA_RULE = """\
title: PowerShell Suspicious Encoded Command
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects PowerShell with encoded commands (T1059.001)
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  filter:
    CommandLine|contains: 'AAAA'
  condition: selection and not filter
falsepositives:
  - Legitimate management scripts
level: high
"""

_BROAD_RULE = """\
title: Broad PowerShell Usage
tags:
  - attack.t1059
logsource:
  product: windows
detection:
  selection:
    Image|contains: '*'
  condition: selection
"""


class TestRuleScoring:
    def setup_method(self):
        self.gen = RuleGenerator()

    def test_score_good_sigma_rule(self):
        score = self.gen.score_existing(
            _SIGMA_RULE, "T1059.001", "sigma",
        )
        assert isinstance(score, RuleQualityScore)
        # Should have high specificity (has selection conditions + filter)
        assert score.specificity > 0.5
        # FP risk should be lowered due to filter clause
        assert score.fp_risk < 0.5
        # MITRE alignment: t1059.001 present in rule
        assert score.mitre_alignment > 0.8

    def test_score_broad_rule_has_lower_specificity(self):
        score = self.gen.score_existing(_BROAD_RULE, "T1059", "sigma")
        broad_score = self.gen.score_existing(_SIGMA_RULE, "T1059.001", "sigma")
        # The broad rule with wildcard should score lower
        assert score.specificity <= broad_score.specificity

    def test_score_overall_in_range(self):
        score = self.gen.score_existing(_SIGMA_RULE, "T1059.001", "sigma")
        assert 0.0 <= score.overall <= 1.0

    def test_mitre_alignment_missing_technique(self):
        rule_no_technique = "title: Generic Detection\ndetection:\n  selection:\n    field: value\n  condition: selection"
        score = self.gen.score_existing(rule_no_technique, "T9999", "sigma")
        # T9999 not mentioned → lower mitre alignment
        assert score.mitre_alignment < 0.9

    def test_data_source_fit_with_context(self):
        from odcp.models import Detection, Environment, Platform, ScanReport
        report = ScanReport(
            environment=Environment(
                name="test",
                platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
            ),
            detections=[
                Detection(id="d1", name="D1", search_query="index=wineventlog sourcetype=WinEventLog:Security")
            ],
        )
        data_sources = self.gen._extract_data_sources(report)
        assert any("wineventlog" in ds.lower() for ds in data_sources)

    def test_data_source_fit_empty_report(self):
        score = self.gen.score_existing(_SIGMA_RULE, "T1059.001", "sigma", report=None)
        # With no report, data_source_fit is 0.5 (unknown)
        assert score.data_source_fit == 0.5

    def test_notes_populated_for_issues(self):
        score = self.gen.score_existing(_BROAD_RULE, "T9999", "sigma")
        # Should have at least one note (technique not found)
        assert len(score.notes) >= 1


class TestPromptBuilding:
    def test_prompt_contains_technique(self):
        gen = RuleGenerator()
        prompt = gen._build_prompt("T1059.001", "PowerShell", "sigma", [], "")
        assert "T1059.001" in prompt
        assert "PowerShell" in prompt
        assert "SIGMA" in prompt

    def test_prompt_contains_data_sources(self):
        gen = RuleGenerator()
        prompt = gen._build_prompt("T1059", "", "sigma", ["wineventlog", "sysmon"], "")
        assert "wineventlog" in prompt
        assert "sysmon" in prompt

    def test_prompt_empty_data_sources(self):
        gen = RuleGenerator()
        prompt = gen._build_prompt("T1059", "", "sigma", [], "")
        assert "(none available)" in prompt


class TestResponseParsing:
    def test_parse_rule_and_rationale(self):
        gen = RuleGenerator()
        raw = """
<rule>
title: My Detection
detection:
  selection:
    field: value
  condition: selection
</rule>

<rationale>
This rule detects X because Y.
</rationale>
"""
        rule, rationale = gen._parse_response(raw, "sigma")
        assert "title: My Detection" in rule
        assert "This rule detects X because Y." in rationale

    def test_parse_missing_tags_falls_back_to_raw(self):
        gen = RuleGenerator()
        raw = "title: Raw Rule\ncondition: selection"
        rule, rationale = gen._parse_response(raw, "sigma")
        assert "Raw Rule" in rule
        assert rationale == ""
