"""AI-powered detection rule generator.

Generates platform-appropriate detection rules (Sigma preferred for
portability) for a given MITRE ATT&CK technique using available data
source context from a scan report.

Requires the ``agent`` extra (Anthropic SDK)::

    pip install 'odcp[agent]'

Usage::

    gen = RuleGenerator()
    result = gen.generate("T1059.001", platform="sigma", report=scan_report)
    print(result.rule_content)
    print(f"Quality: {result.quality_score.overall:.2f}")
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Sigma YAML skeleton used as few-shot context for the LLM
_SIGMA_EXAMPLE = """\
title: Example Detection
id: 00000000-0000-0000-0000-000000000001
status: experimental
description: Detects <describe what this finds>
references:
  - https://attack.mitre.org/techniques/<technique_id>/
author: ODCP Rule Generator
date: 2024/01/01
tags:
  - attack.<tactic>
  - attack.<technique_id_lower>
logsource:
  category: <process_creation|network_connection|file_event|…>
  product: <windows|linux|macos|…>
detection:
  selection:
    <field>: '<value>'
  condition: selection
falsepositives:
  - <list known false positives>
level: <critical|high|medium|low>
"""

_SPLUNK_EXAMPLE = """\
[search name]
search = index=<index> sourcetype=<sourcetype> <field>=<value>
  | stats count by <field1>, <field2>
  | where count > <threshold>
"""

_KQL_EXAMPLE = """\
<TableName>
| where TimeGenerated > ago(1h)
| where <Field> =~ "<value>"
| summarize Count = count() by <Field1>, <Field2>
| where Count > <threshold>
"""


class RuleQualityScore(BaseModel):
    """Automated quality assessment for a generated detection rule."""

    specificity: float = 0.0         # 0–1: how specific vs. broad
    fp_risk: float = 0.0             # 0–1: estimated false-positive risk (lower = better)
    mitre_alignment: float = 0.0     # 0–1: rule targets the stated technique
    data_source_fit: float = 0.0     # 0–1: rule matches available data sources
    overall: float = 0.0             # composite
    notes: list[str] = Field(default_factory=list)


class GeneratedRule(BaseModel):
    """A detection rule produced by the AI rule generator."""

    technique_id: str
    technique_name: str = ""
    platform: str                     # sigma, splunk, kql, yara-l
    rule_content: str
    rule_format: str = "sigma"
    quality_score: RuleQualityScore = Field(default_factory=RuleQualityScore)
    rationale: str = ""
    data_sources_used: list[str] = Field(default_factory=list)
    validation_passed: bool = False   # True if ODCP scan passes readiness threshold
    validation_notes: str = ""


class RuleGenerator:
    """Generates detection rules using the Claude API.

    Falls back gracefully when the Anthropic SDK is not installed.
    """

    def __init__(self, model: str = "claude-opus-4-6") -> None:
        self.model = model

    def generate(
        self,
        technique_id: str,
        platform: str = "sigma",
        report: Optional[object] = None,  # ScanReport
        technique_name: str = "",
        additional_context: str = "",
    ) -> GeneratedRule:
        """Generate a detection rule for the given technique.

        Parameters
        ----------
        technique_id:
            MITRE ATT&CK technique ID (e.g. ``T1059.001``).
        platform:
            Target platform: ``sigma``, ``splunk``, ``kql``, or ``yara-l``.
        report:
            Optional scan report providing data source context.
        technique_name:
            Human-readable technique name (looked up if omitted).
        additional_context:
            Free-text context appended to the prompt.
        """
        try:
            import anthropic  # type: ignore[import]
        except ImportError:
            raise SystemExit(
                "Anthropic SDK not installed. Run: pip install 'odcp[agent]'"
            )

        data_sources = self._extract_data_sources(report)
        prompt = self._build_prompt(
            technique_id, technique_name, platform,
            data_sources, additional_context,
        )

        client = anthropic.Anthropic()
        message = client.messages.create(
            model=self.model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text if message.content else ""

        rule_content, rationale = self._parse_response(raw, platform)
        quality = self._score_rule(rule_content, technique_id, platform, data_sources)

        return GeneratedRule(
            technique_id=technique_id,
            technique_name=technique_name,
            platform=platform,
            rule_content=rule_content,
            rule_format=platform,
            quality_score=quality,
            rationale=rationale,
            data_sources_used=data_sources,
        )

    def score_existing(
        self,
        rule_content: str,
        technique_id: str,
        platform: str,
        report: Optional[object] = None,
    ) -> RuleQualityScore:
        """Score an existing rule without generating a new one."""
        data_sources = self._extract_data_sources(report)
        return self._score_rule(rule_content, technique_id, platform, data_sources)

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _extract_data_sources(self, report: Optional[object]) -> list[str]:
        """Pull index/sourcetype names from a scan report for context."""
        if report is None:
            return []
        try:
            sources: list[str] = []
            for det in getattr(report, "detections", []):
                q = getattr(det, "search_query", "") or ""
                # Extract index= and sourcetype= values
                sources.extend(re.findall(r'index=(\S+)', q))
                sources.extend(re.findall(r'sourcetype=(\S+)', q))
            return sorted(set(s.strip('"\'') for s in sources))[:20]
        except Exception:
            return []

    def _build_prompt(
        self,
        technique_id: str,
        technique_name: str,
        platform: str,
        data_sources: list[str],
        additional_context: str,
    ) -> str:
        fmt_map = {"sigma": _SIGMA_EXAMPLE, "splunk": _SPLUNK_EXAMPLE, "kql": _KQL_EXAMPLE}
        example = fmt_map.get(platform, _SIGMA_EXAMPLE)
        ds_block = "\n".join(f"  - {s}" for s in data_sources) if data_sources else "  (none available)"

        return f"""You are an expert detection engineer. Generate a high-quality {platform.upper()} detection rule for:

MITRE ATT&CK Technique: {technique_id}{' — ' + technique_name if technique_name else ''}

Available data sources in the target environment:
{ds_block}

{additional_context}

Requirements:
1. The rule MUST target the stated technique specifically (not generic activity)
2. Use only data sources that are available (listed above), or common universal sources if none listed
3. Include tuning filters to minimize false positives where possible
4. Add ATT&CK tags in the correct format
5. Keep the rule focused — one detection, one condition

Format your response exactly as:

<rule>
{example.strip()}
</rule>

<rationale>
Brief explanation of what the rule detects, why this technique was chosen, and any known limitations or tuning recommendations.
</rationale>
"""

    def _parse_response(self, raw: str, platform: str) -> tuple[str, str]:
        """Extract rule content and rationale from LLM response."""
        rule_match = re.search(r'<rule>(.*?)</rule>', raw, re.DOTALL)
        rationale_match = re.search(r'<rationale>(.*?)</rationale>', raw, re.DOTALL)

        rule_content = rule_match.group(1).strip() if rule_match else raw.strip()
        rationale = rationale_match.group(1).strip() if rationale_match else ""

        return rule_content, rationale

    def _score_rule(
        self,
        rule_content: str,
        technique_id: str,
        platform: str,
        data_sources: list[str],
    ) -> RuleQualityScore:
        """Heuristic quality scoring without an additional API call."""
        notes: list[str] = []
        lower = rule_content.lower()

        # Specificity: does it have specific field conditions?
        has_conditions = bool(re.search(r'(selection|filter|condition|where\s+\w)', lower))
        has_wildcards = lower.count('*') > 3
        specificity = 0.7 if has_conditions else 0.3
        if has_wildcards:
            specificity -= 0.2
            notes.append("Many wildcards detected — consider tightening conditions")

        # FP risk: presence of tuning keywords lowers risk
        fp_risk = 0.5
        if any(kw in lower for kw in ('filter', 'not ', 'exclude', 'whitelist', 'allowlist')):
            fp_risk -= 0.2
            notes.append("Tuning filters present — good FP reduction")
        if has_wildcards:
            fp_risk += 0.2

        # MITRE alignment: technique ID referenced
        tid_lower = technique_id.lower().replace('.', r'\.')
        mitre_alignment = 0.9 if re.search(tid_lower, lower) else 0.5
        if mitre_alignment < 0.9:
            notes.append(f"Technique ID {technique_id} not found in rule — verify ATT&CK tags")

        # Data source fit: overlaps with available sources
        if data_sources:
            ds_hits = sum(1 for ds in data_sources if ds.lower() in lower)
            data_source_fit = min(1.0, ds_hits / max(len(data_sources), 1) * 3)
            if data_source_fit < 0.2:
                notes.append("Rule doesn't reference known data sources — verify logsource")
        else:
            data_source_fit = 0.5  # no info to judge

        overall = round(
            specificity * 0.35
            + (1 - fp_risk) * 0.25
            + mitre_alignment * 0.25
            + data_source_fit * 0.15,
            3,
        )

        return RuleQualityScore(
            specificity=round(specificity, 3),
            fp_risk=round(fp_risk, 3),
            mitre_alignment=round(mitre_alignment, 3),
            data_source_fit=round(data_source_fit, 3),
            overall=overall,
            notes=notes,
        )
