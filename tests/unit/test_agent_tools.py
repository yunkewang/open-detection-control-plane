"""Unit tests for the ODCP agent tool implementations."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from odcp.agent.session import AgentSession
from odcp.agent.tools import (
    TOOL_REGISTRY,
    ToolError,
    get_tool_schemas,
)
from odcp.models import (
    Dependency,
    DependencyKind,
    DependencyStatus,
    Detection,
    DetectionSeverity,
    Environment,
    Finding,
    FindingCategory,
    FindingSeverity,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ScanReport,
)
from odcp.models.report import ReadinessSummary, DependencyStats


# ── Test fixtures ────────────────────────────────────────────────────────────


def _make_report(**overrides) -> ScanReport:
    """Build a minimal but representative ScanReport for testing.

    Dependency linkage follows the real model:
    - Dependency has its own ``id``; no ``detection_id`` field.
    - Detection.references holds the dep IDs it needs.
    - Finding.dependency_id links a finding to the specific dep.
    """
    # Pre-create deps so we can reference their IDs
    dep_auth = Dependency(id="dep-auth", kind=DependencyKind.field, name="auth", status=DependencyStatus.resolved)
    dep_macro = Dependency(id="dep-macro", kind=DependencyKind.macro, name="my_macro", status=DependencyStatus.missing)
    dep_old = Dependency(id="dep-old", kind=DependencyKind.field, name="old", status=DependencyStatus.missing)

    defaults = dict(
        environment=Environment(
            name="TestEnv",
            platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
        ),
        detections=[
            Detection(
                id="det-1",
                name="Brute Force Login",
                description="Detects multiple failed logins",
                search_query="index=auth sourcetype=linux_secure | stats count by user",
                severity=DetectionSeverity.high,
                enabled=True,
                tags=["T1110", "credential_access"],
                references=[dep_auth.id],
            ),
            Detection(
                id="det-2",
                name="Data Exfiltration",
                description="Detects large outbound transfers",
                search_query="`my_macro` | stats sum(bytes) by dest",
                severity=DetectionSeverity.critical,
                enabled=True,
                tags=["T1041", "exfiltration"],
                references=[dep_macro.id],
            ),
            Detection(
                id="det-3",
                name="Disabled Detection",
                description="Old rule",
                search_query="index=old | stats count",
                severity=DetectionSeverity.low,
                enabled=False,
                tags=[],
                references=[dep_old.id],
            ),
        ],
        dependencies=[dep_auth, dep_macro, dep_old],
        findings=[
            Finding(
                detection_id="det-2",
                dependency_id=dep_macro.id,
                category=FindingCategory.missing_dependency,
                severity=FindingSeverity.critical,
                title="Missing macro: my_macro",
                description="The macro 'my_macro' is not defined in macros.conf",
            ),
            Finding(
                detection_id="det-3",
                dependency_id=dep_old.id,
                category=FindingCategory.missing_dependency,
                severity=FindingSeverity.low,
                title="Missing index: old",
                description="Index 'old' not found",
            ),
        ],
        readiness_scores=[
            ReadinessScore(
                detection_id="det-1",
                detection_name="Brute Force Login",
                status=ReadinessStatus.runnable,
                score=1.0,
                total_dependencies=1,
                resolved_dependencies=1,
                missing_dependencies=0,
            ),
            ReadinessScore(
                detection_id="det-2",
                detection_name="Data Exfiltration",
                status=ReadinessStatus.blocked,
                score=0.0,
                total_dependencies=1,
                resolved_dependencies=0,
                missing_dependencies=1,
            ),
            ReadinessScore(
                detection_id="det-3",
                detection_name="Disabled Detection",
                status=ReadinessStatus.blocked,
                score=0.0,
                total_dependencies=1,
                resolved_dependencies=0,
                missing_dependencies=1,
            ),
        ],
        readiness_summary=ReadinessSummary(
            total_detections=3,
            runnable=1,
            partially_runnable=0,
            blocked=2,
            unknown=0,
            overall_score=0.33,
        ),
        dependency_stats=DependencyStats(
            total=3,
            by_kind={"field": 2, "macro": 1},
            by_status={"resolved": 1, "missing": 2},
        ),
    )
    defaults.update(overrides)
    return ScanReport(**defaults)


def _session_with_report(**overrides) -> AgentSession:
    session = AgentSession()
    session.report = _make_report(**overrides)
    return session


# ── Tool registry ────────────────────────────────────────────────────────────


class TestToolRegistry:
    def test_all_expected_tools_registered(self):
        expected = {
            "load_report",
            "load_baseline",
            "get_detection_posture",
            "list_detections",
            "get_detection_detail",
            "get_findings",
            "get_coverage_gaps",
            "get_dependency_issues",
            "get_runtime_health",
            "get_tuning_proposals",
            "run_ai_soc_cycle",
            "get_optimization_recommendations",
            "get_data_sources",
            "compare_reports",
            "explain_detection",
        }
        assert expected.issubset(set(TOOL_REGISTRY.keys()))

    def test_each_tool_has_valid_schema(self):
        for name, tool in TOOL_REGISTRY.items():
            assert tool.name == name
            assert tool.description
            schema = tool.input_schema
            assert schema["type"] == "object"
            assert "properties" in schema
            assert "required" in schema

    def test_get_tool_schemas_anthropic(self):
        schemas = get_tool_schemas("anthropic")
        assert len(schemas) == len(TOOL_REGISTRY)
        for s in schemas:
            assert "name" in s
            assert "description" in s
            assert "input_schema" in s

    def test_get_tool_schemas_openai(self):
        schemas = get_tool_schemas("openai")
        assert len(schemas) == len(TOOL_REGISTRY)
        for s in schemas:
            assert s["type"] == "function"
            assert "function" in s
            assert "name" in s["function"]
            assert "parameters" in s["function"]


# ── load_report ──────────────────────────────────────────────────────────────


class TestLoadReport:
    def test_load_valid_report(self, tmp_path: Path):
        report = _make_report()
        report_file = tmp_path / "report.json"
        report_file.write_text(report.model_dump_json())

        session = AgentSession()
        tool = TOOL_REGISTRY["load_report"]
        result = tool.fn({"path": str(report_file)}, session)

        assert result["status"] == "loaded"
        assert result["environment"] == "TestEnv"
        assert result["total_detections"] == 3
        assert session.report is not None

    def test_load_missing_file_raises(self):
        session = AgentSession()
        # The raw tool fn propagates FileNotFoundError (executor wraps it to error dict)
        tool = TOOL_REGISTRY["load_report"]
        with pytest.raises(FileNotFoundError):
            tool.fn({"path": "/does/not/exist.json"}, session)

    def test_load_report_missing_path_param(self):
        session = AgentSession()
        tool = TOOL_REGISTRY["load_report"]
        with pytest.raises(ToolError):
            tool.fn({}, session)


# ── get_detection_posture ────────────────────────────────────────────────────


class TestGetDetectionPosture:
    def test_posture_returns_summary(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_detection_posture"].fn({}, session)

        assert result["environment"] == "TestEnv"
        readiness = result["readiness"]
        assert readiness["total"] == 3
        assert readiness["runnable"] == 1
        assert readiness["blocked"] == 2
        assert 0 <= readiness["overall_score"] <= 1.0

    def test_posture_no_report_raises(self):
        session = AgentSession()
        with pytest.raises(RuntimeError):
            TOOL_REGISTRY["get_detection_posture"].fn({}, session)

    def test_posture_includes_finding_counts(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_detection_posture"].fn({}, session)
        assert "findings_by_severity" in result
        # We have 1 critical and 1 low finding
        assert result["findings_by_severity"].get("critical", 0) >= 1


# ── list_detections ──────────────────────────────────────────────────────────


class TestListDetections:
    def test_list_all(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["list_detections"].fn({}, session)
        assert result["total_matching"] == 3
        assert len(result["detections"]) == 3

    def test_filter_by_status_blocked(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["list_detections"].fn({"status": "blocked"}, session)
        assert result["total_matching"] == 2
        for det in result["detections"]:
            assert det["status"] == "blocked"

    def test_filter_by_status_runnable(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["list_detections"].fn({"status": "runnable"}, session)
        assert result["total_matching"] == 1
        assert result["detections"][0]["name"] == "Brute Force Login"

    def test_filter_by_severity(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["list_detections"].fn({"severity": "critical"}, session)
        assert result["total_matching"] == 1
        assert result["detections"][0]["severity"] == "critical"

    def test_filter_by_name_contains(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["list_detections"].fn({"name_contains": "exfil"}, session)
        assert result["total_matching"] == 1
        assert "Exfiltration" in result["detections"][0]["name"]

    def test_limit_respected(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["list_detections"].fn({"limit": 1}, session)
        assert result["returned"] == 1
        assert result["total_matching"] == 3


# ── get_detection_detail ─────────────────────────────────────────────────────


class TestGetDetectionDetail:
    def test_exact_name_match(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_detection_detail"].fn(
            {"name": "Brute Force Login"}, session
        )
        assert result["name"] == "Brute Force Login"
        assert result["readiness"]["status"] == "runnable"
        assert result["readiness"]["score"] == 1.0

    def test_partial_name_match(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_detection_detail"].fn(
            {"name": "brute force"}, session
        )
        assert result["name"] == "Brute Force Login"

    def test_blocked_detection_shows_missing_deps(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_detection_detail"].fn(
            {"name": "Data Exfiltration"}, session
        )
        assert result["readiness"]["status"] == "blocked"
        assert result["readiness"]["missing"] == 1
        missing = [d for d in result["dependencies"] if d["status"] != "resolved"]
        assert len(missing) == 1
        assert missing[0]["name"] == "my_macro"

    def test_ambiguous_name_raises(self):
        session = _session_with_report()
        with pytest.raises(ToolError, match="Ambiguous"):
            TOOL_REGISTRY["get_detection_detail"].fn({"name": "on"}, session)

    def test_unknown_name_raises(self):
        session = _session_with_report()
        with pytest.raises(ToolError, match="No detection"):
            TOOL_REGISTRY["get_detection_detail"].fn({"name": "ZZZUNKNOWN"}, session)

    def test_missing_name_param_raises(self):
        session = _session_with_report()
        with pytest.raises(ToolError):
            TOOL_REGISTRY["get_detection_detail"].fn({}, session)

    def test_findings_included(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_detection_detail"].fn(
            {"name": "Data Exfiltration"}, session
        )
        assert len(result["findings"]) > 0
        assert result["findings"][0]["category"] == "missing_dependency"


# ── get_findings ─────────────────────────────────────────────────────────────


class TestGetFindings:
    def test_all_findings(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_findings"].fn({}, session)
        assert result["total_matching"] == 2

    def test_filter_by_severity_critical(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_findings"].fn({"severity": "critical"}, session)
        assert result["total_matching"] == 1
        assert result["findings"][0]["severity"] == "critical"

    def test_filter_by_category(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_findings"].fn(
            {"category": "missing_dependency"}, session
        )
        assert result["total_matching"] == 2

    def test_limit(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_findings"].fn({"limit": 1}, session)
        assert result["returned"] == 1

    def test_detection_name_resolved(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_findings"].fn({"severity": "critical"}, session)
        # Should show detection name, not ID
        assert result["findings"][0]["detection"] == "Data Exfiltration"


# ── get_coverage_gaps ────────────────────────────────────────────────────────


class TestGetCoverageGaps:
    def test_no_coverage_returns_unavailable(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_coverage_gaps"].fn({}, session)
        assert result["available"] is False
        assert "coverage" in result["message"].lower()

    def test_coverage_from_metadata(self):
        session = _session_with_report(
            metadata={
                "coverage_summary": {
                    "coverage_score": 0.6,
                    "covered_techniques": 6,
                    "partial_techniques": 2,
                    "uncovered_techniques": 2,
                    "tactic_breakdown": {"initial_access": {"covered": 2, "total": 3}},
                    "techniques": [
                        {
                            "technique_id": "T1110",
                            "technique_name": "Brute Force",
                            "tactic": "credential_access",
                            "coverage": "covered",
                            "detection_count": 1,
                        },
                        {
                            "technique_id": "T1566",
                            "technique_name": "Phishing",
                            "tactic": "initial_access",
                            "coverage": "uncovered",
                            "detection_count": 0,
                        },
                    ],
                }
            }
        )
        result = TOOL_REGISTRY["get_coverage_gaps"].fn({}, session)
        assert result["available"] is True
        assert result["covered"] == 6
        assert len(result["techniques"]) == 2

    def test_uncovered_only_filter(self):
        session = _session_with_report(
            metadata={
                "coverage_summary": {
                    "coverage_score": 0.5,
                    "covered_techniques": 1,
                    "partial_techniques": 0,
                    "uncovered_techniques": 1,
                    "techniques": [
                        {"technique_id": "T1110", "coverage": "covered", "detection_count": 1},
                        {"technique_id": "T1566", "coverage": "uncovered", "detection_count": 0},
                    ],
                }
            }
        )
        result = TOOL_REGISTRY["get_coverage_gaps"].fn({"uncovered_only": True}, session)
        assert result["available"] is True
        assert all(t["coverage"] == "uncovered" for t in result["techniques"])


# ── get_dependency_issues ────────────────────────────────────────────────────


class TestGetDependencyIssues:
    def test_returns_affected_detections(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_dependency_issues"].fn({}, session)
        assert result["total_affected_detections"] == 2
        names = [i["detection"] for i in result["issues"]]
        assert "Data Exfiltration" in names

    def test_filter_by_severity(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_dependency_issues"].fn(
            {"severity": "critical"}, session
        )
        assert result["total_affected_detections"] == 1
        assert result["issues"][0]["detection"] == "Data Exfiltration"

    def test_runnable_not_included(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_dependency_issues"].fn({}, session)
        names = [i["detection"] for i in result["issues"]]
        assert "Brute Force Login" not in names


# ── get_runtime_health ───────────────────────────────────────────────────────


class TestGetRuntimeHealth:
    def test_not_available_when_no_metadata(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_runtime_health"].fn({}, session)
        assert result["available"] is False

    def test_returns_runtime_data_when_present(self):
        session = _session_with_report(
            metadata={
                "runtime_health_summary": {
                    "total_detections": 3,
                    "healthy": 2,
                    "degraded": 1,
                    "overall_health_score": 0.8,
                }
            }
        )
        result = TOOL_REGISTRY["get_runtime_health"].fn({}, session)
        assert result["available"] is True
        assert result["overall_health_score"] == 0.8


# ── get_optimization_recommendations ─────────────────────────────────────────


class TestGetOptimizationRecommendations:
    def test_not_available_when_no_metadata(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["get_optimization_recommendations"].fn({}, session)
        assert result["available"] is False

    def test_returns_recommendations_when_present(self):
        session = _session_with_report(
            metadata={
                "optimization_summary": {
                    "current_score": 0.33,
                    "max_achievable_score": 0.9,
                    "priorities": [
                        {
                            "rank": 1,
                            "dependency_name": "my_macro",
                            "dependency_kind": "macro",
                            "score_impact": 0.33,
                            "detections_affected": 1,
                            "effort": "low",
                            "recommended_action": "Define macro my_macro in macros.conf",
                        }
                    ],
                }
            }
        )
        result = TOOL_REGISTRY["get_optimization_recommendations"].fn({}, session)
        assert result["available"] is True
        assert result["max_achievable_score"] == 0.9
        assert len(result["recommendations"]) == 1
        assert result["recommendations"][0]["dependency"] == "my_macro"


# ── explain_detection ────────────────────────────────────────────────────────


class TestExplainDetection:
    def test_explains_runnable(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["explain_detection"].fn(
            {"name": "Brute Force Login"}, session
        )
        assert result["status"] == "runnable"
        assert "operational" in result["explanation"].lower()
        assert result["score"] == 1.0

    def test_explains_blocked(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["explain_detection"].fn(
            {"name": "Data Exfiltration"}, session
        )
        assert result["status"] == "blocked"
        assert "cannot run" in result["explanation"].lower() or "blocked" in result["explanation"].lower()
        assert len(result["blocked_dependencies"]) > 0

    def test_explanation_has_recommended_action(self):
        session = _session_with_report()
        result = TOOL_REGISTRY["explain_detection"].fn(
            {"name": "Data Exfiltration"}, session
        )
        assert result["recommended_action"]


# ── compare_reports ──────────────────────────────────────────────────────────


class TestCompareReports:
    def test_requires_baseline(self):
        session = _session_with_report()
        with pytest.raises(ToolError, match="baseline"):
            TOOL_REGISTRY["compare_reports"].fn({}, session)

    def test_compare_with_loaded_baseline(self):
        session = _session_with_report()
        # Use same report as both baseline and current for a zero-drift case
        session.baseline = session.report
        result = TOOL_REGISTRY["compare_reports"].fn({}, session)
        assert "drift_events" in result
        assert "risk_score" in result
        assert "readiness_delta" in result
