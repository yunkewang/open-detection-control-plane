"""Integration tests for the ODCP agent CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from odcp.cli.main import app
from odcp.models import Detection, Environment, Platform, ReadinessScore, ReadinessStatus, ScanReport
from odcp.models.report import ReadinessSummary


runner = CliRunner()


def _write_report(tmp_path: Path, name: str = "TestEnv") -> Path:
    """Write a minimal scan report to a temp file and return its path."""
    report = ScanReport(
        environment=Environment(
            name=name,
            platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
        ),
        detections=[
            Detection(id="d1", name="Login Brute Force", search_query="index=auth"),
            Detection(id="d2", name="Data Exfil", search_query="index=network"),
        ],
        readiness_scores=[
            ReadinessScore(
                detection_id="d1",
                detection_name="Login Brute Force",
                status=ReadinessStatus.runnable,
                score=1.0,
            ),
            ReadinessScore(
                detection_id="d2",
                detection_name="Data Exfil",
                status=ReadinessStatus.blocked,
                score=0.0,
                total_dependencies=1,
                missing_dependencies=1,
            ),
        ],
        readiness_summary=ReadinessSummary(
            total_detections=2, runnable=1, blocked=1, overall_score=0.5
        ),
    )
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json())
    return path


# ── odcp agent tools ─────────────────────────────────────────────────────────


class TestAgentToolsCommand:
    def test_tools_table_output(self):
        result = runner.invoke(app, ["agent", "tools"])
        assert result.exit_code == 0
        assert "load_report" in result.output
        assert "get_detection_posture" in result.output
        assert "list_detections" in result.output

    def test_tools_json_output(self):
        result = runner.invoke(app, ["agent", "tools", "--format", "json"])
        assert result.exit_code == 0
        schemas = json.loads(result.output)
        assert isinstance(schemas, list)
        assert len(schemas) > 0
        for s in schemas:
            assert "name" in s
            assert "description" in s
            assert "input_schema" in s

    def test_tools_shows_all_expected(self):
        result = runner.invoke(app, ["agent", "tools"])
        for tool_name in [
            "load_report",
            "get_detection_posture",
            "list_detections",
            "get_detection_detail",
            "get_findings",
            "get_coverage_gaps",
            "get_dependency_issues",
            "explain_detection",
        ]:
            assert tool_name in result.output, f"Tool '{tool_name}' missing from output"


# ── odcp agent schema ─────────────────────────────────────────────────────────


class TestAgentSchemaCommand:
    def test_schema_anthropic_format(self):
        result = runner.invoke(app, ["agent", "schema"])
        assert result.exit_code == 0
        schemas = json.loads(result.output)
        assert isinstance(schemas, list)
        # Anthropic format uses 'input_schema'
        for s in schemas:
            assert "input_schema" in s

    def test_schema_openai_format(self):
        result = runner.invoke(app, ["agent", "schema", "--fmt", "openai"])
        assert result.exit_code == 0
        schemas = json.loads(result.output)
        assert isinstance(schemas, list)
        for s in schemas:
            assert s["type"] == "function"
            assert "parameters" in s["function"]

    def test_schema_write_to_file(self, tmp_path: Path):
        out_file = tmp_path / "tools.json"
        result = runner.invoke(
            app, ["agent", "schema", "--output", str(out_file)]
        )
        assert result.exit_code == 0
        assert out_file.exists()
        schemas = json.loads(out_file.read_text())
        assert len(schemas) > 0

    def test_schema_is_valid_json(self):
        result = runner.invoke(app, ["agent", "schema"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        # Re-serialise to confirm no issues
        assert json.dumps(parsed)


# ── Agent executor integration (no LLM required) ─────────────────────────────


class TestAgentExecutorIntegration:
    """Test the executor API end-to-end without hitting an LLM."""

    def test_full_workflow(self, tmp_path: Path):
        from odcp.agent import AgentSession, ToolExecutor

        report_path = _write_report(tmp_path)
        session = AgentSession()
        executor = ToolExecutor(session)

        # Step 1: load report
        result = executor.execute("load_report", {"path": str(report_path)})
        assert "error" not in result
        assert result["total_detections"] == 2

        # Step 2: get posture
        result = executor.execute("get_detection_posture", {})
        assert result["readiness"]["total"] == 2
        assert result["readiness"]["blocked"] == 1

        # Step 3: list blocked detections
        result = executor.execute("list_detections", {"status": "blocked"})
        assert result["total_matching"] == 1
        assert result["detections"][0]["name"] == "Data Exfil"

        # Step 4: explain the blocked detection
        result = executor.execute("explain_detection", {"name": "Data Exfil"})
        assert result["status"] == "blocked"
        assert result["explanation"]

    def test_error_recovery_no_report(self):
        from odcp.agent import AgentSession, ToolExecutor

        session = AgentSession()
        executor = ToolExecutor(session)

        # Without loading a report, tools should return error dicts (not raise)
        result = executor.execute("get_detection_posture", {})
        assert "error" in result

        # Loading a nonexistent file also returns error dict
        result = executor.execute("load_report", {"path": "/fake/path.json"})
        assert "error" in result

    def test_tool_schema_export_via_executor(self):
        from odcp.agent import get_tool_schemas

        anthropic_schemas = get_tool_schemas("anthropic")
        openai_schemas = get_tool_schemas("openai")

        assert len(anthropic_schemas) == len(openai_schemas)
        # Verify schemas are fully JSON serialisable
        json.dumps(anthropic_schemas)
        json.dumps(openai_schemas)

    def test_execute_from_llm_block_anthropic(self, tmp_path: Path):
        from odcp.agent import AgentSession, ToolExecutor

        report_path = _write_report(tmp_path)
        session = AgentSession()
        session.load_report_from_path(str(report_path))
        executor = ToolExecutor(session)

        block = {
            "id": "tu_001",
            "name": "list_detections",
            "input": {"limit": 10},
        }
        raw = executor.execute_from_llm_block(block)
        result = json.loads(raw)
        assert "detections" in result
        assert len(result["detections"]) == 2

    def test_get_dependency_issues_integration(self, tmp_path: Path):
        from odcp.agent import AgentSession, ToolExecutor

        report_path = _write_report(tmp_path)
        session = AgentSession()
        executor = ToolExecutor(session)
        executor.execute("load_report", {"path": str(report_path)})

        result = executor.execute("get_dependency_issues", {})
        assert "total_affected_detections" in result
        # "Data Exfil" has 1 missing dep
        assert result["total_affected_detections"] == 1

    def test_tuning_proposals_integration(self, tmp_path: Path):
        from odcp.agent import AgentSession, ToolExecutor

        report_path = _write_report(tmp_path)
        session = AgentSession()
        executor = ToolExecutor(session)
        executor.execute("load_report", {"path": str(report_path)})

        result = executor.execute("get_tuning_proposals", {})
        # Should succeed (may or may not have proposals, but no crash)
        assert "available" in result
        if result["available"]:
            assert "proposals" in result

    def test_ai_soc_cycle_integration(self, tmp_path: Path):
        from odcp.agent import AgentSession, ToolExecutor

        report_path = _write_report(tmp_path)
        session = AgentSession()
        executor = ToolExecutor(session)
        executor.execute("load_report", {"path": str(report_path)})

        result = executor.execute("run_ai_soc_cycle", {})
        assert "error" not in result
        assert "environment" in result
        assert "readiness_score" in result
        assert "priority_actions" in result

    def test_data_sources_integration(self, tmp_path: Path):
        from odcp.agent import AgentSession, ToolExecutor

        report_path = _write_report(tmp_path)
        session = AgentSession()
        executor = ToolExecutor(session)
        executor.execute("load_report", {"path": str(report_path)})

        result = executor.execute("get_data_sources", {})
        assert "available" in result

    def test_compare_reports_same_baseline(self, tmp_path: Path):
        from odcp.agent import AgentSession, ToolExecutor

        report_path = _write_report(tmp_path)
        session = AgentSession()
        executor = ToolExecutor(session)
        executor.execute("load_report", {"path": str(report_path)})
        # Load same report as baseline for zero-drift comparison
        executor.execute("load_baseline", {"path": str(report_path)})

        result = executor.execute("compare_reports", {})
        assert "error" not in result
        assert "drift_events" in result
        assert "readiness_delta" in result
