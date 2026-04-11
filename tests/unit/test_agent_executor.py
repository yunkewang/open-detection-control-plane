"""Unit tests for the ODCP agent tool executor."""

from __future__ import annotations

import json

import pytest

from odcp.agent.executor import ToolExecutor
from odcp.agent.session import AgentSession
from odcp.agent.tools import TOOL_REGISTRY, ToolError
from odcp.models import (
    Detection,
    Environment,
    Platform,
    ReadinessScore,
    ReadinessStatus,
    ScanReport,
)
from odcp.models.report import ReadinessSummary


def _session_with_simple_report() -> AgentSession:
    session = AgentSession()
    session.report = ScanReport(
        environment=Environment(
            name="Exec Test Env",
            platforms=[Platform(name="splunk", vendor="Splunk", adapter_type="splunk")],
        ),
        detections=[
            Detection(id="det-1", name="Test Rule", search_query="index=main | stats count"),
        ],
        readiness_scores=[
            ReadinessScore(
                detection_id="det-1",
                detection_name="Test Rule",
                status=ReadinessStatus.runnable,
                score=1.0,
            )
        ],
        readiness_summary=ReadinessSummary(
            total_detections=1, runnable=1, overall_score=1.0
        ),
    )
    return session


class TestToolExecutor:
    def test_execute_valid_tool(self):
        session = _session_with_simple_report()
        executor = ToolExecutor(session)
        result = executor.execute("get_detection_posture", {})
        assert "readiness" in result
        assert result["readiness"]["total"] == 1

    def test_execute_unknown_tool_returns_error(self):
        session = _session_with_simple_report()
        executor = ToolExecutor(session)
        result = executor.execute("nonexistent_tool", {})
        assert "error" in result
        assert "nonexistent_tool" in result["error"]

    def test_execute_with_tool_error_returns_error_dict(self):
        session = AgentSession()  # no report loaded
        executor = ToolExecutor(session)
        result = executor.execute("get_detection_posture", {})
        assert "error" in result
        assert "No report loaded" in result["error"]

    def test_execute_list_detections(self):
        session = _session_with_simple_report()
        executor = ToolExecutor(session)
        result = executor.execute("list_detections", {})
        assert result["total_matching"] == 1
        assert result["detections"][0]["name"] == "Test Rule"

    def test_execute_returns_dict_always(self):
        session = _session_with_simple_report()
        executor = ToolExecutor(session)
        for tool_name in ["get_detection_posture", "list_detections", "get_findings"]:
            result = executor.execute(tool_name, {})
            assert isinstance(result, dict), f"Tool {tool_name} returned non-dict"

    def test_list_tools(self):
        session = AgentSession()
        executor = ToolExecutor(session)
        tools = executor.list_tools()
        assert len(tools) == len(TOOL_REGISTRY)
        for t in tools:
            assert "name" in t
            assert "description" in t


class TestExecuteFromLlmBlock:
    def test_anthropic_format(self):
        session = _session_with_simple_report()
        executor = ToolExecutor(session)
        block = {
            "id": "tool_abc123",
            "name": "get_detection_posture",
            "input": {},
        }
        raw = executor.execute_from_llm_block(block)
        result = json.loads(raw)
        assert "readiness" in result

    def test_openai_format(self):
        session = _session_with_simple_report()
        executor = ToolExecutor(session)
        block = {
            "id": "call_xyz",
            "function": {
                "name": "list_detections",
                "arguments": json.dumps({"limit": 5}),
            },
        }
        raw = executor.execute_from_llm_block(block)
        result = json.loads(raw)
        assert "detections" in result

    def test_openai_format_with_dict_arguments(self):
        session = _session_with_simple_report()
        executor = ToolExecutor(session)
        block = {
            "id": "call_xyz",
            "function": {
                "name": "list_detections",
                "arguments": {"limit": 5},
            },
        }
        raw = executor.execute_from_llm_block(block)
        result = json.loads(raw)
        assert "detections" in result

    def test_invalid_block_format_returns_error(self):
        session = AgentSession()
        executor = ToolExecutor(session)
        raw = executor.execute_from_llm_block({"invalid": "block"})
        result = json.loads(raw)
        assert "error" in result

    def test_result_is_always_valid_json(self):
        session = _session_with_simple_report()
        executor = ToolExecutor(session)
        # Even on error, the result should be valid JSON
        for tool_name in list(TOOL_REGISTRY.keys())[:5]:
            raw = executor.execute_from_llm_block(
                {"name": tool_name, "input": {}}
            )
            try:
                json.loads(raw)
            except json.JSONDecodeError:
                pytest.fail(f"Tool {tool_name} returned invalid JSON: {raw[:200]}")


class TestAgentSession:
    def test_require_report_raises_when_empty(self):
        session = AgentSession()
        with pytest.raises(RuntimeError, match="No report loaded"):
            session.require_report()

    def test_require_report_returns_report(self):
        session = _session_with_simple_report()
        report = session.require_report()
        assert report.environment.name == "Exec Test Env"

    def test_load_report_from_path(self, tmp_path):
        report = ScanReport(
            environment=Environment(name="FileEnv"),
        )
        path = tmp_path / "test_report.json"
        path.write_text(report.model_dump_json())

        session = AgentSession()
        loaded = session.load_report_from_path(str(path))
        assert loaded.environment.name == "FileEnv"
        assert session.report is not None

    def test_load_missing_file_raises(self):
        session = AgentSession()
        with pytest.raises(FileNotFoundError):
            session.load_report_from_path("/no/such/file.json")

    def test_load_baseline_from_path(self, tmp_path):
        report = ScanReport(environment=Environment(name="BaseEnv"))
        path = tmp_path / "base.json"
        path.write_text(report.model_dump_json())

        session = AgentSession()
        loaded = session.load_baseline_from_path(str(path))
        assert loaded.environment.name == "BaseEnv"
        assert session.baseline is not None
        # Should not set main report
        assert session.report is None
