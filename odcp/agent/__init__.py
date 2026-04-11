"""ODCP AI agent integration layer.

Provides LLM-callable tool interfaces and agentic orchestration so that
language models (Claude, GPT, etc.) can query and reason over detection
posture data produced by ODCP scans.

Quickstart (Python API)::

    from odcp.agent import ToolExecutor, AgentSession, get_tool_schemas

    session = AgentSession()
    executor = ToolExecutor(session)

    # Load a report
    executor.execute("load_report", {"path": "report.json"})

    # Query tools directly (no LLM required)
    posture = executor.execute("get_detection_posture", {})

    # Export tool schemas for LLM consumption
    schemas = get_tool_schemas(fmt="anthropic")

CLI (requires ``anthropic`` extra)::

    odcp agent tools                     # list available tools
    odcp agent schema --fmt anthropic    # export JSON schema
    odcp agent run "What is blocked?"    # one-shot query
    odcp agent chat --report r.json      # interactive session
"""

from odcp.agent.executor import ToolExecutor
from odcp.agent.session import AgentSession
from odcp.agent.tools import TOOL_REGISTRY, ToolDefinition, ToolError, get_tool_schemas

__all__ = [
    "AgentSession",
    "ToolDefinition",
    "ToolError",
    "ToolExecutor",
    "TOOL_REGISTRY",
    "get_tool_schemas",
]
