"""Tool executor — dispatches LLM tool-call requests to Python implementations.

The executor is the thin layer between the agent orchestrator (which speaks
the LLM protocol) and the tool implementations (which speak Python).

Usage::

    from odcp.agent import AgentSession, ToolExecutor

    session = AgentSession()
    executor = ToolExecutor(session)

    result = executor.execute("load_report", {"path": "report.json"})
    posture = executor.execute("get_detection_posture", {})
"""

from __future__ import annotations

import json
import traceback
from typing import Any

from odcp.agent.session import AgentSession
from odcp.agent.tools import TOOL_REGISTRY, ToolError


class ToolExecutor:
    """Dispatch tool calls to registered implementations.

    Parameters
    ----------
    session:
        The :class:`~odcp.agent.session.AgentSession` that carries mutable
        state (loaded report, baseline, scratch) across tool calls.
    """

    def __init__(self, session: AgentSession) -> None:
        self.session = session

    # ── Public API ─────────────────────────────────────────────────────────

    def execute(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute a named tool and return its result as a dict.

        Returns a dict that is always JSON-serialisable so it can be
        embedded directly in an LLM message.

        On :class:`~odcp.agent.tools.ToolError` the error message is
        returned as ``{"error": "..."}`` rather than raising, so the LLM
        can read it and respond accordingly.

        On unexpected exceptions the error + truncated traceback are
        returned as ``{"error": "...", "traceback": "..."}`` and the
        exception is *not* re-raised.
        """
        tool = TOOL_REGISTRY.get(name)
        if tool is None:
            available = list(TOOL_REGISTRY.keys())
            return {
                "error": f"Unknown tool '{name}'. Available tools: {available}"
            }

        try:
            result = tool.fn(params, self.session)
            # Ensure the result is always a dict
            if not isinstance(result, dict):
                result = {"result": result}
            return result
        except ToolError as exc:
            return {"error": str(exc)}
        except RuntimeError as exc:
            # e.g. "No report loaded" from require_report()
            return {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            tb = traceback.format_exc(limit=5)
            return {
                "error": f"Unexpected error in tool '{name}': {exc}",
                "traceback": tb,
            }

    def execute_from_llm_block(self, tool_use_block: dict[str, Any]) -> str:
        """Execute a tool from an LLM tool-use message block.

        Accepts Anthropic-style ``{"id": ..., "name": ..., "input": {...}}``
        or OpenAI-style ``{"id": ..., "function": {"name": ..., "arguments": "..."}}``
        blocks.  Returns the result as a JSON string suitable for the
        corresponding tool-result message.
        """
        # Anthropic format
        if "name" in tool_use_block and "input" in tool_use_block:
            name = tool_use_block["name"]
            params = tool_use_block.get("input") or {}
        # OpenAI format
        elif "function" in tool_use_block:
            fn_block = tool_use_block["function"]
            name = fn_block["name"]
            raw = fn_block.get("arguments", "{}")
            try:
                params = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                params = {}
        else:
            return json.dumps({"error": "Unrecognised tool-use block format."})

        result = self.execute(name, params)
        return json.dumps(result, default=str)

    # ── Introspection ──────────────────────────────────────────────────────

    def list_tools(self) -> list[dict[str, str]]:
        """Return a brief listing of all registered tools."""
        return [
            {"name": t.name, "description": t.description[:120]}
            for t in TOOL_REGISTRY.values()
        ]
