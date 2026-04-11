"""Agentic orchestrator — multi-turn Claude tool-use loop.

This module wires the ODCP tool registry to Anthropic's Claude API using
the native tool-use protocol.  It is intentionally kept minimal so that it
can also serve as a reference implementation for other LLM backends.

The ``anthropic`` package is an *optional* dependency (``pip install
odcp[agent]``).  All imports are deferred to runtime so the rest of
``odcp`` stays importable without it installed.

Typical usage::

    from odcp.agent.orchestrator import run_agent

    result = run_agent(
        prompt="Which detections are blocked and why?",
        report_path="report.json",
        model="claude-opus-4-6",
    )
    print(result)

Interactive loop::

    from odcp.agent.orchestrator import interactive_session
    interactive_session(report_path="report.json")
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional

from odcp.agent.executor import ToolExecutor
from odcp.agent.session import AgentSession
from odcp.agent.tools import get_tool_schemas

# Default Claude model — use the most capable available
_DEFAULT_MODEL = "claude-opus-4-6"

# System prompt that grounds Claude in the ODCP context
_SYSTEM_PROMPT = """\
You are an expert Security Operations analyst with deep knowledge of \
detection engineering and security platforms.

You have access to a set of ODCP (Open Detection Control Plane) tools that \
let you inspect detection posture data: readiness scores, MITRE ATT&CK \
coverage, dependency issues, runtime health, AI SOC recommendations, and more.

Guidelines:
- Always load the report first with load_report before calling other tools.
- When asked about "blocked" or "failing" detections, use get_dependency_issues \
  and list_detections with status="blocked".
- For coverage questions use get_coverage_gaps.
- For operational health use get_runtime_health.
- For remediation priorities use get_optimization_recommendations.
- For a comprehensive SOC view use run_ai_soc_cycle.
- When summarising findings, be concise and action-oriented.
- Use explain_detection when a user asks about a specific rule.
- Cite scores as percentages and highlight critical/high-severity issues first.
- If a tool returns {"available": false}, tell the user what scan flags to add.
"""


def _require_anthropic() -> Any:
    """Import and return the ``anthropic`` module, raising a friendly error if absent."""
    try:
        import anthropic  # type: ignore[import]

        return anthropic
    except ImportError:
        print(
            "\n[ERROR] The 'anthropic' package is required for agent commands.\n"
            "Install it with:  pip install 'odcp[agent]'\n",
            file=sys.stderr,
        )
        sys.exit(1)


# ── One-shot agent run ───────────────────────────────────────────────────────


def run_agent(
    prompt: str,
    *,
    report_path: Optional[str] = None,
    model: str = _DEFAULT_MODEL,
    api_key: Optional[str] = None,
    max_turns: int = 10,
    verbose: bool = False,
) -> str:
    """Run the agent for a single prompt and return the final text response.

    Parameters
    ----------
    prompt:
        Natural-language question or instruction for the agent.
    report_path:
        If provided, the first turn automatically loads this report file.
    model:
        Claude model ID to use.
    api_key:
        Anthropic API key.  Falls back to ``ANTHROPIC_API_KEY`` env var.
    max_turns:
        Maximum agentic turns (tool-call + response cycles) before giving up.
    verbose:
        Print intermediate tool calls and results to stderr.
    """
    anthropic = _require_anthropic()

    client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
    session = AgentSession()
    executor = ToolExecutor(session)
    tools = get_tool_schemas(fmt="anthropic")

    # Prime the conversation: if a report path was given, ask Claude to load it
    user_message = prompt
    if report_path:
        user_message = (
            f'The ODCP scan report is at "{report_path}". '
            f"Please load it and then answer: {prompt}"
        )

    messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]

    for turn in range(max_turns):
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            tools=tools,
            messages=messages,
        )

        if verbose:
            print(f"\n[turn {turn + 1}] stop_reason={response.stop_reason}", file=sys.stderr)

        # Collect assistant content blocks
        assistant_blocks: list[dict[str, Any]] = []
        tool_use_blocks: list[Any] = []

        for block in response.content:
            if block.type == "text":
                assistant_blocks.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                assistant_blocks.append(
                    {
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    }
                )
                tool_use_blocks.append(block)

        messages.append({"role": "assistant", "content": assistant_blocks})

        if response.stop_reason == "end_turn":
            # Extract the final text response
            texts = [b["text"] for b in assistant_blocks if b.get("type") == "text"]
            return "\n".join(texts).strip()

        if response.stop_reason != "tool_use" or not tool_use_blocks:
            # Unexpected stop — return whatever text we have
            texts = [b["text"] for b in assistant_blocks if b.get("type") == "text"]
            return "\n".join(texts).strip() or "(no response)"

        # Execute all tool calls and collect results
        tool_results: list[dict[str, Any]] = []
        for block in tool_use_blocks:
            if verbose:
                print(
                    f"  → tool: {block.name}  params: {json.dumps(block.input, default=str)[:200]}",
                    file=sys.stderr,
                )
            raw = executor.execute_from_llm_block(
                {"name": block.name, "input": block.input}
            )
            if verbose:
                print(f"  ← result: {raw[:300]}", file=sys.stderr)
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": raw,
                }
            )

        messages.append({"role": "user", "content": tool_results})

    return "(Agent reached max_turns without a final answer.)"


# ── Interactive chat session ─────────────────────────────────────────────────


def interactive_session(
    *,
    report_path: Optional[str] = None,
    model: str = _DEFAULT_MODEL,
    api_key: Optional[str] = None,
    max_turns_per_query: int = 10,
    verbose: bool = False,
) -> None:
    """Start an interactive chat session in the terminal.

    Each user message triggers a fresh agent run that carries the session
    state (loaded report, scratch cache) across turns.
    """
    anthropic = _require_anthropic()

    client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
    session = AgentSession()
    executor = ToolExecutor(session)
    tools = get_tool_schemas(fmt="anthropic")

    # ── Banner ──────────────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("  ODCP AI Agent  —  detection posture assistant")
    if report_path:
        print(f"  Report: {report_path}")
    print("  Type 'exit' or press Ctrl-C to quit.")
    print("═" * 60 + "\n")

    # Pre-load report so later turns don't need to do it
    if report_path:
        result = executor.execute("load_report", {"path": report_path})
        if "error" not in result:
            print(
                f"[loaded] {result.get('environment')} | "
                f"{result.get('total_detections')} detections | "
                f"score {result.get('overall_score', 0):.0%}\n"
            )
        else:
            print(f"[warn] Could not load report: {result['error']}\n")

    # Persistent conversation history (grows across user turns)
    conversation: list[dict[str, Any]] = []

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break

        if not user_input:
            continue
        if user_input.lower() in {"exit", "quit", "bye"}:
            print("Bye!")
            break

        conversation.append({"role": "user", "content": user_input})

        # Agentic loop for this turn
        for turn in range(max_turns_per_query):
            response = client.messages.create(
                model=model,
                max_tokens=4096,
                system=_SYSTEM_PROMPT,
                tools=tools,
                messages=conversation,
            )

            assistant_blocks: list[dict[str, Any]] = []
            tool_use_blocks: list[Any] = []

            for block in response.content:
                if block.type == "text":
                    assistant_blocks.append({"type": "text", "text": block.text})
                elif block.type == "tool_use":
                    assistant_blocks.append(
                        {
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        }
                    )
                    tool_use_blocks.append(block)

            conversation.append({"role": "assistant", "content": assistant_blocks})

            if response.stop_reason == "end_turn":
                texts = [b["text"] for b in assistant_blocks if b.get("type") == "text"]
                answer = "\n".join(texts).strip()
                print(f"\nAgent: {answer}\n")
                break

            if response.stop_reason != "tool_use" or not tool_use_blocks:
                texts = [b["text"] for b in assistant_blocks if b.get("type") == "text"]
                print(f"\nAgent: {' '.join(texts) or '(no response)'}\n")
                break

            # Execute tools
            tool_results: list[dict[str, Any]] = []
            for block in tool_use_blocks:
                if verbose:
                    print(f"  [tool] {block.name}", file=sys.stderr)
                raw = executor.execute_from_llm_block(
                    {"name": block.name, "input": block.input}
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": raw,
                    }
                )
            conversation.append({"role": "user", "content": tool_results})
        else:
            print("\nAgent: (reached turn limit for this query)\n")
