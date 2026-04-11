"""LLM-callable tool definitions for ODCP.

Each tool:
* Has a JSON-Schema ``input_schema`` compatible with Anthropic and OpenAI tool formats.
* Is implemented as a plain Python function: ``fn(params, session) -> dict``.
* Returns a JSON-serialisable dict so that it can be embedded directly in an
  LLM message stream without further transformation.
* Raises ``ToolError`` for recoverable errors (bad params, missing data, etc.)
  so the orchestrator can relay the message back to the LLM without crashing.

The module-level ``TOOL_REGISTRY`` maps tool name → ``ToolDefinition`` and is
the single source of truth consumed by both the executor and the schema
export helpers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from odcp.agent.session import AgentSession

# ── Errors ─────────────────────────────────────────────────────────────────


class ToolError(Exception):
    """Raised by tool implementations for user-visible, recoverable errors."""


# ── Tool definition ─────────────────────────────────────────────────────────


@dataclass
class ToolDefinition:
    """Metadata + implementation for a single LLM-callable tool."""

    name: str
    description: str
    input_schema: dict[str, Any]
    fn: Callable[[dict[str, Any], "AgentSession"], Any]

    def to_anthropic_schema(self) -> dict[str, Any]:
        """Return the Anthropic tool-use schema block."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

    def to_openai_schema(self) -> dict[str, Any]:
        """Return the OpenAI function-calling schema block."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema,
            },
        }


# ── Helpers ─────────────────────────────────────────────────────────────────


def _truncate(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _sev_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


# ── Tool implementations ────────────────────────────────────────────────────


def _primary_platform(report) -> str:
    """Return the first platform adapter_type or 'unknown'."""
    platforms = report.environment.platforms
    if platforms:
        return platforms[0].adapter_type
    return "unknown"


def _load_report(params: dict[str, Any], session: "AgentSession") -> dict:
    """Load a scan report from disk."""
    path = params.get("path", "")
    if not path:
        raise ToolError("'path' parameter is required.")
    report = session.load_report_from_path(path)
    rs = report.readiness_summary
    return {
        "status": "loaded",
        "environment": report.environment.name,
        "platform": _primary_platform(report),
        "scan_timestamp": report.scan_timestamp.isoformat(),
        "total_detections": rs.total_detections,
        "overall_score": round(rs.overall_score, 3),
        "total_findings": len(report.findings),
    }


def _load_baseline(params: dict[str, Any], session: "AgentSession") -> dict:
    """Load a baseline scan report from disk for drift comparison."""
    path = params.get("path", "")
    if not path:
        raise ToolError("'path' parameter is required.")
    baseline = session.load_baseline_from_path(path)
    rs = baseline.readiness_summary
    return {
        "status": "loaded_as_baseline",
        "environment": baseline.environment.name,
        "scan_timestamp": baseline.scan_timestamp.isoformat(),
        "total_detections": rs.total_detections,
        "overall_score": round(rs.overall_score, 3),
    }


def _get_detection_posture(params: dict[str, Any], session: "AgentSession") -> dict:
    """Return the overall detection readiness posture."""
    report = session.require_report()
    rs = report.readiness_summary
    ds = report.dependency_stats

    result: dict[str, Any] = {
        "environment": report.environment.name,
        "platform": _primary_platform(report),
        "scan_timestamp": report.scan_timestamp.isoformat(),
        "readiness": {
            "total": rs.total_detections,
            "runnable": rs.runnable,
            "partially_runnable": rs.partially_runnable,
            "blocked": rs.blocked,
            "unknown": rs.unknown,
            "overall_score": round(rs.overall_score, 3),
            "blocked_pct": round(rs.blocked / rs.total_detections, 3)
            if rs.total_detections
            else 0.0,
        },
        "dependencies": {
            "total": ds.total,
            "by_status": ds.by_status,
        },
        "findings_by_severity": {},
    }

    # tally findings by severity
    sev_counts: dict[str, int] = {}
    for f in report.findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
    result["findings_by_severity"] = sev_counts

    # include runtime info if present
    rt = report.metadata.get("runtime_health_summary")
    if rt:
        result["runtime_health"] = rt

    return result


def _list_detections(params: dict[str, Any], session: "AgentSession") -> dict:
    """List detections, optionally filtered by status / severity / name fragment."""
    report = session.require_report()
    status_filter = (params.get("status") or "").lower()
    severity_filter = (params.get("severity") or "").lower()
    name_filter = (params.get("name_contains") or "").lower()
    limit = int(params.get("limit") or 50)

    # Build score map
    score_map = {s.detection_id: s for s in report.readiness_scores}

    results = []
    for det in report.detections:
        score = score_map.get(det.id)
        status = score.status.value if score else "unknown"
        sev = det.severity.value

        if status_filter and status != status_filter:
            continue
        if severity_filter and sev != severity_filter:
            continue
        if name_filter and name_filter not in det.name.lower():
            continue

        results.append(
            {
                "name": det.name,
                "severity": sev,
                "status": status,
                "score": round(score.score, 3) if score else None,
                "missing_deps": score.missing_dependencies if score else 0,
                "enabled": det.enabled,
                "tags": det.tags[:5],
            }
        )

    # Sort: blocked first, then by name
    results.sort(key=lambda r: (_sev_order(r["status"].replace("partially_runnable", "medium")), r["name"]))
    total = len(results)
    results = results[:limit]

    return {
        "total_matching": total,
        "returned": len(results),
        "detections": results,
    }


def _get_detection_detail(params: dict[str, Any], session: "AgentSession") -> dict:
    """Return full details for a specific detection by name."""
    report = session.require_report()
    name = params.get("name", "").strip()
    if not name:
        raise ToolError("'name' parameter is required.")

    # Fuzzy-find: exact first, then substring
    det = None
    for d in report.detections:
        if d.name.lower() == name.lower():
            det = d
            break
    if det is None:
        matches = [d for d in report.detections if name.lower() in d.name.lower()]
        if len(matches) == 1:
            det = matches[0]
        elif len(matches) > 1:
            raise ToolError(
                f"Ambiguous name '{name}' matches {len(matches)} detections: "
                + ", ".join(m.name for m in matches[:5])
            )
        else:
            raise ToolError(
                f"No detection named '{name}'. "
                f"Use list_detections to see available detections."
            )

    # Readiness score
    score = next((s for s in report.readiness_scores if s.detection_id == det.id), None)

    # Dependencies for this detection: referenced dep IDs → Dependency objects
    dep_map = {d.id: d for d in report.dependencies}
    deps = [dep_map[ref] for ref in det.references if ref in dep_map]

    # Also collect deps referenced via findings (covers cases where references may be empty)
    dep_ids_via_findings: set[str] = set()
    findings = [f for f in report.findings if f.detection_id == det.id]
    for f in findings:
        if f.dependency_id:
            dep_ids_via_findings.add(f.dependency_id)
    for dep_id in dep_ids_via_findings:
        if dep_id in dep_map and dep_map[dep_id] not in deps:
            deps.append(dep_map[dep_id])

    return {
        "name": det.name,
        "description": det.description or "",
        "severity": det.severity.value,
        "enabled": det.enabled,
        "source_file": det.source_file or "",
        "search_query": _truncate(det.search_query, 500),
        "tags": det.tags,
        "readiness": {
            "status": score.status.value if score else "unknown",
            "score": round(score.score, 3) if score else None,
            "total_dependencies": score.total_dependencies if score else 0,
            "resolved": score.resolved_dependencies if score else 0,
            "missing": score.missing_dependencies if score else 0,
        },
        "dependencies": [
            {
                "name": d.name,
                "kind": d.kind.value,
                "status": d.status.value,
            }
            for d in deps
        ],
        "findings": [
            {
                "category": f.category.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": _truncate(f.description, 300),
                "remediation": f.remediation.title if f.remediation else None,
            }
            for f in sorted(findings, key=lambda x: _sev_order(x.severity.value))
        ],
    }


def _get_findings(params: dict[str, Any], session: "AgentSession") -> dict:
    """Return findings, optionally filtered by severity and/or category."""
    report = session.require_report()
    severity_filter = (params.get("severity") or "").lower()
    category_filter = (params.get("category") or "").lower()
    limit = int(params.get("limit") or 50)

    findings = report.findings
    if severity_filter:
        findings = [f for f in findings if f.severity.value == severity_filter]
    if category_filter:
        findings = [f for f in findings if f.category.value == category_filter]

    findings = sorted(findings, key=lambda f: _sev_order(f.severity.value))

    total = len(findings)
    page = findings[:limit]

    # Build detection name lookup
    det_map = {d.id: d.name for d in report.detections}

    return {
        "total_matching": total,
        "returned": len(page),
        "findings": [
            {
                "detection": det_map.get(f.detection_id, f.detection_id),
                "category": f.category.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": _truncate(f.description, 250),
                "remediation": f.remediation.title if f.remediation else None,
            }
            for f in page
        ],
    }


def _get_coverage_gaps(params: dict[str, Any], session: "AgentSession") -> dict:
    """Return MITRE ATT&CK coverage status from the report metadata."""
    report = session.require_report()
    uncovered_only = bool(params.get("uncovered_only", False))

    coverage_meta = report.metadata.get("coverage_summary", {})
    if not coverage_meta:
        return {
            "available": False,
            "message": "Coverage analysis not available. Re-scan with --coverage flag.",
        }

    techniques = coverage_meta.get("techniques", [])
    if uncovered_only:
        techniques = [t for t in techniques if t.get("coverage") == "uncovered"]

    tactic_breakdown = coverage_meta.get("tactic_breakdown", {})

    return {
        "available": True,
        "coverage_score": round(coverage_meta.get("coverage_score", 0.0), 3),
        "covered": coverage_meta.get("covered_techniques", 0),
        "partial": coverage_meta.get("partial_techniques", 0),
        "uncovered": coverage_meta.get("uncovered_techniques", 0),
        "tactic_breakdown": tactic_breakdown,
        "techniques": [
            {
                "id": t.get("technique_id", ""),
                "name": t.get("technique_name", ""),
                "tactic": t.get("tactic", ""),
                "coverage": t.get("coverage", "uncovered"),
                "detection_count": t.get("detection_count", 0),
            }
            for t in techniques[:50]
        ],
    }


def _get_dependency_issues(params: dict[str, Any], session: "AgentSession") -> dict:
    """Return detections with missing or broken dependencies."""
    report = session.require_report()
    severity_filter = (params.get("severity") or "").lower()

    det_map = {d.id: d for d in report.detections}
    dep_map = {d.id: d for d in report.dependencies}

    # Build detection → blocked dep IDs via findings (dependency_id on findings)
    det_blocked_dep_ids: dict[str, list[str]] = {}
    for f in report.findings:
        if f.dependency_id:
            det_blocked_dep_ids.setdefault(f.detection_id, []).append(f.dependency_id)

    issues = []
    for score in report.readiness_scores:
        if score.missing_dependencies == 0:
            continue
        det = det_map.get(score.detection_id)
        if det is None:
            continue

        # Collect blocked deps via both references and findings
        blocked_dep_ids = set(det_blocked_dep_ids.get(score.detection_id, []))
        # Also check referenced deps
        for ref_id in det.references:
            dep = dep_map.get(ref_id)
            if dep and dep.status.value in ("missing", "degraded", "unknown"):
                blocked_dep_ids.add(ref_id)

        blocked_deps = [dep_map[did] for did in blocked_dep_ids if did in dep_map]

        issues.append(
            {
                "detection": det.name,
                "severity": det.severity.value,
                "status": score.status.value,
                "score": round(score.score, 3),
                "missing_deps": score.missing_dependencies,
                "blocked_dependencies": [
                    {"name": d.name, "kind": d.kind.value, "status": d.status.value}
                    for d in blocked_deps[:10]
                ],
            }
        )

    if severity_filter:
        issues = [i for i in issues if i["severity"] == severity_filter]

    issues.sort(key=lambda i: (i["missing_deps"] * -1, _sev_order(i["severity"])))

    return {
        "total_affected_detections": len(issues),
        "issues": issues[:50],
    }


def _get_runtime_health(params: dict[str, Any], session: "AgentSession") -> dict:
    """Return runtime health summary if available in the report."""
    report = session.require_report()
    rt = report.metadata.get("runtime_health_summary")
    if not rt:
        return {
            "available": False,
            "message": "Runtime health data not available. Re-scan with --api-url and --token flags.",
        }
    return {"available": True, **rt}


def _get_tuning_proposals(params: dict[str, Any], session: "AgentSession") -> dict:
    """Return AI SOC detection tuning proposals if available."""
    report = session.require_report()

    # Tuning proposals may be cached in session scratch from a previous ai-soc cycle
    feedback = session.scratch.get("feedback_summary")
    if feedback is None:
        # Try computing it now
        try:
            from odcp.analyzers.ai_soc.feedback import FeedbackAnalyzer

            analyzer = FeedbackAnalyzer()
            feedback_obj = analyzer.analyze(report)
            feedback = feedback_obj.model_dump()
            session.scratch["feedback_summary"] = feedback
        except Exception as exc:
            return {"available": False, "message": f"Could not compute tuning proposals: {exc}"}

    proposals = feedback.get("proposals", [])
    priority_filter = (params.get("priority") or "").lower()
    if priority_filter:
        proposals = [p for p in proposals if p.get("priority") == priority_filter]

    return {
        "available": True,
        "total_analyzed": feedback.get("total_detections_analyzed", 0),
        "noisy": feedback.get("noisy_detections", 0),
        "stale": feedback.get("stale_detections", 0),
        "healthy": feedback.get("healthy_detections", 0),
        "total_proposals": len(proposals),
        "proposals": [
            {
                "detection": p.get("detection_name", ""),
                "action": p.get("proposal_type", ""),
                "priority": p.get("priority", ""),
                "rationale": _truncate(p.get("rationale", ""), 200),
            }
            for p in sorted(
                proposals,
                key=lambda p: {"high": 0, "medium": 1, "low": 2}.get(p.get("priority", ""), 3),
            )[:30]
        ],
        "recommendations": feedback.get("recommendations", []),
    }


def _run_ai_soc_cycle(params: dict[str, Any], session: "AgentSession") -> dict:
    """Run the full AI SOC automation cycle and return priority actions."""
    report = session.require_report()
    baseline_path = params.get("baseline_path", "")

    baseline = None
    if baseline_path:
        try:
            baseline = session.load_baseline_from_path(baseline_path)
        except FileNotFoundError as exc:
            raise ToolError(str(exc)) from exc

    try:
        from odcp.analyzers.ai_soc.orchestrator import AiSocOrchestrator

        orch = AiSocOrchestrator()
        result = orch.run_cycle(report, baseline=baseline)
    except Exception as exc:
        raise ToolError(f"AI SOC cycle failed: {exc}") from exc

    # Cache the feedback summary for subsequent get_tuning_proposals calls
    if result.feedback_summary:
        session.scratch["feedback_summary"] = result.feedback_summary.model_dump()

    return {
        "environment": result.environment_name,
        "readiness_score": round(result.readiness_score, 3),
        "detectable_now": result.detectable_now,
        "blocked_by_data": result.blocked_by_data,
        "blocked_by_logic": result.blocked_by_logic,
        "coverage_score": round(result.coverage_score, 3),
        "threat_intel_techniques": result.threat_intel_techniques,
        "source_catalog": {
            "total": result.source_catalog.total_sources
            if result.source_catalog
            else 0,
            "platforms": result.source_catalog.platforms_represented
            if result.source_catalog
            else [],
            "healthy": result.source_catalog.healthy_sources
            if result.source_catalog
            else 0,
            "degraded": result.source_catalog.degraded_sources
            if result.source_catalog
            else 0,
            "unavailable": result.source_catalog.unavailable_sources
            if result.source_catalog
            else 0,
        },
        "drift": {
            "events": result.drift_summary.total_drift_events
            if result.drift_summary
            else 0,
            "risk_score": round(result.drift_summary.risk_score, 3)
            if result.drift_summary
            else 0.0,
        },
        "priority_actions": result.priority_actions,
    }


def _get_optimization_recommendations(params: dict[str, Any], session: "AgentSession") -> dict:
    """Return ranked optimization / remediation recommendations from the report."""
    report = session.require_report()
    limit = int(params.get("limit") or 20)

    opt_meta = report.metadata.get("optimization_summary", {})
    if not opt_meta:
        return {
            "available": False,
            "message": "Optimization analysis not available. Re-scan with --coverage flag.",
        }

    priorities = opt_meta.get("priorities", [])
    return {
        "available": True,
        "current_score": round(opt_meta.get("current_score", 0.0), 3),
        "max_achievable_score": round(opt_meta.get("max_achievable_score", 0.0), 3),
        "recommendations": [
            {
                "rank": p.get("rank", i + 1),
                "dependency": p.get("dependency_name", ""),
                "kind": p.get("dependency_kind", ""),
                "impact": round(p.get("score_impact", 0.0), 3),
                "detections_affected": p.get("detections_affected", 0),
                "effort": p.get("effort", "medium"),
                "action": _truncate(p.get("recommended_action", ""), 200),
            }
            for i, p in enumerate(priorities[:limit])
        ],
    }


def _get_data_sources(params: dict[str, Any], session: "AgentSession") -> dict:
    """Return the data source inventory from the report metadata."""
    report = session.require_report()

    ds_meta = report.metadata.get("data_source_inventory", {})
    if not ds_meta:
        # Try to build it on the fly from the AI SOC source inventory
        try:
            from odcp.analyzers.ai_soc.source_inventory import SourceInventoryBuilder

            builder = SourceInventoryBuilder()
            catalog = builder.build_from_single(report)
            return {
                "available": True,
                "total_sources": catalog.total_sources,
                "platforms": catalog.platforms_represented,
                "healthy": catalog.healthy_sources,
                "degraded": catalog.degraded_sources,
                "unavailable": catalog.unavailable_sources,
                "attack_coverage": list(catalog.attack_data_source_coverage.keys())[:20],
                "sources": [
                    {
                        "name": s.name,
                        "platform": s.platform,
                        "kind": s.source_kind,
                        "health": s.health.value if s.health else "unknown",
                        "detection_count": s.detection_count,
                    }
                    for s in catalog.sources[:30]
                ],
            }
        except Exception as exc:
            return {
                "available": False,
                "message": f"Data source inventory not available: {exc}",
            }

    return {"available": True, **ds_meta}


def _compare_reports(params: dict[str, Any], session: "AgentSession") -> dict:
    """Compare the current report against the loaded baseline to detect drift."""
    report = session.require_report()

    if session.baseline is None:
        baseline_path = params.get("baseline_path", "")
        if baseline_path:
            try:
                session.load_baseline_from_path(baseline_path)
            except FileNotFoundError as exc:
                raise ToolError(str(exc)) from exc
        else:
            raise ToolError(
                "No baseline loaded. Either call load_baseline first or pass 'baseline_path'."
            )

    baseline = session.baseline
    assert baseline is not None  # for type checker

    try:
        from odcp.analyzers.ai_soc.drift_detector import DriftDetector

        drift = DriftDetector().compare_reports(baseline, report)
    except Exception as exc:
        raise ToolError(f"Drift comparison failed: {exc}") from exc

    rs_curr = report.readiness_summary
    rs_base = baseline.readiness_summary
    score_delta = rs_curr.overall_score - rs_base.overall_score

    return {
        "baseline_timestamp": baseline.scan_timestamp.isoformat(),
        "current_timestamp": report.scan_timestamp.isoformat(),
        "readiness_delta": round(score_delta, 3),
        "drift_events": drift.total_drift_events,
        "risk_score": round(drift.risk_score, 3),
        "sources_added": drift.sources_added,
        "sources_removed": drift.sources_removed,
        "health_changes": drift.health_changes,
        "top_events": [
            {
                "kind": e.event_kind,
                "source": e.source_name,
                "severity": e.severity,
                "description": _truncate(e.description, 200),
            }
            for e in drift.events[:10]
        ],
        "recommendations": drift.recommendations,
    }


def _explain_detection(params: dict[str, Any], session: "AgentSession") -> dict:
    """Return a plain-language explanation of a detection's current operational state."""
    # Delegate to get_detection_detail first
    detail = _get_detection_detail(params, session)

    readiness = detail["readiness"]
    status = readiness["status"]
    score = readiness.get("score") or 0.0
    missing = readiness.get("missing", 0)
    findings = detail.get("findings", [])
    name = detail["name"]

    # Build a structured explanation
    if status == "runnable":
        state_msg = (
            f"'{name}' is fully operational. All {readiness['total_dependencies']} "
            f"dependencies are resolved and it has a readiness score of {score:.0%}."
        )
    elif status == "partially_runnable":
        state_msg = (
            f"'{name}' can run but is impaired. {missing} of "
            f"{readiness['total_dependencies']} dependencies are missing, "
            f"reducing its score to {score:.0%}."
        )
    elif status == "blocked":
        state_msg = (
            f"'{name}' cannot run. {missing} critical dependencies are missing "
            f"(readiness {score:.0%}). It will not fire any alerts in its current state."
        )
    else:
        state_msg = (
            f"'{name}' has unknown readiness ({score:.0%}). "
            f"Dependency resolution is incomplete."
        )

    # Summarise top findings
    finding_summaries = []
    for f in findings[:3]:
        finding_summaries.append(
            f"• [{f['severity'].upper()}] {f['title']}: {_truncate(f['description'], 150)}"
        )
        if f["remediation"]:
            finding_summaries.append(f"  Fix: {f['remediation']}")

    # What needs fixing
    blocked_deps = [
        d for d in detail.get("dependencies", []) if d["status"] != "exists"
    ]

    return {
        "name": name,
        "severity": detail["severity"],
        "enabled": detail["enabled"],
        "status": status,
        "score": score,
        "explanation": state_msg,
        "key_issues": finding_summaries,
        "blocked_dependencies": [
            f"{d['name']} ({d['kind']})" for d in blocked_deps[:5]
        ],
        "recommended_action": _first_remediation(detail),
    }


def _first_remediation(detail: dict) -> str:
    for f in detail.get("findings", []):
        if f.get("remediation"):
            return f["remediation"]
    if detail["readiness"]["missing"] > 0:
        return f"Resolve {detail['readiness']['missing']} missing dependencies."
    if not detail["enabled"]:
        return "Enable the detection rule."
    return "No immediate action required."


# ── Registry ────────────────────────────────────────────────────────────────

TOOL_REGISTRY: dict[str, ToolDefinition] = {}


def _register(
    name: str,
    description: str,
    properties: dict[str, Any],
    required: list[str],
    fn: Callable[[dict[str, Any], Any], Any],
) -> None:
    TOOL_REGISTRY[name] = ToolDefinition(
        name=name,
        description=description,
        input_schema={
            "type": "object",
            "properties": properties,
            "required": required,
        },
        fn=fn,
    )


_register(
    name="load_report",
    description=(
        "Load an ODCP scan report JSON file from disk into the current session. "
        "This must be called before most other tools. Returns a brief summary of what was loaded."
    ),
    properties={
        "path": {
            "type": "string",
            "description": "Absolute or relative path to the scan report JSON file.",
        }
    },
    required=["path"],
    fn=_load_report,
)

_register(
    name="load_baseline",
    description=(
        "Load an older ODCP scan report as the baseline for drift comparison. "
        "Must be called before compare_reports if a baseline_path is not provided inline."
    ),
    properties={
        "path": {
            "type": "string",
            "description": "Path to the baseline scan report JSON file.",
        }
    },
    required=["path"],
    fn=_load_baseline,
)

_register(
    name="get_detection_posture",
    description=(
        "Return the overall detection readiness posture: readiness score, "
        "counts of runnable/blocked detections, dependency statistics, "
        "and findings by severity. Requires a report to be loaded."
    ),
    properties={},
    required=[],
    fn=_get_detection_posture,
)

_register(
    name="list_detections",
    description=(
        "List security detections in the loaded report. "
        "Optionally filter by readiness status (runnable, partially_runnable, blocked, unknown), "
        "severity (critical, high, medium, low, informational), "
        "or a substring of the detection name."
    ),
    properties={
        "status": {
            "type": "string",
            "enum": ["runnable", "partially_runnable", "blocked", "unknown"],
            "description": "Filter by readiness status.",
        },
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "informational"],
            "description": "Filter by detection severity.",
        },
        "name_contains": {
            "type": "string",
            "description": "Return only detections whose name contains this substring.",
        },
        "limit": {
            "type": "integer",
            "description": "Maximum number of results to return (default 50).",
            "default": 50,
        },
    },
    required=[],
    fn=_list_detections,
)

_register(
    name="get_detection_detail",
    description=(
        "Return full detail for a single detection by name: readiness score, "
        "all dependencies and their status, all findings with remediation steps, "
        "and the detection query. Accepts an exact or partial name match."
    ),
    properties={
        "name": {
            "type": "string",
            "description": "Detection name (exact or partial match).",
        }
    },
    required=["name"],
    fn=_get_detection_detail,
)

_register(
    name="get_findings",
    description=(
        "Return analysis findings from the loaded report. "
        "Optionally filter by severity (critical/high/medium/low/info) "
        "and/or category (missing_dependency, runtime_health, data_flow_issue, etc.)."
    ),
    properties={
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"],
            "description": "Filter findings by severity level.",
        },
        "category": {
            "type": "string",
            "description": (
                "Filter by finding category: missing_dependency, unresolved_reference, "
                "configuration_issue, data_gap, optimization_opportunity, runtime_health, "
                "stale_execution, data_flow_issue, acceleration_issue."
            ),
        },
        "limit": {
            "type": "integer",
            "description": "Maximum number of findings to return (default 50).",
            "default": 50,
        },
    },
    required=[],
    fn=_get_findings,
)

_register(
    name="get_coverage_gaps",
    description=(
        "Return MITRE ATT&CK technique coverage from the report. "
        "Shows covered, partial, and uncovered techniques with tactic breakdown. "
        "Only available if the scan was run with the --coverage flag."
    ),
    properties={
        "uncovered_only": {
            "type": "boolean",
            "description": "If true, return only uncovered techniques.",
            "default": False,
        }
    },
    required=[],
    fn=_get_coverage_gaps,
)

_register(
    name="get_dependency_issues",
    description=(
        "Return detections that have missing or broken dependencies. "
        "Shows each affected detection, how many deps are missing, "
        "and which specific dependencies need attention."
    ),
    properties={
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "informational"],
            "description": "Filter to detections of a specific severity.",
        }
    },
    required=[],
    fn=_get_dependency_issues,
)

_register(
    name="get_runtime_health",
    description=(
        "Return runtime health summary for the detection environment. "
        "Shows saved search scheduling health, lookup table health, index data flow, "
        "and data model acceleration. Only available when the scan included --api-url."
    ),
    properties={},
    required=[],
    fn=_get_runtime_health,
)

_register(
    name="get_tuning_proposals",
    description=(
        "Return AI SOC detection tuning proposals: which detections are noisy, "
        "stale, or degraded, and what actions are recommended (disable, adjust threshold, "
        "update query, escalate severity). Computes proposals on demand if not yet cached."
    ),
    properties={
        "priority": {
            "type": "string",
            "enum": ["high", "medium", "low"],
            "description": "Filter proposals by priority level.",
        }
    },
    required=[],
    fn=_get_tuning_proposals,
)

_register(
    name="run_ai_soc_cycle",
    description=(
        "Run the full AI SOC automation cycle: build source catalog, assess data-aware "
        "feasibility, detect environment drift (if baseline available), run detection "
        "feedback analysis, and generate priority actions. Returns a consolidated "
        "summary with the top recommended actions for the SOC team."
    ),
    properties={
        "baseline_path": {
            "type": "string",
            "description": "Optional path to a baseline report for drift detection.",
        }
    },
    required=[],
    fn=_run_ai_soc_cycle,
)

_register(
    name="get_optimization_recommendations",
    description=(
        "Return ranked optimization recommendations showing which dependency fixes "
        "would yield the greatest readiness score improvement. Each recommendation "
        "includes the impact score and the number of detections it would unblock. "
        "Only available when the scan included --coverage."
    ),
    properties={
        "limit": {
            "type": "integer",
            "description": "Maximum number of recommendations to return (default 20).",
            "default": 20,
        }
    },
    required=[],
    fn=_get_optimization_recommendations,
)

_register(
    name="get_data_sources",
    description=(
        "Return the unified data source inventory: all data sources observed across "
        "platforms, their health status, and ATT&CK data source coverage mapping. "
        "Computes the source catalog on demand if not already cached."
    ),
    properties={},
    required=[],
    fn=_get_data_sources,
)

_register(
    name="compare_reports",
    description=(
        "Compare the current report against a baseline to detect environment drift: "
        "sources added/removed, health changes, and readiness score delta. "
        "Requires a baseline to be loaded via load_baseline or baseline_path param."
    ),
    properties={
        "baseline_path": {
            "type": "string",
            "description": "Optional path to the baseline report (alternative to load_baseline).",
        }
    },
    required=[],
    fn=_compare_reports,
)

_register(
    name="explain_detection",
    description=(
        "Return a plain-language explanation of a detection's current operational state: "
        "why it's blocked/partial/runnable, what the key issues are, and what to fix first. "
        "Useful for summarising detection health to a SOC analyst."
    ),
    properties={
        "name": {
            "type": "string",
            "description": "Detection name (exact or partial match).",
        }
    },
    required=["name"],
    fn=_explain_detection,
)


# ── Schema export ────────────────────────────────────────────────────────────


def get_tool_schemas(fmt: str = "anthropic") -> list[dict[str, Any]]:
    """Return all tool schemas in the requested format.

    Parameters
    ----------
    fmt:
        ``"anthropic"`` (default) or ``"openai"``.
    """
    if fmt == "openai":
        return [t.to_openai_schema() for t in TOOL_REGISTRY.values()]
    return [t.to_anthropic_schema() for t in TOOL_REGISTRY.values()]
