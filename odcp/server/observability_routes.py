"""Observability routes — Prometheus metrics, health checks, SLA, and compliance.

Mounted under the main FastAPI app:
- ``GET /health/live``          — liveness probe (always 200)
- ``GET /health/ready``         — readiness probe (200 if report loaded)
- ``GET /metrics``              — Prometheus text format
- ``GET /api/sla/status``       — SLA compliance for lifecycle detections
- ``GET /api/compliance/report`` — compliance evidence report (soc2 / nist_csf)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from odcp.server.auth import analyst_or_above, reader_or_above

logger = logging.getLogger(__name__)

health_router = APIRouter(tags=["health"])
observability_api_router = APIRouter(prefix="/api", tags=["observability"])


# ── Health probes ─────────────────────────────────────────────────────────────


@health_router.get("/health/live")
async def liveness() -> JSONResponse:
    """Kubernetes liveness probe — always returns 200."""
    return JSONResponse({"status": "ok"})


@health_router.get("/health/ready")
async def readiness(request: Request) -> JSONResponse:
    """Kubernetes readiness probe — 200 if report is loaded, 503 otherwise."""
    try:
        store = request.app.state.store
        if store.loaded:
            return JSONResponse({"status": "ready", "report_loaded": True})
        return JSONResponse(
            {"status": "not_ready", "report_loaded": False},
            status_code=503,
        )
    except AttributeError:
        return JSONResponse({"status": "not_ready", "report_loaded": False}, status_code=503)


# ── Prometheus metrics ────────────────────────────────────────────────────────


@health_router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics(request: Request) -> PlainTextResponse:
    """Expose Prometheus-format gauge metrics for ODCP state."""
    lines: list[str] = []

    def gauge(name: str, value: float, help_text: str, labels: str = "") -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        label_str = f"{{{labels}}}" if labels else ""
        lines.append(f"{name}{label_str} {value}")

    # Report / detection metrics
    try:
        store = request.app.state.store
        if store.loaded and store.report:
            rpt = store.report
            posture = store.posture_dict()
            gauge("odcp_report_loaded", 1, "1 if a scan report is loaded")
            gauge("odcp_detections_total", len(rpt.detections), "Total detections in the loaded report")
            gauge("odcp_readiness_score", posture.get("readiness_score", 0),
                  "Overall detection readiness score (0-1)")
            gauge("odcp_detections_runnable", posture.get("runnable", 0),
                  "Detections in runnable state")
            gauge("odcp_detections_blocked", posture.get("blocked", 0),
                  "Detections in blocked state")
            gauge("odcp_detections_partial", posture.get("partially_runnable", 0),
                  "Detections in partially_runnable state")
            gauge("odcp_findings_total", posture.get("total_findings", 0),
                  "Total findings in report")
            gauge("odcp_findings_critical", posture.get("critical_count", 0),
                  "Critical severity findings")
            gauge("odcp_findings_high", posture.get("high_count", 0),
                  "High severity findings")
        else:
            gauge("odcp_report_loaded", 0, "1 if a scan report is loaded")
    except Exception:
        gauge("odcp_report_loaded", 0, "1 if a scan report is loaded")

    # Fleet metrics
    try:
        registry = request.app.state.agent_registry
        summary = registry.fleet_summary()
        gauge("odcp_agents_total", summary.total_agents, "Total registered collector agents")
        gauge("odcp_agents_active", summary.active_agents, "Active collector agents")
        gauge("odcp_agents_degraded", summary.degraded_agents, "Degraded collector agents")
        gauge("odcp_agents_offline", summary.offline_agents, "Offline collector agents")
    except Exception:
        pass

    # Lifecycle metrics
    try:
        lm = request.app.state.lifecycle_manager
        lm_summary = lm.summary()
        gauge("odcp_lifecycle_total", lm_summary.total, "Total lifecycle-tracked detections")
        for state, count in lm_summary.by_state.items():
            gauge("odcp_lifecycle_by_state", count,
                  f"Detections in lifecycle state", f'state="{state}"')
    except Exception:
        pass

    # Audit metrics
    try:
        audit = request.app.state.audit_logger
        gauge("odcp_audit_events_total", audit.total(), "Total audit events in memory")
    except Exception:
        pass

    # Intel metrics
    try:
        intel = request.app.state.intel_manager
        intel_summary = intel.summary()
        gauge("odcp_intel_campaigns_total", intel_summary.total_campaigns,
              "Total threat campaigns tracked")
        gauge("odcp_intel_campaigns_active", intel_summary.active_campaigns,
              "Active threat campaigns")
        gauge("odcp_intel_iocs_total", intel_summary.total_iocs, "Total IOCs tracked")
    except Exception:
        pass

    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


# ── SLA status ────────────────────────────────────────────────────────────────


@observability_api_router.get("/sla/status")
async def api_sla_status(
    request: Request,
    max_days_draft: int = Query(default=30, description="Max days allowed in draft"),
    max_days_review: int = Query(default=14, description="Max days allowed in review"),
    max_days_testing: int = Query(default=21, description="Max days allowed in testing"),
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    """Evaluate SLA compliance for all lifecycle-tracked detections."""
    try:
        lm = request.app.state.lifecycle_manager
    except AttributeError:
        raise HTTPException(status_code=503, detail="Lifecycle manager unavailable.")

    from odcp.sla.tracker import SlaPolicy, SlaTracker
    policy = SlaPolicy(
        max_days_in_draft=max_days_draft,
        max_days_in_review=max_days_review,
        max_days_in_testing=max_days_testing,
    )
    tracker = SlaTracker(policy)
    records = lm.get_all()
    summary = tracker.evaluate(records)
    return JSONResponse(summary.model_dump(mode="json"))


# ── Compliance report ─────────────────────────────────────────────────────────


@observability_api_router.get("/compliance/report", response_model=None)
async def api_compliance_report(
    request: Request,
    framework: str = Query(default="soc2", description="Framework: soc2 or nist_csf"),
    period: str = Query(default="", description="Period label e.g. 2025-Q1"),
    fmt: str = Query(default="json", description="Output format: json or markdown"),
    _auth=Depends(analyst_or_above()),
):
    """Generate a compliance evidence report."""
    from odcp.compliance.report_builder import ComplianceReportBuilder

    builder = ComplianceReportBuilder()
    try:
        store = getattr(request.app.state, "store", None)
        lm = getattr(request.app.state, "lifecycle_manager", None)
        audit = getattr(request.app.state, "audit_logger", None)
        intel = getattr(request.app.state, "intel_manager", None)
        registry = getattr(request.app.state, "agent_registry", None)

        report = builder.build(
            framework=framework,
            store=store,
            lifecycle_manager=lm,
            audit_logger=audit,
            intel_manager=intel,
            registry=registry,
            period_label=period,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if fmt == "markdown":
        return PlainTextResponse(report.as_markdown(), media_type="text/markdown")
    return JSONResponse(report.model_dump(mode="json"))
