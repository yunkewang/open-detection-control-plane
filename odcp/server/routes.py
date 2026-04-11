"""Web server routes — UI pages, JSON API, and SSE endpoint.

All routes receive the ``ReportStore`` via FastAPI dependency injection.
The store is attached to ``app.state.store`` by the app factory.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from odcp.server.state import ReportStore

logger = logging.getLogger(__name__)

# Templates directory lives next to this file
_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

ui_router = APIRouter(tags=["ui"])
api_router = APIRouter(prefix="/api", tags=["api"])


# ── Dependency ─────────────────────────────────────────────────────────────


def get_store(request: Request) -> ReportStore:
    return request.app.state.store  # type: ignore[return-value]


# ── UI pages ───────────────────────────────────────────────────────────────


@ui_router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request, store: ReportStore = Depends(get_store)
) -> HTMLResponse:
    posture = store.posture_dict()
    priority_actions: list[str] = []

    if store.report:
        try:
            from odcp.analyzers.ai_soc.orchestrator import AiSocOrchestrator
            result = AiSocOrchestrator().run_cycle(store.report)
            priority_actions = result.priority_actions[:6]
        except Exception:
            pass

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"posture": posture, "priority_actions": priority_actions, "page": "dashboard"},
    )


@ui_router.get("/detections", response_class=HTMLResponse)
async def detections_page(
    request: Request,
    store: ReportStore = Depends(get_store),
    status: Optional[str] = None,
    severity: Optional[str] = None,
) -> HTMLResponse:
    detections = _build_detections(store, status_filter=status, severity_filter=severity)
    return templates.TemplateResponse(
        request,
        "detections.html",
        {
            "detections": detections,
            "status_filter": status or "",
            "severity_filter": severity or "",
            "posture": store.posture_dict(),
            "page": "detections",
        },
    )


@ui_router.get("/coverage", response_class=HTMLResponse)
async def coverage_page(
    request: Request, store: ReportStore = Depends(get_store)
) -> HTMLResponse:
    coverage = _build_coverage(store)
    return templates.TemplateResponse(
        request,
        "coverage.html",
        {"coverage": coverage, "posture": store.posture_dict(), "page": "coverage"},
    )


@ui_router.get("/findings", response_class=HTMLResponse)
async def findings_page(
    request: Request,
    store: ReportStore = Depends(get_store),
    severity: Optional[str] = None,
    category: Optional[str] = None,
) -> HTMLResponse:
    findings = _build_findings(store, severity_filter=severity, category_filter=category)
    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "findings": findings,
            "severity_filter": severity or "",
            "category_filter": category or "",
            "posture": store.posture_dict(),
            "page": "findings",
        },
    )


@ui_router.get("/sources", response_class=HTMLResponse)
async def sources_page(
    request: Request, store: ReportStore = Depends(get_store)
) -> HTMLResponse:
    sources = _build_sources(store)
    return templates.TemplateResponse(
        request,
        "sources.html",
        {"sources": sources, "posture": store.posture_dict(), "page": "sources"},
    )


@ui_router.get("/agent", response_class=HTMLResponse)
async def agent_page(
    request: Request, store: ReportStore = Depends(get_store)
) -> HTMLResponse:
    from odcp.agent.tools import TOOL_REGISTRY
    tool_list = [{"name": t.name, "description": t.description[:80]} for t in TOOL_REGISTRY.values()]
    return templates.TemplateResponse(
        request,
        "agent.html",
        {
            "tool_list": tool_list,
            "posture": store.posture_dict(),
            "page": "agent",
            "report_path": str(store.report_path) if store.report_path else "",
        },
    )


# ── JSON API ───────────────────────────────────────────────────────────────


@api_router.get("/posture")
async def api_posture(store: ReportStore = Depends(get_store)) -> JSONResponse:
    if not store.loaded:
        raise HTTPException(status_code=404, detail="No report loaded")
    return JSONResponse(store.posture_dict())


@api_router.get("/detections")
async def api_detections(
    store: ReportStore = Depends(get_store),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 200,
) -> JSONResponse:
    if not store.loaded:
        raise HTTPException(status_code=404, detail="No report loaded")
    dets = _build_detections(store, status_filter=status, severity_filter=severity)
    return JSONResponse({"total": len(dets), "detections": dets[:limit]})


@api_router.get("/findings")
async def api_findings(
    store: ReportStore = Depends(get_store),
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 200,
) -> JSONResponse:
    if not store.loaded:
        raise HTTPException(status_code=404, detail="No report loaded")
    findings = _build_findings(store, severity_filter=severity, category_filter=category)
    return JSONResponse({"total": len(findings), "findings": findings[:limit]})


@api_router.get("/coverage")
async def api_coverage(store: ReportStore = Depends(get_store)) -> JSONResponse:
    if not store.loaded:
        raise HTTPException(status_code=404, detail="No report loaded")
    return JSONResponse(_build_coverage(store))


@api_router.get("/sources")
async def api_sources(store: ReportStore = Depends(get_store)) -> JSONResponse:
    if not store.loaded:
        raise HTTPException(status_code=404, detail="No report loaded")
    return JSONResponse(_build_sources(store))


@api_router.post("/report/load")
async def api_load_report(
    payload: dict[str, Any],
    store: ReportStore = Depends(get_store),
) -> JSONResponse:
    path = payload.get("path", "")
    if not path:
        raise HTTPException(status_code=400, detail="'path' required")
    try:
        await store.load_from_path(path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to load report: {exc}") from exc
    return JSONResponse(store.posture_dict())


@api_router.post("/agent/query")
async def api_agent_query(
    payload: dict[str, Any],
    store: ReportStore = Depends(get_store),
) -> JSONResponse:
    """Run a one-shot agent query (requires anthropic installed)."""
    prompt = payload.get("prompt", "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="'prompt' required")
    model = payload.get("model", "claude-opus-4-6")

    try:
        from odcp.agent import AgentSession, ToolExecutor
        from odcp.agent.orchestrator import run_agent

        # Pre-seed the agent session with the already-loaded report
        session = AgentSession()
        session.report = store.report

        # Run agent — report is already in session, no path needed
        answer = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: run_agent(prompt, model=model),
        )
        return JSONResponse({"answer": answer})
    except SystemExit:
        raise HTTPException(
            status_code=503,
            detail="Anthropic SDK not installed. Run: pip install 'odcp[agent]'",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@api_router.get("/agent/tools")
async def api_agent_tools() -> JSONResponse:
    from odcp.agent.tools import get_tool_schemas
    return JSONResponse(get_tool_schemas("anthropic"))


# ── SSE endpoint ───────────────────────────────────────────────────────────


@api_router.get("/events")
async def sse_events(
    request: Request, store: ReportStore = Depends(get_store)
) -> StreamingResponse:
    """Server-Sent Events stream.

    Clients receive a ``report_updated`` event whenever the report file
    changes on disk, plus a keepalive ``ping`` every 15 s.
    """

    async def event_stream() -> AsyncGenerator[str, None]:
        q = store.subscribe()
        try:
            # Send initial state immediately
            initial = json.dumps({"event": "connected", "loaded": store.loaded})
            yield f"data: {initial}\n\n"

            while True:
                # Wait for next event with a keepalive timeout
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield "data: {\"event\": \"ping\"}\n\n"
                except asyncio.CancelledError:
                    break
        finally:
            store.unsubscribe(q)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Data builders ──────────────────────────────────────────────────────────


def _sev_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


def _build_detections(
    store: ReportStore,
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
) -> list[dict]:
    if not store.report:
        return []
    report = store.report
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
        results.append(
            {
                "id": det.id,
                "name": det.name,
                "description": (det.description or "")[:120],
                "severity": sev,
                "status": status,
                "score": round((score.score if score else 0) * 100),
                "missing_deps": score.missing_dependencies if score else 0,
                "enabled": det.enabled,
                "tags": det.tags[:4],
            }
        )
    results.sort(key=lambda r: (_sev_order(r["status"].replace("partially_runnable", "medium")), _sev_order(r["severity"])))
    return results


def _build_findings(
    store: ReportStore,
    severity_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
) -> list[dict]:
    if not store.report:
        return []
    report = store.report
    det_map = {d.id: d.name for d in report.detections}
    findings = report.findings
    if severity_filter:
        findings = [f for f in findings if f.severity.value == severity_filter]
    if category_filter:
        findings = [f for f in findings if f.category.value == category_filter]
    findings = sorted(findings, key=lambda f: _sev_order(f.severity.value))
    return [
        {
            "id": f.id,
            "detection": det_map.get(f.detection_id, f.detection_id),
            "category": f.category.value,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description[:300],
            "remediation": f.remediation.title if f.remediation else None,
            "remediation_steps": f.remediation.steps[:3] if f.remediation else [],
        }
        for f in findings
    ]


def _build_coverage(store: ReportStore) -> dict:
    if not store.report:
        return {"available": False}
    meta = store.report.metadata.get("coverage_summary", {})
    if not meta:
        return {"available": False, "message": "Re-scan with --coverage flag."}
    return {
        "available": True,
        "coverage_score": round(meta.get("coverage_score", 0) * 100),
        "covered": meta.get("covered_techniques", 0),
        "partial": meta.get("partial_techniques", 0),
        "uncovered": meta.get("uncovered_techniques", 0),
        "tactic_breakdown": meta.get("tactic_breakdown", {}),
        "techniques": meta.get("techniques", [])[:60],
    }


def _build_sources(store: ReportStore) -> dict:
    if not store.report:
        return {"available": False}
    try:
        from odcp.analyzers.ai_soc.source_inventory import SourceInventoryBuilder
        catalog = SourceInventoryBuilder().build_from_single(store.report)
        return {
            "available": True,
            "total": catalog.total_sources,
            "platforms": catalog.platforms_represented,
            "healthy": catalog.healthy_sources,
            "degraded": catalog.degraded_sources,
            "unavailable": catalog.unavailable_sources,
            "sources": [
                {
                    "name": s.name,
                    "platform": s.platform,
                    "kind": s.source_kind,
                    "health": s.health.value if s.health else "unknown",
                    "detection_count": s.detection_count,
                    "field_count": len(s.fields),
                }
                for s in sorted(catalog.sources, key=lambda x: x.detection_count, reverse=True)[:50]
            ],
        }
    except Exception as exc:
        return {"available": False, "message": str(exc)}
