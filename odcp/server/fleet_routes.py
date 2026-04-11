"""Fleet management routes — collector agent registration, reporting, and monitoring.

These routes are mounted on the FastAPI app under ``/api/fleet`` and
``/fleet`` (UI page).  The ``AgentRegistry`` instance is attached to
``app.state.agent_registry`` by the app factory.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from odcp.collector.registry import AgentRegistry
from odcp.models.collector import (
    AgentHeartbeat,
    AgentRegistration,
)
from odcp.models.report import ScanReport

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

fleet_ui_router = APIRouter(tags=["fleet-ui"])
fleet_api_router = APIRouter(prefix="/api/fleet", tags=["fleet-api"])


# ── Dependency ─────────────────────────────────────────────────────────────


def get_registry(request: Request) -> AgentRegistry:
    return request.app.state.agent_registry  # type: ignore[return-value]


# ── UI page ────────────────────────────────────────────────────────────────


@fleet_ui_router.get("/fleet", response_class=HTMLResponse)
async def fleet_page(
    request: Request,
    registry: AgentRegistry = Depends(get_registry),
) -> HTMLResponse:
    """Fleet management dashboard page."""
    summary = registry.fleet_summary()

    # Pull report store for posture context (may not be loaded)
    try:
        store = request.app.state.store
        posture = store.posture_dict()
    except AttributeError:
        posture = {}

    agents = registry.all_agents()
    return _templates.TemplateResponse(
        request,
        "fleet.html",
        {
            "summary": summary.model_dump(mode="json"),
            "agents": [a.model_dump(mode="json") for a in agents],
            "posture": posture,
            "page": "fleet",
        },
    )


# ── Fleet JSON API ─────────────────────────────────────────────────────────


@fleet_api_router.get("/health")
async def fleet_health() -> JSONResponse:
    """Health check endpoint for the fleet API."""
    return JSONResponse({"status": "ok", "service": "odcp-fleet"})


@fleet_api_router.post("/agents/register", status_code=201)
async def register_agent(
    registration: AgentRegistration,
    registry: AgentRegistry = Depends(get_registry),
) -> JSONResponse:
    """Register a new collector agent (or re-register an existing one)."""
    info = registry.register(registration)
    logger.info("Agent registered via API: %s", registration.config.agent_id)
    return JSONResponse(info.model_dump(mode="json"), status_code=201)


@fleet_api_router.post("/agents/{agent_id}/report", status_code=202)
async def receive_report(
    agent_id: str,
    report: ScanReport,
    registry: AgentRegistry = Depends(get_registry),
) -> JSONResponse:
    """Accept a full scan report from a collector agent."""
    ok = registry.receive_report(agent_id, report)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail=f"Agent '{agent_id}' not found. Register first.",
        )
    return JSONResponse({"accepted": True, "agent_id": agent_id}, status_code=202)


@fleet_api_router.post("/agents/{agent_id}/heartbeat", status_code=202)
async def receive_heartbeat(
    agent_id: str,
    heartbeat: AgentHeartbeat,
    registry: AgentRegistry = Depends(get_registry),
) -> JSONResponse:
    """Accept a liveness heartbeat from a collector agent."""
    ok = registry.receive_heartbeat(agent_id, heartbeat)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail=f"Agent '{agent_id}' not found. Register first.",
        )
    return JSONResponse({"accepted": True, "agent_id": agent_id}, status_code=202)


@fleet_api_router.delete("/agents/{agent_id}", status_code=200)
async def deregister_agent(
    agent_id: str,
    registry: AgentRegistry = Depends(get_registry),
) -> JSONResponse:
    """Deregister a collector agent (called on clean agent shutdown)."""
    ok = registry.deregister(agent_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return JSONResponse({"deregistered": True, "agent_id": agent_id})


@fleet_api_router.get("/agents")
async def list_agents(
    registry: AgentRegistry = Depends(get_registry),
    status: Optional[str] = None,
    environment: Optional[str] = None,
    platform: Optional[str] = None,
) -> JSONResponse:
    """List all registered agents with optional filters."""
    agents = registry.all_agents()

    if status:
        agents = [a for a in agents if a.status.value == status]
    if environment:
        agents = [a for a in agents if environment.lower() in a.environment_name.lower()]
    if platform:
        agents = [a for a in agents if a.platform.lower() == platform.lower()]

    return JSONResponse(
        {
            "total": len(agents),
            "agents": [a.model_dump(mode="json") for a in agents],
        }
    )


@fleet_api_router.get("/agents/{agent_id}")
async def get_agent(
    agent_id: str,
    registry: AgentRegistry = Depends(get_registry),
) -> JSONResponse:
    """Get info for a specific agent."""
    info = registry.get_agent(agent_id)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return JSONResponse(info.model_dump(mode="json"))


@fleet_api_router.get("/agents/{agent_id}/report")
async def get_agent_report(
    agent_id: str,
    registry: AgentRegistry = Depends(get_registry),
) -> JSONResponse:
    """Retrieve the latest scan report from a specific agent."""
    report = registry.get_report(agent_id)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail=f"No report for agent '{agent_id}'.",
        )
    return JSONResponse(report.model_dump(mode="json"))


@fleet_api_router.get("/summary")
async def fleet_summary(
    registry: AgentRegistry = Depends(get_registry),
) -> JSONResponse:
    """Return a summary of the entire collector fleet."""
    summary = registry.fleet_summary()
    return JSONResponse(summary.model_dump(mode="json"))
