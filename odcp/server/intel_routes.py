"""Threat intelligence API routes.

Mounted as:
- ``/intel``              (UI page, via ``intel_ui_router``)
- ``/api/intel/...``      (JSON API, via ``intel_api_router``)

The ``IntelManager`` is attached to ``app.state.intel_manager``.

Auth (when enabled):
- GET routes require readonly role or above.
- POST/DELETE require analyst role or above.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from odcp.intel.manager import IntelManager
from odcp.models.intel import (
    IntelFeed,
    IocEntry,
    IocType,
    ThreatActor,
    ThreatCampaign,
)
from odcp.server.auth import analyst_or_above, reader_or_above

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

intel_ui_router = APIRouter(tags=["intel-ui"])
intel_api_router = APIRouter(prefix="/api/intel", tags=["intel-api"])


# ── Dependencies ─────────────────────────────────────────────────────────────


def get_intel(request: Request) -> IntelManager:
    return request.app.state.intel_manager  # type: ignore[return-value]


# ── UI page ──────────────────────────────────────────────────────────────────


@intel_ui_router.get("/intel", response_class=HTMLResponse)
async def intel_page(
    request: Request,
    intel: IntelManager = Depends(get_intel),
) -> HTMLResponse:
    summary = intel.summary()
    campaigns = intel.get_campaigns(active_only=False)
    iocs = intel.get_iocs()[:50]
    actors = intel.get_actors()
    feeds = intel.get_feeds()

    gap_report = None
    try:
        store = request.app.state.store
        posture = store.posture_dict()
        if store.report:
            gap_report = intel.analyze_coverage(store.report)
    except AttributeError:
        posture = {}

    return _templates.TemplateResponse(
        request,
        "intel.html",
        {
            "summary": summary.model_dump(mode="json"),
            "campaigns": [c.model_dump(mode="json") for c in campaigns],
            "iocs": [i.model_dump(mode="json") for i in iocs],
            "actors": [a.model_dump(mode="json") for a in actors],
            "feeds": [f.model_dump(mode="json") for f in feeds],
            "gap_report": gap_report.model_dump(mode="json") if gap_report else None,
            "posture": posture,
            "page": "intel",
        },
    )


# ── Summary ───────────────────────────────────────────────────────────────────


@intel_api_router.get("/summary")
async def api_intel_summary(
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    return JSONResponse(intel.summary().model_dump(mode="json"))


# ── Campaigns ─────────────────────────────────────────────────────────────────


@intel_api_router.get("/campaigns")
async def api_list_campaigns(
    intel: IntelManager = Depends(get_intel),
    active_only: bool = False,
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    campaigns = intel.get_campaigns(active_only=active_only)
    return JSONResponse({
        "total": len(campaigns),
        "campaigns": [c.model_dump(mode="json") for c in campaigns],
    })


@intel_api_router.post("/campaigns", status_code=201)
async def api_add_campaign(
    payload: dict[str, Any],
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(analyst_or_above()),
) -> JSONResponse:
    try:
        campaign = ThreatCampaign.model_validate(payload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid campaign data: {exc}") from exc
    intel.add_campaign(campaign)
    return JSONResponse(campaign.model_dump(mode="json"), status_code=201)


@intel_api_router.get("/campaigns/{campaign_id}")
async def api_get_campaign(
    campaign_id: str,
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    c = intel.get_campaign(campaign_id)
    if c is None:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")
    return JSONResponse(c.model_dump(mode="json"))


@intel_api_router.delete("/campaigns/{campaign_id}", status_code=200)
async def api_remove_campaign(
    campaign_id: str,
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(analyst_or_above()),
) -> JSONResponse:
    ok = intel.remove_campaign(campaign_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")
    return JSONResponse({"removed": True, "campaign_id": campaign_id})


# ── IOCs ──────────────────────────────────────────────────────────────────────


@intel_api_router.get("/iocs")
async def api_list_iocs(
    intel: IntelManager = Depends(get_intel),
    ioc_type: Optional[str] = None,
    limit: int = 200,
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    iocs = intel.get_iocs(ioc_type=ioc_type)
    return JSONResponse({
        "total": len(iocs),
        "iocs": [i.model_dump(mode="json") for i in iocs[:limit]],
    })


@intel_api_router.post("/iocs", status_code=201)
async def api_add_ioc(
    payload: dict[str, Any],
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(analyst_or_above()),
) -> JSONResponse:
    try:
        ioc = IocEntry.model_validate(payload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid IOC data: {exc}") from exc
    intel.add_ioc(ioc)
    return JSONResponse(ioc.model_dump(mode="json"), status_code=201)


@intel_api_router.post("/iocs/bulk", status_code=201)
async def api_add_iocs_bulk(
    payload: dict[str, Any],
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(analyst_or_above()),
) -> JSONResponse:
    """Bulk-add IOCs. Body: ``{"iocs": [...]}``"""
    raw_iocs = payload.get("iocs", [])
    if not isinstance(raw_iocs, list):
        raise HTTPException(status_code=400, detail="'iocs' must be a list.")
    iocs: list[IocEntry] = []
    errors: list[str] = []
    for i, entry in enumerate(raw_iocs):
        try:
            iocs.append(IocEntry.model_validate(entry))
        except Exception as exc:
            errors.append(f"iocs[{i}]: {exc}")
    if errors and not iocs:
        raise HTTPException(status_code=400, detail="; ".join(errors[:5]))
    count = intel.add_iocs_bulk(iocs)
    return JSONResponse({"added": count, "errors": len(errors)}, status_code=201)


# ── Actors ────────────────────────────────────────────────────────────────────


@intel_api_router.get("/actors")
async def api_list_actors(
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    actors = intel.get_actors()
    return JSONResponse({
        "total": len(actors),
        "actors": [a.model_dump(mode="json") for a in actors],
    })


@intel_api_router.post("/actors", status_code=201)
async def api_add_actor(
    payload: dict[str, Any],
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(analyst_or_above()),
) -> JSONResponse:
    try:
        actor = ThreatActor.model_validate(payload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid actor data: {exc}") from exc
    intel.add_actor(actor)
    return JSONResponse(actor.model_dump(mode="json"), status_code=201)


# ── Feeds ─────────────────────────────────────────────────────────────────────


@intel_api_router.get("/feeds")
async def api_list_feeds(
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    feeds = intel.get_feeds()
    return JSONResponse({
        "total": len(feeds),
        "feeds": [f.model_dump(mode="json") for f in feeds],
    })


@intel_api_router.post("/feeds", status_code=201)
async def api_add_feed(
    payload: dict[str, Any],
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(analyst_or_above()),
) -> JSONResponse:
    try:
        feed = IntelFeed.model_validate(payload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid feed data: {exc}") from exc
    intel.add_feed(feed)
    return JSONResponse(feed.model_dump(mode="json"), status_code=201)


# ── Gap analysis ──────────────────────────────────────────────────────────────


@intel_api_router.get("/gap-analysis")
async def api_gap_analysis(
    request: Request,
    intel: IntelManager = Depends(get_intel),
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    """Threat-weighted coverage gap analysis against the loaded report."""
    try:
        store = request.app.state.store
    except AttributeError:
        raise HTTPException(status_code=503, detail="Report store unavailable.")
    if not store.loaded or not store.report:
        raise HTTPException(status_code=404, detail="No report loaded.")
    report = intel.analyze_coverage(store.report)
    return JSONResponse(report.model_dump(mode="json"))
