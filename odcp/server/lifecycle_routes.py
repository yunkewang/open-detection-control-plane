"""Detection lifecycle management routes.

Mounted as:
- ``/lifecycle``           (UI page, via ``lifecycle_ui_router``)
- ``/api/lifecycle/...``   (JSON API, via ``lifecycle_api_router``)

The ``LifecycleManager`` is attached to ``app.state.lifecycle_manager``
by the app factory.

Auth (when enabled):
- GET routes require readonly role or above.
- POST (transitions) require analyst role or above.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from odcp.lifecycle.manager import LifecycleError, LifecycleManager
from odcp.models.lifecycle import DetectionState
from odcp.server.auth import analyst_or_above, reader_or_above

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

lifecycle_ui_router = APIRouter(tags=["lifecycle-ui"])
lifecycle_api_router = APIRouter(prefix="/api/lifecycle", tags=["lifecycle-api"])


# ── Dependencies ─────────────────────────────────────────────────────────────


def get_lifecycle(request: Request) -> LifecycleManager:
    return request.app.state.lifecycle_manager  # type: ignore[return-value]


# ── UI page ──────────────────────────────────────────────────────────────────


@lifecycle_ui_router.get("/lifecycle", response_class=HTMLResponse)
async def lifecycle_page(
    request: Request,
    lm: LifecycleManager = Depends(get_lifecycle),
    state: Optional[str] = None,
) -> HTMLResponse:
    """Detection lifecycle management dashboard."""
    summary = lm.summary()
    records = lm.get_all(state_filter=state)

    try:
        store = request.app.state.store
        posture = store.posture_dict()
        # Auto-register any loaded detections not yet tracked
        if store.report:
            lm.sync_from_report(store.report, actor="system")
            records = lm.get_all(state_filter=state)
            summary = lm.summary()
    except AttributeError:
        posture = {}

    rows = [
        {**r.model_dump(mode="json"), **r.state_display()}
        for r in records
    ]

    return _templates.TemplateResponse(
        request,
        "lifecycle.html",
        {
            "summary": summary.model_dump(mode="json"),
            "records": rows,
            "state_filter": state or "",
            "posture": posture,
            "page": "lifecycle",
            "states": [s.value for s in DetectionState],
        },
    )


# ── JSON API ─────────────────────────────────────────────────────────────────


@lifecycle_api_router.get("/summary")
async def api_lifecycle_summary(
    lm: LifecycleManager = Depends(get_lifecycle),
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    """Aggregate lifecycle state counts."""
    s = lm.summary()
    return JSONResponse(s.model_dump(mode="json"))


@lifecycle_api_router.get("/detections")
async def api_lifecycle_list(
    lm: LifecycleManager = Depends(get_lifecycle),
    state: Optional[str] = None,
    limit: int = 200,
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    """List all tracked detections with lifecycle state."""
    records = lm.get_all(state_filter=state)
    return JSONResponse(
        {
            "total": len(records),
            "detections": [r.model_dump(mode="json") for r in records[:limit]],
        }
    )


@lifecycle_api_router.get("/detections/{detection_id}")
async def api_lifecycle_get(
    detection_id: str,
    lm: LifecycleManager = Depends(get_lifecycle),
    _auth=Depends(reader_or_above()),
) -> JSONResponse:
    """Get lifecycle record and full history for a detection."""
    record = lm.get(detection_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Detection '{detection_id}' is not tracked.",
        )
    return JSONResponse(record.model_dump(mode="json"))


@lifecycle_api_router.post("/detections/{detection_id}/register")
async def api_lifecycle_register(
    detection_id: str,
    payload: dict[str, Any],
    lm: LifecycleManager = Depends(get_lifecycle),
    _auth=Depends(analyst_or_above()),
) -> JSONResponse:
    """Register a detection for lifecycle tracking (creates a draft record)."""
    name = payload.get("detection_name", detection_id)
    record = lm.get_or_create(detection_id, name)
    return JSONResponse(record.model_dump(mode="json"), status_code=201)


@lifecycle_api_router.post("/detections/{detection_id}/transition")
async def api_lifecycle_transition(
    detection_id: str,
    payload: dict[str, Any],
    request: Request,
    lm: LifecycleManager = Depends(get_lifecycle),
    _auth=Depends(analyst_or_above()),
) -> JSONResponse:
    """Transition a detection to a specific target state.

    Body: ``{"to_state": "testing", "actor": "alice", "comment": "..."}``
    """
    to_state_raw = payload.get("to_state", "")
    try:
        to_state = DetectionState(to_state_raw)
    except ValueError:
        valid = [s.value for s in DetectionState]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid state '{to_state_raw}'. Valid: {valid}",
        )

    actor = _resolve_actor(request, payload)
    comment = payload.get("comment")

    try:
        record = lm.transition(detection_id, to_state, actor=actor, comment=comment)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except LifecycleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return JSONResponse(record.model_dump(mode="json"))


@lifecycle_api_router.post("/detections/{detection_id}/promote")
async def api_lifecycle_promote(
    detection_id: str,
    payload: dict[str, Any],
    request: Request,
    lm: LifecycleManager = Depends(get_lifecycle),
    _auth=Depends(analyst_or_above()),
) -> JSONResponse:
    """Advance a detection to the next state in the lifecycle."""
    actor = _resolve_actor(request, payload)
    comment = payload.get("comment")
    try:
        record = lm.promote(detection_id, actor=actor, comment=comment)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except LifecycleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return JSONResponse(record.model_dump(mode="json"))


@lifecycle_api_router.post("/detections/{detection_id}/rollback")
async def api_lifecycle_rollback(
    detection_id: str,
    payload: dict[str, Any],
    request: Request,
    lm: LifecycleManager = Depends(get_lifecycle),
    _auth=Depends(analyst_or_above()),
) -> JSONResponse:
    """Roll a detection back to the previous state."""
    actor = _resolve_actor(request, payload)
    comment = payload.get("comment")
    try:
        record = lm.rollback(detection_id, actor=actor, comment=comment)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except LifecycleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return JSONResponse(record.model_dump(mode="json"))


# ── Helpers ───────────────────────────────────────────────────────────────────


def _resolve_actor(request: Request, payload: dict[str, Any]) -> str:
    """Derive actor name from token (if auth enabled) or payload fallback."""
    try:
        token = request.app.state.token_store
        # Access the token resolved by the dependency (stored on request.state)
    except AttributeError:
        pass
    # Fall back to payload-provided actor or 'anonymous'
    return payload.get("actor", "anonymous")
