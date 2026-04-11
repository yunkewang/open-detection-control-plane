"""Token management and audit log API routes.

All routes under ``/api/auth/`` require authentication when auth is
enabled.  Token creation and revocation are admin-only.
``GET /api/auth/me`` is accessible to any authenticated user.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from odcp.models.auth import AuditEvent, TokenCreateRequest, TokenPublic, UserRole
from odcp.server.auth import TokenStore, get_current_token, require_role
from odcp.server.audit import AuditLogger

logger = logging.getLogger(__name__)

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


# ── Dependency helpers ─────────────────────────────────────────────────────


def get_token_store(request: Request) -> TokenStore:
    return request.app.state.token_store


def get_audit_logger(request: Request) -> AuditLogger:
    return request.app.state.audit_logger


# ── Token management ───────────────────────────────────────────────────────


@auth_router.post("/tokens", status_code=201)
async def create_token(
    body: TokenCreateRequest,
    request: Request,
    token_store: TokenStore = Depends(get_token_store),
    audit: AuditLogger = Depends(get_audit_logger),
    _auth=Depends(require_role(UserRole.admin)),
) -> JSONResponse:
    """Create a new API token (admin only).

    The plain token is returned once in the response body and is never
    stored on the server.  Save it immediately.
    """
    current = await get_current_token(request)
    plain, record = token_store.create(
        name=body.name, role=body.role, agent_id=body.agent_id
    )
    audit.log_from_request(
        request, "token.create", f"token:{record.token_id}",
        token=current,
        detail={"name": body.name, "role": body.role.value},
    )
    return JSONResponse(
        {
            "token": plain,
            "token_id": record.token_id,
            "name": record.name,
            "role": record.role.value,
            "agent_id": record.agent_id,
            "created_at": record.created_at.isoformat(),
            "warning": "Save this token — it will not be shown again.",
        },
        status_code=201,
    )


@auth_router.get("/tokens")
async def list_tokens(
    token_store: TokenStore = Depends(get_token_store),
    _auth=Depends(require_role(UserRole.admin)),
) -> JSONResponse:
    """List all tokens (admin only). Plain tokens are never returned."""
    records = token_store.list_all()
    return JSONResponse(
        {
            "total": len(records),
            "tokens": [
                TokenPublic(
                    token_id=r.token_id,
                    name=r.name,
                    role=r.role,
                    created_at=r.created_at,
                    last_used_at=r.last_used_at,
                    agent_id=r.agent_id,
                ).model_dump(mode="json")
                for r in records
            ],
        }
    )


@auth_router.delete("/tokens/{token_id}")
async def revoke_token(
    token_id: str,
    request: Request,
    token_store: TokenStore = Depends(get_token_store),
    audit: AuditLogger = Depends(get_audit_logger),
    _auth=Depends(require_role(UserRole.admin)),
) -> JSONResponse:
    """Revoke a token by ID (admin only)."""
    current = await get_current_token(request)
    if current and current.token_id == token_id:
        raise HTTPException(
            status_code=400, detail="Cannot revoke your own token."
        )
    ok = token_store.revoke(token_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Token '{token_id}' not found.")
    audit.log_from_request(
        request, "token.revoke", f"token:{token_id}", token=current,
    )
    return JSONResponse({"revoked": True, "token_id": token_id})


@auth_router.get("/me")
async def whoami(
    token=Depends(get_current_token),
) -> JSONResponse:
    """Return information about the currently authenticated token."""
    if token is None:
        return JSONResponse(
            {"auth_enabled": False, "message": "Authentication is disabled on this server."}
        )
    return JSONResponse(
        {
            "auth_enabled": True,
            "token_id": token.token_id,
            "name": token.name,
            "role": token.role.value,
            "agent_id": token.agent_id,
            "created_at": token.created_at.isoformat(),
            "last_used_at": token.last_used_at.isoformat() if token.last_used_at else None,
        }
    )


# ── Audit log ──────────────────────────────────────────────────────────────


@auth_router.get("/audit")
async def get_audit_log(
    audit: AuditLogger = Depends(get_audit_logger),
    limit: int = Query(default=100, ge=1, le=1000),
    action: Optional[str] = Query(default=None, description="Filter by action substring"),
    actor: Optional[str] = Query(default=None, description="Filter by actor name"),
    status: Optional[str] = Query(default=None, description="Filter by status (success|denied)"),
    _auth=Depends(require_role(UserRole.admin, UserRole.analyst)),
) -> JSONResponse:
    """Return recent audit events (admin or analyst)."""
    events = audit.recent(
        limit=limit,
        action_filter=action,
        actor_filter=actor,
        status_filter=status,
    )
    return JSONResponse(
        {
            "total_in_memory": audit.total(),
            "returned": len(events),
            "events": [e.model_dump(mode="json") for e in events],
        }
    )
