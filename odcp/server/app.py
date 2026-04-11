"""FastAPI application factory for the ODCP web dashboard."""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from typing import Optional

from odcp.collector.registry import AgentRegistry
from odcp.server.state import ReportStore

logger = logging.getLogger(__name__)


def _require_fastapi():
    try:
        import fastapi  # noqa: F401
    except ImportError:
        print(
            "\n[ERROR] The 'fastapi' and 'uvicorn' packages are required for the dashboard.\n"
            "Install them with:  pip install 'odcp[server]'\n",
            file=sys.stderr,
        )
        sys.exit(1)


def create_app(
    store: Optional[ReportStore] = None,
    registry: Optional[AgentRegistry] = None,
    token_store=None,       # Optional[TokenStore] — avoid hard import for tests
    audit_logger=None,      # Optional[AuditLogger]
    lifecycle_manager=None, # Optional[LifecycleManager]
) -> "fastapi.FastAPI":  # type: ignore[name-defined]  # noqa: F821
    """Create and return the FastAPI application.

    Parameters
    ----------
    store:
        A pre-configured :class:`~odcp.server.state.ReportStore`.  If
        ``None``, an empty store (no report loaded) is created.
    registry:
        A pre-configured :class:`~odcp.collector.registry.AgentRegistry`.
        If ``None``, a fresh in-memory registry is created.
    token_store:
        A pre-configured :class:`~odcp.server.auth.TokenStore`.  If
        ``None``, auth is **disabled** (open access, safe for dev/testing).
    audit_logger:
        A pre-configured :class:`~odcp.server.audit.AuditLogger`.  If
        ``None``, a memory-only logger is created.
    lifecycle_manager:
        A pre-configured :class:`~odcp.lifecycle.LifecycleManager`.  If
        ``None``, a fresh in-memory manager is created.
    """
    _require_fastapi()

    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware

    from odcp.lifecycle.manager import LifecycleManager
    from odcp.server.audit import AuditLogger
    from odcp.server.auth import TokenStore
    from odcp.server.auth_routes import auth_router
    from odcp.server.fleet_routes import fleet_api_router, fleet_ui_router
    from odcp.server.lifecycle_routes import lifecycle_api_router, lifecycle_ui_router
    from odcp.server.routes import api_router, ui_router

    if store is None:
        store = ReportStore()
    if registry is None:
        registry = AgentRegistry()
    if token_store is None:
        token_store = TokenStore(auth_enabled=False)
    if audit_logger is None:
        audit_logger = AuditLogger()
    if lifecycle_manager is None:
        lifecycle_manager = LifecycleManager()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await store.start_watcher()
        await registry.start_staleness_checker()
        yield
        await store.stop_watcher()
        await registry.stop_staleness_checker()

    app = FastAPI(
        title="ODCP Dashboard",
        description="Open Detection Control Plane — real-time SOC visibility",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Attach all server-side state immediately (before lifespan)
    app.state.store = store
    app.state.agent_registry = registry
    app.state.token_store = token_store
    app.state.audit_logger = audit_logger
    app.state.lifecycle_manager = lifecycle_manager

    app.include_router(ui_router)
    app.include_router(api_router)
    app.include_router(fleet_ui_router)
    app.include_router(fleet_api_router)
    app.include_router(auth_router)
    app.include_router(lifecycle_ui_router)
    app.include_router(lifecycle_api_router)

    return app
