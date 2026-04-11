"""FastAPI application factory for the ODCP web dashboard."""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from typing import Optional

from odcp.collector.registry import AgentRegistry
from odcp.server.state import ReportStore


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
    """
    _require_fastapi()

    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware

    from odcp.server.fleet_routes import fleet_api_router, fleet_ui_router
    from odcp.server.routes import api_router, ui_router

    if store is None:
        store = ReportStore()
    if registry is None:
        registry = AgentRegistry()

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

    # Attach store and registry immediately (not waiting for lifespan)
    app.state.store = store
    app.state.agent_registry = registry

    app.include_router(ui_router)
    app.include_router(api_router)
    app.include_router(fleet_ui_router)
    app.include_router(fleet_api_router)

    return app
