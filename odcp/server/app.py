"""FastAPI application factory for the ODCP web dashboard."""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from typing import Optional

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


def create_app(store: Optional[ReportStore] = None) -> "fastapi.FastAPI":  # type: ignore[name-defined]  # noqa: F821
    """Create and return the FastAPI application.

    Parameters
    ----------
    store:
        A pre-configured :class:`~odcp.server.state.ReportStore`.  If
        ``None``, an empty store (no report loaded) is created.
    """
    _require_fastapi()

    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware

    from odcp.server.routes import api_router, ui_router

    if store is None:
        store = ReportStore()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await store.start_watcher()
        yield
        await store.stop_watcher()

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

    # Attach store to app.state immediately (not waiting for lifespan)
    app.state.store = store

    app.include_router(ui_router)
    app.include_router(api_router)

    return app
