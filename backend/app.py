"""FastAPI application factory.

Wires logging, middleware (request-context error envelope + rate limiting),
CORS, routers, exception handlers, and an optional static mount for the built
React frontend.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from api import activity, dumps, health, images, jobs, plugins
from core.config import get_settings
from core.container import get_container
from core.exceptions import ProcTreeError
from core.logging import configure_logging
from core.middleware import RateLimitMiddleware, RequestContextMiddleware

log = logging.getLogger("proctree")


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    settings.ensure_dirs()
    get_container()  # eager-instantiate singletons

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        log.info("ProcTree API starting")
        yield
        get_container().jobs.shutdown()
        log.info("ProcTree API stopped")

    app = FastAPI(
        title="ProcTree Workbench API",
        version="2.0.0",
        description="Volatility 3 memory-forensics analysis platform.",
        docs_url="/docs",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Middleware (order: rate limit -> context). Starlette runs them LIFO, so
    # add context last to make it outermost.
    app.add_middleware(RateLimitMiddleware, limit_per_minute=settings.rate_limit_per_minute)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.exception_handler(ProcTreeError)
    async def _domain_handler(request: Request, exc: ProcTreeError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    api_routers = [
        health.router, images.router, plugins.router,
        dumps.router, jobs.router, activity.router,
    ]
    for r in api_routers:
        app.include_router(r, prefix="/api")

    # Optional static frontend (built React dist). Mounted last so /api wins.
    if settings.frontend_dist and settings.frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=str(settings.frontend_dist), html=True), name="ui")
        log.info("serving frontend from %s", settings.frontend_dist)

    return app


app = create_app()
