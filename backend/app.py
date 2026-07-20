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
<<<<<<< HEAD
from core.exceptions import DumpHoundError
from core.logging import configure_logging
from core.middleware import RateLimitMiddleware, RequestContextMiddleware

log = logging.getLogger("dumphound")
=======
from core.exceptions import ProcTreeError
from core.logging import configure_logging
from core.middleware import RateLimitMiddleware, RequestContextMiddleware

log = logging.getLogger("proctree")
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    settings.ensure_dirs()
    get_container()  # eager-instantiate singletons

    @asynccontextmanager
    async def lifespan(_: FastAPI):
<<<<<<< HEAD
        log.info("DumpHound API starting")
        yield
        get_container().jobs.shutdown()
        log.info("DumpHound API stopped")

    app = FastAPI(
        title="DumpHound API",
        version="2.0.0",
        description="DumpHound — Volatility 3 memory-forensics analysis platform.",
=======
        log.info("ProcTree API starting")
        yield
        get_container().jobs.shutdown()
        log.info("ProcTree API stopped")

    app = FastAPI(
        title="ProcTree Workbench API",
        version="2.0.0",
        description="Volatility 3 memory-forensics analysis platform.",
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
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

<<<<<<< HEAD
    @app.exception_handler(DumpHoundError)
    async def _domain_handler(request: Request, exc: DumpHoundError) -> JSONResponse:
=======
    @app.exception_handler(ProcTreeError)
    async def _domain_handler(request: Request, exc: ProcTreeError) -> JSONResponse:
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
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
