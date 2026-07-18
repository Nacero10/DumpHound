"""ASGI middleware: error envelope, request id, and a simple rate limiter."""
from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .exceptions import ProcTreeError, RateLimitError


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id and convert domain errors into a JSON envelope."""

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except ProcTreeError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "error": {"code": exc.code, "message": exc.message},
                    "request_id": request_id,
                },
            )
        except Exception:  # noqa: BLE001 - last-resort guard
            return JSONResponse(
                status_code=500,
                content={
                    "error": {"code": "internal_error", "message": "Unexpected error"},
                    "request_id": request_id,
                },
            )
        response.headers["X-Request-ID"] = request_id
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window-ish sliding rate limiter keyed by client host.

    In-process and intentionally simple. For multi-replica deployments put a
    shared limiter (nginx/redis) in front; nginx.conf in deploy/ does exactly
    that for the Docker tier.
    """

    def __init__(self, app, limit_per_minute: int) -> None:
        super().__init__(app)
        self.limit = limit_per_minute
        self.window = 60.0
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        # Only throttle mutating / expensive endpoints.
        if request.method in ("POST", "PUT", "DELETE") or request.url.path.startswith(
            "/api/"
        ):
            client = request.client.host if request.client else "unknown"
            now = time.monotonic()
            bucket = self._hits[client]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                exc = RateLimitError("Rate limit exceeded")
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"error": {"code": exc.code, "message": exc.message}},
                    headers={"Retry-After": "60"},
                )
            bucket.append(now)
        return await call_next(request)
