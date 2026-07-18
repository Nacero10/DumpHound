"""Domain exception hierarchy.

Each exception carries an HTTP status and a stable ``code`` string so the
error-handling middleware can emit a consistent JSON envelope without leaking
internal detail.
"""
from __future__ import annotations


class ProcTreeError(Exception):
    """Base class for all application errors."""

    status_code: int = 500
    code: str = "internal_error"

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.__class__.__doc__ or "Error"
        super().__init__(self.message)


class ValidationError(ProcTreeError):
    """A request parameter failed a security or format check."""

    status_code = 400
    code = "validation_error"


class NotFoundError(ProcTreeError):
    """The requested resource does not exist."""

    status_code = 404
    code = "not_found"


class SecurityError(ProcTreeError):
    """A request violated a security guard (path traversal, bad plugin...)."""

    status_code = 403
    code = "security_error"


class VolatilityError(ProcTreeError):
    """Volatility execution failed or produced no usable output."""

    status_code = 502
    code = "volatility_error"


class JobError(ProcTreeError):
    """A background job failed or is in an invalid state."""

    status_code = 409
    code = "job_error"


class RateLimitError(ProcTreeError):
    """Too many requests from this client."""

    status_code = 429
    code = "rate_limited"
