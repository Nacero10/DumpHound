"""Domain exception hierarchy.

Each exception carries an HTTP status and a stable ``code`` string so the
error-handling middleware can emit a consistent JSON envelope without leaking
internal detail.
"""
from __future__ import annotations


<<<<<<< HEAD
class DumpHoundError(Exception):
=======
class ProcTreeError(Exception):
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
    """Base class for all application errors."""

    status_code: int = 500
    code: str = "internal_error"

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.__class__.__doc__ or "Error"
        super().__init__(self.message)


<<<<<<< HEAD
class ValidationError(DumpHoundError):
=======
class ValidationError(ProcTreeError):
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
    """A request parameter failed a security or format check."""

    status_code = 400
    code = "validation_error"


<<<<<<< HEAD
class NotFoundError(DumpHoundError):
=======
class NotFoundError(ProcTreeError):
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
    """The requested resource does not exist."""

    status_code = 404
    code = "not_found"


<<<<<<< HEAD
class SecurityError(DumpHoundError):
=======
class SecurityError(ProcTreeError):
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
    """A request violated a security guard (path traversal, bad plugin...)."""

    status_code = 403
    code = "security_error"


<<<<<<< HEAD
class VolatilityError(DumpHoundError):
=======
class VolatilityError(ProcTreeError):
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
    """Volatility execution failed or produced no usable output."""

    status_code = 502
    code = "volatility_error"


<<<<<<< HEAD
class JobError(DumpHoundError):
=======
class JobError(ProcTreeError):
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
    """A background job failed or is in an invalid state."""

    status_code = 409
    code = "job_error"


<<<<<<< HEAD
class RateLimitError(DumpHoundError):
=======
class RateLimitError(ProcTreeError):
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
    """Too many requests from this client."""

    status_code = 429
    code = "rate_limited"
