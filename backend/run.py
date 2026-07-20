"""Dev entrypoint: ``python run.py``."""
from __future__ import annotations

import uvicorn

from core.config import get_settings

if __name__ == "__main__":
    s = get_settings()
    uvicorn.run("app:app", host=s.host, port=s.port, reload=False, log_config=None)
