# ============================================================================
#  ProcTree Workbench - single container (no-build edition)
#
#  We do NOT rebuild the React UI inside Docker. The repo already ships a
#  working prebuilt frontend/dist, so the image just installs the Python
#  backend + Volatility 3 and copies that dist in. This avoids every Vite/Node
#  build pitfall (wrong index.html, Node version, etc.) and builds fast.
#
#  Build & run:   docker compose up --build   ->   http://127.0.0.1:8799/
# ============================================================================

FROM python:3.12-slim

# Stream logs, no .pyc, and force UTF-8 everywhere (mirrors the in-app vol fix
# so Unicode filenames never crash a plugin run).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    PYTHONIOENCODING=utf-8

WORKDIR /app

# Build tools are only needed if a Volatility dependency lacks a prebuilt wheel.
# Kept for reliability; safe to drop if your build pulls wheels cleanly.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

# Install deps first (manifest layer is cached unless requirements change).
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt \
 && pip install --no-cache-dir volatility3

# App code + the PREBUILT UI (no Node, no Vite).
COPY backend/ ./backend/
COPY frontend/dist ./frontend/dist

# Paths + bindings. VOL_HOST=0.0.0.0 is required so the published port reaches
# the server from your host (127.0.0.1 inside the container is unreachable).
ENV VOL_FRONTEND_DIST=/app/frontend/dist \
    VOL_RULES_DIR=/app/backend/rules \
    VOL_IMAGE_DIR=/data/images \
    VOL_SYMBOL_DIR=/data/symbols \
    VOL_OUTPUT_DIR=/data/dumps \
    VOL_HOST=0.0.0.0 \
    VOL_PORT=8799 \
    VOL_OFFLINE=true

RUN mkdir -p /data/images /data/symbols /data/dumps

EXPOSE 8799
WORKDIR /app/backend
CMD ["python", "run.py"]
