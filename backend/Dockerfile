# ProcTree backend — FastAPI + Volatility 3.
# Volatility itself is heavy and version-sensitive; install it here so the API
# can shell out to `vol`. If you run fully air-gapped, bake your symbol packs
# into VOL_SYMBOL_DIR and set VOL_OFFLINE=1 (the default).
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps for Volatility (yara/capstone optional but recommended).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Python deps first for layer caching.
COPY backend/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt \
    && pip install "volatility3==2.28.0"

# App source.
COPY backend/ ./backend/

# Non-root runtime user; create data dirs it owns.
RUN useradd --create-home --uid 10001 proctree \
    && mkdir -p /data/images /data/dumps /data/symbols \
    && chown -R proctree:proctree /data /app
USER proctree

ENV VOL_BIN=vol \
    VOL_IMAGE_DIR=/data/images \
    VOL_OUTPUT_DIR=/data/dumps \
    VOL_SYMBOL_DIR=/data/symbols \
    VOL_RULES_DIR=/app/backend/rules \
    VOL_HOST=0.0.0.0 \
    VOL_PORT=8799 \
    VOL_OFFLINE=true

EXPOSE 8799
WORKDIR /app/backend

# uvicorn via the app factory.
CMD ["python", "run.py"]
