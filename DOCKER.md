# Docker - learn it by shipping ProcTree

This walks you through running ProcTree in Docker *and* teaches the core ideas
as you go. The `Dockerfile`, `docker-compose.yml`, and `.dockerignore` are all
heavily commented - read them alongside this.

## The mental model (5 terms)

- **Image** - a frozen, read-only template (your app + its dependencies + a tiny
  OS). Built once, run many times. Think "class".
- **Container** - a running instance of an image. Think "object". Disposable;
  delete and recreate freely.
- **Dockerfile** - the recipe that builds an image, one instruction at a time.
- **Layer** - each Dockerfile instruction produces a cached layer. Unchanged
  layers are reused, so rebuilds are fast. Order matters (cheap-to-change things
  last).
- **Volume** - a host folder mapped into a container, so data lives outside the
  container's throwaway filesystem (your memory images, dumps, symbols).

## Why a container here

You already run ProcTree natively on Windows and hit two environment problems:
Python 3.14 had no pydantic-core wheel (needed a Rust compiler), and the console
code page (cp1252) crashed vol on Unicode filenames. A container removes *both*:
the image pins **Python 3.12** (wheels exist, no compiler) and runs a **UTF-8
Linux** userland. "Works on my machine" becomes "works in the image, everywhere."

## One-time: install Docker Desktop

Windows: install **Docker Desktop**, start it, confirm it's running:

```powershell
docker version
docker compose version
```

## Prepare your data folders

Volumes map these host folders into the container. Create them and drop your
evidence in:

```powershell
cd "C:\Users\PC\Downloads\Side Projects\Dump_It\v1"
mkdir data\images, data\symbols, data\dumps
copy <your-dump>.mem .\data\images\
# Linux ISF symbol packs (the kernel.json you build with dwarf2json):
#   copy kernel.json .\data\symbols\linux\
```

## Build and run

```powershell
docker compose up --build
```

What happens, in order:
1. Docker reads `.dockerignore`, then sends the build context (repo files, minus
   ignored ones) to the engine.
2. **Stage 1 (`web`)**: `node:20-slim` runs `npm ci` then `npm run build`,
   producing the static SPA in `/web/dist`.
3. **Stage 2 (`runtime`)**: `python:3.12-slim` installs the backend deps +
   Volatility 3, copies the backend source, and copies `dist` *from stage 1*.
4. A container starts from the finished image, binds `0.0.0.0:8799`, and the
   published port maps it to your machine.

Open **http://127.0.0.1:8799/**.

Run it detached (in the background) instead:

```powershell
docker compose up --build -d
docker compose logs -f          # follow logs;  Ctrl+C to stop following
docker compose down             # stop and remove the container
```

## Everyday commands

```powershell
docker compose up --build       # (re)build after changing code/Dockerfile
docker compose up -d            # start (uses cached image if unchanged)
docker compose down             # stop + remove container (image stays)
docker ps                       # list running containers
docker compose logs -f          # tail logs
docker exec -it proctree bash   # open a shell INSIDE the running container
docker exec -it proctree vol --version   # run vol inside the container
docker image ls                 # list images and their sizes
docker system df                # how much disk Docker is using
docker system prune             # reclaim space (dangling images/containers)
```

## How the pieces line up with native run

| Native (Windows env var) | Container (set in image/compose) |
|---|---|
| `VOL_FRONTEND_DIST = ...\frontend\dist` | `/app/frontend/dist` (baked in) |
| `VOL_IMAGE_DIR = ...\images` | volume -> `/data/images` |
| `VOL_SYMBOL_DIR = ...\symbols` | volume -> `/data/symbols` |
| `VOL_OUTPUT_DIR` (dumps) | volume -> `/data/dumps` |
| host `127.0.0.1:8799` | `VOL_HOST=0.0.0.0`, published `8799:8799` |

## Troubleshooting

- **`{"detail":"Not Found"}` at `/`** - the SPA didn't get mounted. In the
  container build this can't happen (dist is baked in); if you see it, the image
  is stale - rebuild with `docker compose up --build`.
- **Run panel says "no vol"** - Volatility didn't install. Check build logs;
  if a dep tried to compile, uncomment the `build-essential` line in the
  Dockerfile and rebuild.
- **Plugins return "no data"** - same as native: missing ISF symbols for a Linux
  kernel. Mount the matching `kernel.json` under `./data/symbols/linux/`.
- **Windows memory image** - set `VOL_OFFLINE: "false"` in `docker-compose.yml`
  so vol can download PDB symbols, then rebuild/restart.
- **Port already in use** - change the host side: `ports: ["9000:8799"]`, then
  open `http://127.0.0.1:9000/`.
- **Permission denied on a mounted image** - make sure the file is readable;
  the `:ro` mount only needs read access.

## Why these specific choices (the teaching bits)

- **Multi-stage build**: Node is only needed to *compile* the UI. Keeping it in a
  separate stage means the shipped image has no Node, npm, or TS source - just
  the static output. Smaller attack surface, smaller image.
- **Copy manifests before source**: maximizes layer-cache hits. Editing a React
  component re-runs only the `COPY frontend/ .` + `npm run build` layers, not the
  slow `npm ci`.
- **`python:3.12-slim`**: pinning the runtime fixes the wheel/compiler problem at
  the source - the container never sees Python 3.14.
- **`VOL_HOST=0.0.0.0`**: inside a container, binding loopback would make the app
  unreachable from your host even with a published port.
- **Read-only evidence mounts (`:ro`)**: forensic hygiene - the container can
  read but never modify your memory images.
- **`.dockerignore` excludes `data/` and `*.mem`**: keeps multi-GB images out of
  the build context (which would otherwise be copied to the Docker engine on
  every build).
