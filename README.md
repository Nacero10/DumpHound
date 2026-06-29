# ProcTree Workbench — Memory-Forensics Platform

A production-grade refactor of the single-file ProcTree Workbench into a modular
**FastAPI + React/TypeScript** platform for **Volatility 3** memory analysis.

It ingests Volatility CSV exports, builds an interactive process tree, correlates
bash history / sockets / open files, scores `linux.pagecache.Files` artifacts
against an ATT&CK-mapped detection ruleset, and generates page-cache extraction
commands — with the correct `--inode <InodeAddr>` (address, **not** inode number).

> The browser app analyzes CSVs **entirely client-side** — nothing is uploaded.
> The backend is optional and only needed to run Volatility live and dump cached
> files straight from an image.

---

## Architecture

```
proctree-platform/
├── backend/                 FastAPI service (Python 3.12, Pydantic v2)
│   ├── app.py               app factory: middleware, routers, lifespan
│   ├── api/                 thin routers: health, images, plugins, jobs, dumps
│   ├── services/            volatility, job, artifact, dump, detection
│   ├── repositories/        in-memory job + artifact stores
│   ├── models/              request/response/job/artifact schemas
│   ├── core/                config, security, validators, DI container, logging
│   ├── rules/               linux.json · windows.json · mitre.json
│   └── tests/               48 pytest tests (security, detection, API)
├── frontend/                React 18 + TypeScript + Vite
│   ├── src/
│   │   ├── api/             typed fetch client
│   │   ├── components/      ProcessTree(D3) · Inspector · Dashboard · FileCache · Modules
│   │   ├── services/        parser · detection · export
│   │   ├── stores/          Zustand app store
│   │   ├── hooks/           React Query hooks
│   │   └── pages/           WorkbenchPage
│   └── public/rules/        rules served to the SPA for offline detection
├── deploy/nginx.conf        static serving + /api proxy (SSE unbuffered)
├── docker-compose.yml
└── docs/                    Mermaid class / sequence / component diagrams
```

See `docs/class-diagram.md`, `docs/sequence-diagram.md`, and
`docs/component-diagram.md` for the UML.

---

## Detection engine (data-driven)

All detection logic lives in JSON, loaded by **both** the Python backend and the
TypeScript client — never hardcoded in UI components.

| File | Contents |
|---|---|
| `rules/linux.json` | pagecache, lineage, command, network, spoofing, malfind, modules rules |
| `rules/windows.json` | Windows lineage / command / malfind rules (Office spawns, encoded PS, wmiexec, etc.) |
| `rules/mitre.json` | technique id → {name, tactic} for ATT&CK enrichment |

Detector classes: `ProcessLineageDetector`, `CommandDetector`, `NetworkDetector`,
`MalfindDetector`, `SpoofingDetector`, `ModuleDetector`, `SyscallDetector`,
`PagecacheDetector`, and `MitreMapper`. Severity levels are `alert` / `warn` / `info`.

### Rootkit & hidden-module coverage

Kernel-level tampering is surfaced from Volatility's `linux.malware.*` plugins:

| Indicator | Source plugin | Rule | Severity | ATT&CK |
|---|---|---|---|---|
| Hidden module (unlinked from module list) | `linux.malware.hidden_modules` | `hidden_module` | alert | T1014 |
| Out-of-tree module | `linux.lsmod` / `check_modules` | `oot_module` | alert | T1014 |
| Unsigned module | `linux.lsmod` | `unsigned_module` | warn | T1014 |
| Suspicious kernel taint (O/E/F/R) | `linux.lsmod` | `suspicious_taint` | warn | T1014 |
| Syscall-table hooking (handler doesn't resolve) | `linux.malware.check_syscall` | `hooked_syscall` | alert | T1014 |
| `.ko` outside `/lib/modules` (page cache) | `linux.pagecache.Files` | `ko_outside_modules` | alert | T1547.006 |
| RWX/injected regions | `linux.malware.malfind` | `rwx_region` | warn | T1620 |

The **Modules & Rootkits** view decodes kernel taint letters (e.g. `O` = out-of-tree,
`E` = unsigned, `F` = force-loaded), floats hidden/tainted modules to the top, and
provides a syscall-integrity table that flags every handler Volatility couldn't
resolve to a known symbol — the classic signature of syscall-table hooking.
CSV plugin type is inferred from headers: an lsmod export (with a `Taints` column)
is treated as visible modules, while a `hidden_modules` export (name/address/size,
no taint column) marks every row as hidden.

To add a rule, edit the JSON — no code change. Example (page-cache):

```json
{ "id": "ld_preload", "level": "alert", "technique": "T1574.006",
  "detail": "ld.so.preload present in page cache (library injection)",
  "match": { "path_eq": "/etc/ld.so.preload" } }
```

Matcher DSL keys: `path_eq`, `path_contains`, `path_not_contains`,
`path_contains_any`, `path_ext`, `path_regex`, `parent_comm_in`, `child_comm_in`,
`cmd_regex`/`cmd_flags`, `proto_in`, `state_in`, `local_port_gte`,
`local_port_not_in`, `field_truthy`, `field_eq`, `field_regex`, `comm_in`.

### Two-page workflow

The UI is split into two routed pages sharing one in-memory evidence store:

- **Process Graph** — the D3 process tree with the live Inspector and a severity
  strip. Click any node to inspect its history, sockets, files, and findings.
- **Files & Modules** — artifact analysis, tabbed into *Findings* (the full
  ATT&CK-mapped dashboard), *File Cache* (page-cache scoring + dump commands), and
  *Modules & Rootkits* (kernel modules, hidden modules, syscall integrity).

Switching pages preserves all parsed data and findings.

---

## Quick start — Docker (full stack)

```bash
# 1. drop a memory image where the backend can see it
mkdir -p data/images data/dumps data/symbols
cp /path/to/memdump.mem data/images/

# 2. build + run
docker compose up --build

# 3. open the workbench
#    http://127.0.0.1:8080      (SPA, /api proxied to the backend)
#    http://127.0.0.1:8080/api/health
```

nginx serves the SPA and proxies `/api` to the backend with rate limiting and
SSE buffering disabled. The backend port is not published — only nginx reaches it.

---

## Local development

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt        # includes pytest + httpx
# Volatility is optional locally; the API degrades gracefully without it:
# pip install volatility3==2.28.0

cp .env.example .env                        # adjust paths if desired
mkdir -p images dumps
python run.py
# → http://127.0.0.1:8799        API docs: http://127.0.0.1:8799/docs
```

Run the tests:

```bash
cd backend && source .venv/bin/activate
python -m pytest -q          # 48 passed
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# → http://127.0.0.1:5173     (/api proxied to 127.0.0.1:8799 via vite)
```

Production build:

```bash
npm run build                 # tsc -b && vite build  → dist/
npm run preview               # serve dist locally
```

---

## Using the workbench

### Option A — run Volatility from the app (backend required)

Click **▸ Run Volatility**, pick an image from `VOL_IMAGE_DIR`, select plugins
(a recommended set is preselected), and run. Each plugin executes on the backend
and its CSV streams straight into the analysis store — because the app knows
which plugin it invoked, results are routed without any header guessing.

### Option B — drag in CSVs (fully offline)

1. Export Volatility 3 plugins as CSV (see `docs/volatility-commands.md` for the
   complete command set and the CSV→panel mapping):

   ```bash
   vol -f memdump.mem -r csv -q linux.pstree.PsTree                        > pstree.csv
   vol -f memdump.mem -r csv -q linux.bash.Bash                            > bash.csv
   vol -f memdump.mem -r csv -q linux.sockstat.Sockstat                    > sockstat.csv
   vol -f memdump.mem -r csv -q linux.lsof.Lsof                            > lsof.csv
   vol -f memdump.mem -r csv -q linux.pagecache.Files                      > pagecache.csv
   vol -f memdump.mem -r csv -q linux.lsmod.Lsmod                          > lsmod.csv
   vol -f memdump.mem -r csv -q linux.malware.hidden_modules.Hidden_modules > hidden.csv
   vol -f memdump.mem -r csv -q linux.malware.check_syscall.Check_syscall   > syscall.csv
   ```

2. Drag the CSVs onto the workbench. Plugin type is inferred from headers —
   filenames don't matter.

### The process graph

The **Process Graph** page renders an interactive graph with two layouts:
**Tree** (tidy hierarchical lineage) and **Force** (organic force-directed).
Drag any node to reposition it — it stays pinned where you drop it;
double-click a node to release it back into the physics simulation. Scroll to
zoom, drag the background to pan, **Fit** re-frames everything. Nodes are colored
by finding severity; click one to drive the Inspector.



   ```bash
   vol -f memdump.mem linux.pagecache.InodePages --inode 0x88c1a2b40000 --dump
   ```

   > **Critical:** `--inode` takes the **InodeAddr** (e.g. `0x88c1a2b40000`),
   > not the inode number. Using the number is the most common reason dumps come
   > back empty. When `CachedPages < InodePages`, the dump is zero-padded over the
   > missing pages — the workbench flags these rows.

   Bulk recovery:

   ```bash
   vol -o ./out -f memdump.mem linux.pagecache.RecoverFs
   tar tzvf out/*.tar.gz | less
   ```

---

## Security model

- **Plugin allowlist** — only named Volatility plugins can execute.
- **Path validation** — `resolve_image()` rejects `/`, `\`, `..`; the image must
  resolve inside `VOL_IMAGE_DIR`.
- **Inode validation** — `^(0x[0-9a-fA-F]+|\d+)$`; injection like `0x1; rm -rf /`
  is rejected with HTTP 400.
- **Safe subprocess** — every argument is a discrete argv element; no shell
  strings are ever constructed. `--offline` is always appended.
- **Job & artifact isolation** — each dump runs in a token-scoped output dir;
  downloads are addressed by opaque tokens, not paths.
- **Rate limiting** — sliding-window per client (configurable, also at nginx).
- **Audit logging** — append-only record of run/dump operations.
- **Structured logging** — JSON logs with request ids.

---

## Configuration (env, prefix `VOL_`)

| Variable | Default | Notes |
|---|---|---|
| `VOL_BIN` | `vol` | Volatility 3 CLI path |
| `VOL_IMAGE_DIR` | `./images` | images must live here |
| `VOL_OUTPUT_DIR` | `./dumps` | recovered artifacts |
| `VOL_SYMBOL_DIR` | (unset) | passed as `-s` to vol |
| `VOL_RULES_DIR` | `./rules` | detection rule JSON |
| `VOL_TIMEOUT` | `900` | per-call seconds |
| `VOL_WORKERS` | `2` | concurrent jobs |
| `VOL_HOST` | `127.0.0.1` | bind address |
| `VOL_PORT` | `8799` | listen port |
| `VOL_OFFLINE` | `true` | append `--offline` |
| `VOL_RATE_LIMIT_PER_MINUTE` | `60` | per-client request cap |
| `VOL_LOG_LEVEL` | `INFO` | log level |

---

## API surface

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | service + Volatility availability |
| GET | `/api/images` | list images in `VOL_IMAGE_DIR` |
| GET | `/api/plugins` | allowlisted plugins |
| POST | `/api/plugins/run` | run a table plugin → CSV |
| POST | `/api/plugins/detect` | run detection over parsed records |
| POST | `/api/jobs/inode` | async page-cache dump by InodeAddr |
| POST | `/api/jobs/recoverfs` | async full filesystem recovery |
| GET | `/api/jobs/{id}` | job status + artifacts |
| GET | `/api/jobs/{id}/stream` | SSE job progress |
| GET | `/api/dumps/download/{token}` | secure artifact download |

Full OpenAPI at `/docs` (Swagger) and `/openapi.json`.

---

## What's verified

- Backend: **52/52 pytest** passing (security guards, detection incl. hidden
  modules / taint / syscall hooking, API contract).
- Frontend: **`tsc -b && vite build`** compiles clean (strict mode, no unused).
- Detection parity (headless client run against planted indicators):
  process/lineage/command/page-cache (`webserver_spawns_shell`, `reverse_shell`,
  `remote_download_exec`, `ld_preload`, `webshell`, `etc_passwd`, `oot_module`)
  **and** rootkit indicators (`suspicious_taint`, `hidden_module`,
  `hooked_syscall`) all fire correctly.

Docker images are defined but require a Docker daemon to build/run (not available
in every environment). The compose file, Dockerfiles, and nginx config are
provided and ready to `docker compose up --build`.
#   D u m p H o u n d  
 