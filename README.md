# 🐕 DumpHound — ProcTree Workbench

> A browser-based forensic analysis platform for memory dumps. Run Volatility 3 plugins, visualize process trees, detect malware indicators, and recover artifacts — all from a clean web UI.

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.6-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6.svg)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 📸 What It Looks Like

| Dashboard | Process Tree | File Recovery |
|---|---|---|
| Run Volatility plugins with one click | Interactive parent/child process graph | Dump inodes and recover deleted files |
| Auto-detect suspicious patterns | Drill into process details | Download artifacts via secure tokens |

---

## 🚀 Features

- **🔌 One-Click Volatility Runs** — Select a memory image and plugin; the backend runs Volatility 3 and returns structured CSV data.
- **🌳 Interactive Process Tree** — Visualize parent/child relationships, command lines, network connections, and loaded modules.
- **🛡️ Detection Engine** — Data-driven rule engine maps findings to MITRE ATT&CK techniques. Runs **entirely in the browser** for offline analysis.
- **📁 Artifact Recovery** — Dump specific inodes or bulk-recover filesystems from Linux page cache. Downloads are tokenized and SHA256-verified.
- **⚡ Offline Mode** — Drag-and-drop Volatility CSV exports straight into the browser. No backend required.
- **🐳 Docker-First** — Single `docker compose up --build` gets you running. No Python/Node installation needed.
- **🔒 Security-Hardened** — Plugin allowlists, path containment, argv-list subprocess execution, rate limiting, and structured audit logging.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Browser (React SPA)                      │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Process Tree│  │ Detection    │  │ Offline CSV Drop    │ │
│  │ Dashboard   │  │ Engine (WASM)│  │ & Analysis          │ │
│  └──────┬──────┘  └──────────────┘  └─────────────────────┘ │
└─────────┼────────────────────────────────────────────────────┘
          │ HTTP / SSE
┌─────────▼────────────────────────────────────────────────────┐
│              FastAPI Backend (Python 3.12)                   │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ API Router  │  │ Volatility   │  │ Artifact Service    │ │
│  │ (dumps,     │──│ Service      │──│ (tokenized          │ │
│  │  jobs,      │  │ (subprocess) │  │  downloads)         │ │
│  │  plugins)   │  └──────────────┘  └─────────────────────┘ │
│  └─────────────┘         │                                    │
│  ┌─────────────┐  ┌──────┴──────┐  ┌─────────────────────┐   │
│  │ Detection   │  │ Job Service │  │ Audit Logger        │   │
│  │ Service     │  │ (ThreadPool)│  │ (append-only JSON)  │   │
│  └─────────────┘  └─────────────┘  └─────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
          │
    ┌─────┴──────────────────────────────────────────┐
    │  Volatility 3 CLI  ·  Memory Images  ·  Symbols │
    └──────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

### Option A: Docker (Recommended)

```bash
# 1. Prepare your data folders
mkdir -p data/images data/symbols data/dumps
cp your-dump.mem data/images/

# 2. Build and run
docker compose up --build

# 3. Open http://127.0.0.1:8799
```

### Option B: Native (Windows PowerShell)

```powershell
# 1. Backend dependencies
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install volatility3

# 2. Start the backend
$env:VOL_FRONTEND_DIST = "$PWD\..\frontend\dist"
$env:VOL_IMAGE_DIR     = "$PWD\..\images"
$env:VOL_SYMBOL_DIR    = "$PWD\..\symbols"
python run.py

# 3. In another terminal, start the frontend dev server
cd ..\frontend
npm install
npm run dev

# 4. Open http://localhost:5173
```

> 📖 See [`SETUP-WINDOWS.md`](SETUP-WINDOWS.md) and [`DOCKER.md`](DOCKER.md) for detailed walkthroughs.

---

## 🎯 Usage

### Run a Plugin

1. Place your `.mem`, `.raw`, `.lime`, or `.dmp` file in the images folder.
2. Open the dashboard and select your image from the dropdown.
3. Pick a plugin (e.g., `linux.pslist.PsList`, `windows.netscan.NetScan`).
4. Click **Run**. Results appear as a table.

### Detect Threats

The detection engine automatically scans parsed data for:

| Category | Example Findings |
|---|---|
| **Process Lineage** | Web server spawning shell, suspicious parent/child pairs |
| **Commands** | Reverse shells, encoded PowerShell, history clearing |
| **Memory** | RWX regions, malfind anomalies, process spoofing |
| **Network** | Listening on high ports, unusual protocols |
| **Modules** | Out-of-tree modules, hidden modules, suspicious taints |
| **Syscalls** | Hooked system call tables |
| **Page Cache** | `ld.so.preload`, dropped `.ko` files, SSH keys in temp |

Findings are mapped to [MITRE ATT&CK](https://attack.mitre.org/) techniques with direct links.

### Recover Files

- **Inode dump:** Right-click a file in the page cache → dump its inode to recover the raw content.
- **Bulk recovery:** Click **Recover Filesystem** to run `linux.pagecache.RecoverFs` and get all recoverable files as downloadable artifacts.

### Offline Analysis

No backend? No problem. Drag one or more Volatility CSV exports into the browser window. The frontend parses, merges, and analyzes them using the same rule engine.

---

## 🛡️ Security

DumpHound is designed to handle sensitive forensic evidence safely:

- **Plugin Allowlist** — Only 80+ pre-approved Volatility plugins can run. Freeform names are rejected.
- **Path Containment** — All filesystem access is validated with `Path.resolve()` + `relative_to()` checks. `..` and path separators are blocked.
- **No Shell Injection** — Volatility is executed via `subprocess.run(argv=list, shell=False)`. User input never touches a shell string.
- **Tokenized Downloads** — Recovered artifacts are accessed via cryptographically random tokens (`secrets.token_urlsafe`), not file paths.
- **Rate Limiting** — Mutating endpoints are throttled per client IP.
- **Audit Logging** — Every plugin run, dump, and download is logged to an append-only JSON audit trail.

> ⚠️ **Note:** The app currently has **no authentication layer**. It is intended for single-analyst use on `127.0.0.1`. Do not expose the API to untrusted networks without adding authentication first.

---

## 📁 Project Structure

```
Dump_It/
├── backend/                  # FastAPI Python backend
│   ├── api/                  # HTTP route handlers
│   ├── core/                 # Config, security, middleware, DI
│   ├── services/             # Volatility runner, detection engine, jobs
│   ├── models/               # Pydantic request/response models
│   ├── repositories/         # In-memory stores (jobs, artifacts)
│   ├── rules/                # Detection rule JSON files
│   └── tests/                # pytest suite
├── frontend/                 # React + Vite SPA
│   ├── src/
│   │   ├── components/       # UI components (tree, inspector, dashboard)
│   │   ├── pages/            # Top-level routes
│   │   ├── services/         # Client-side parser + detection engine
│   │   ├── stores/           # Zustand global state
│   │   └── api/              # Typed fetch client
│   └── dist/                 # Prebuilt static files (Docker uses these)
├── deploy/                   # nginx configuration
├── docs/                     # Architecture diagrams, analyst guide
├── data/                     # Runtime data (images, dumps, symbols) — gitignored
├── docker-compose.yml        # One-command Docker setup
├── Dockerfile                # Single-container build (prebuilt UI)
└── backend/Dockerfile        # Multi-stage backend-only build
```

---

## 🧪 Testing

```bash
cd backend
pytest
```

The test suite covers:
- **Security guards** — path traversal rejection, plugin allowlist, inode injection, option validation
- **API endpoints** — health, images, plugins, dumps, detection, activity
- **Detection engine** — every detector category with planted indicators

---

## ⚙️ Configuration

All settings use the `VOL_` prefix and can be set via environment variables or a `.env` file:

| Variable | Default | Description |
|---|---|---|
| `VOL_IMAGE_DIR` | `./images` | Memory image storage |
| `VOL_OUTPUT_DIR` | `./dumps` | Recovered artifact output |
| `VOL_SYMBOL_DIR` | *(none)* | ISF symbol packs (`kernel.json`) |
| `VOL_RULES_DIR` | `./rules` | Detection rule JSON files |
| `VOL_HOST` | `127.0.0.1` | API bind address |
| `VOL_PORT` | `8799` | API port |
| `VOL_OFFLINE` | `true` | Pass `--offline` to Volatility |
| `VOL_TIMEOUT` | `900` | Per-call timeout (seconds) |
| `VOL_WORKERS` | `2` | Background job thread pool size |
| `VOL_RATE_LIMIT_PER_MINUTE` | `60` | Rate limit for mutating endpoints |
| `VOL_LOG_LEVEL` | `INFO` | Python logging level |

---

## 🐳 Docker Details

| Image | Purpose | Base |
|---|---|---|
| Root `Dockerfile` | Single-container build with prebuilt UI | `python:3.12-slim` |
| `backend/Dockerfile` | Backend-only, runs as non-root user | `python:3.12-slim` |
| `frontend/Dockerfile` | nginx serving built SPA | `nginx:1.27-alpine` |

The root Dockerfile is the fastest path: it skips Node entirely and copies the prebuilt `frontend/dist/` into the image. The backend Dockerfile is useful if you want to run the API standalone and serve the frontend separately.

---

## 🗺️ Roadmap / TODO

- [ ] Add authentication layer (API key or HTTP Basic Auth)
- [ ] Persist jobs and artifacts to SQLite or Redis
- [ ] Plugin result caching to avoid re-running identical queries
- [ ] Windows symbol auto-download toggle in UI
- [ ] Export findings to STIX/TAXII or MISP
- [ ] Multi-image comparison view

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-thing`)
3. Make your changes
4. Run tests (`cd backend && pytest`)
5. Commit and push
6. Open a Pull Request

Please keep `data/` out of Git — it is excluded by `.gitignore` for a reason (memory dumps are huge and evidence should not be version-controlled).

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [Volatility Foundation](https://www.volatilityfoundation.org/) — the gold standard in memory forensics
- [MITRE ATT&CK](https://attack.mitre.org/) — the detection engine maps directly to their framework
-  Holmes 2025 4: The Tunnel Without Walls  -- Hack The Box Challenge

---

> **DumpHound** — *Sniffing out evil in memory dumps.* 🐾
