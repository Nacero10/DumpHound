

<img width="350" height="350" alt="logo" src="https://github.com/user-attachments/assets/5908f813-39bf-4257-9c64-f966711ff1a5" />


# 🐕 DumpHound — ProcTree Workbench

> A browser-based forensic analysis platform for memory dumps. Run Volatility 3 plugins, visualize process trees, detect malware indicators, and recover artifacts — all from a clean web UI.

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.6-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6.svg)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg)](https://www.docker.com/)

---
# DumpHound — ProcTree Workbench

A browser-based forensic analysis platform for memory dumps. Run Volatility 3 plugins, visualize process trees, detect malware indicators, and recover artifacts — all from a clean, intuitive web interface.

Built with Python 3.12, FastAPI, React, and TypeScript. Docker-ready.

---

## What It Does

DumpHound brings memory forensics out of the command line and into the browser. Instead of juggling Volatility plugin output and CSV files, you get:

- **Interactive dashboards** that show process hierarchies at a glance
- **One-click analysis** — select an image, pick a plugin, see results instantly
- **Threat detection** that automatically flags suspicious patterns and maps them to MITRE ATT&CK techniques
- **Artifact recovery** — dump filesystems, recover deleted files, download evidence securely
- **Offline mode** — no backend needed; drag CSV exports straight into the browser for analysis
- **Single Docker command** to get everything running locally

---

## Key Features

**One-Click Volatility Runs**  
Select a memory image and plugin from the dashboard; the backend runs Volatility 3 and returns structured CSV data in seconds.

**Interactive Process Tree**  
Visualize parent/child process relationships, command lines, network connections, and loaded modules all in one view. Click to drill into any process.

**Detection Engine**  
A data-driven rule engine runs entirely in the browser, mapping findings to MITRE ATT&CK techniques. Works offline — no internet required.

**Artifact Recovery**  
Dump specific inodes or bulk-recover filesystems from Linux page cache. All downloads are tokenized and SHA256-verified for audit compliance.

**Offline Mode**  
No backend? Drag Volatility CSV exports straight into the browser. The frontend parses and analyzes them using the same rules.

**Docker-First**  
One command gets you running: `docker compose up --build`. No Python, Node, or manual setup needed.

**Security-Hardened**  
Plugin allowlists, path containment checks, no shell injection, tokenized downloads, rate limiting, and append-only audit logging.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Browser (React SPA)                      │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Process Tree│  │ Detection    │  │ Offline CSV Drop    │ │
│  │ Dashboard   │  │ Engine       │  │ & Analysis          │ │
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

## Getting Started

### Docker (Recommended)

```bash
# 1. Create data folders
mkdir -p data/images data/symbols data/dumps
cp your-dump.mem data/images/

# 2. Build and run
docker compose up --build

# 3. Open http://127.0.0.1:8799
```

### Windows (Native Setup)

```powershell
# 1. Install backend dependencies
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

# 3. In another terminal, start the frontend
cd ..\frontend
npm install
npm run dev

# 4. Open http://localhost:5173
```

See SETUP-WINDOWS.md and DOCKER.md for detailed guides.

---

## How to Use It

**Running Analysis**

1. Place your `.mem`, `.raw`, `.lime`, or `.dmp` file in the images folder
2. Open the dashboard and select your image from the dropdown
3. Pick a plugin — for example, `linux.pslist.PsList` or `windows.netscan.NetScan`
4. Click Run. Your results appear as an interactive table

**Detecting Threats**

The detection engine automatically analyzes your data for red flags:

- Process Lineage — web servers spawning shells, suspicious parent-child chains
- Commands — reverse shells, encoded PowerShell, history clearing
- Memory Regions — RWX memory, malfind anomalies, process spoofing
- Network — listening on high ports, unusual protocols
- Modules — out-of-tree modules, hidden modules, malicious imports
- Syscalls — hooked system call tables
- Page Cache — preload files, dropped kernel modules, SSH keys in temp directories

Every finding is mapped to MITRE ATT&CK techniques with direct links.

**Recovering Files**

Right-click any file in the page cache to dump its inode and recover the raw content. For bulk recovery, click Recover Filesystem to extract all recoverable files at once.

**Working Offline**

No backend required. Just drag one or more Volatility CSV exports into your browser. The frontend parses them, merges the data, and analyzes using the same rules.

---

## Security Considerations

DumpHound is designed to handle sensitive forensic evidence responsibly:

- Plugin Allowlist — only 80+ pre-approved Volatility plugins can run
- Path Containment — all filesystem access is validated; `..` and path traversal attempts are blocked
- No Shell Injection — Volatility runs via safe subprocess.run(argv=list, shell=False)
- Tokenized Downloads — recovered artifacts use cryptographic tokens, not file paths
- Rate Limiting — mutating endpoints are throttled per client IP
- Audit Logging — every plugin run, dump, and download is logged to an append-only JSON trail

Note: The app has no built-in authentication. It is intended for single-analyst use on 127.0.0.1. Do not expose it to untrusted networks without adding authentication first.

---

## Project Structure

```
DumpHound/
├── backend/                  # FastAPI backend (Python)
│   ├── api/                  # HTTP routes
│   ├── core/                 # Config, security, middleware
│   ├── services/             # Volatility runner, detection, jobs
│   ├── models/               # Pydantic request/response
│   ├── repositories/         # In-memory stores
│   ├── rules/                # Detection rule JSON
│   └── tests/                # pytest suite
├── frontend/                 # React + Vite SPA
│   ├── src/
│   │   ├── components/       # UI components
│   │   ├── pages/            # Routes
│   │   ├── services/         # Parser, detection engine
│   │   ├── stores/           # Zustand state
│   │   └── api/              # Typed fetch client
│   └── dist/                 # Prebuilt static files
├── deploy/                   # nginx config
├── docs/                     # Architecture and guides
├── data/                     # Runtime data (gitignored)
├── docker-compose.yml        # Docker setup
├── Dockerfile                # Single-container build
└── backend/Dockerfile        # Backend-only build
```

---

## Configuration

Settings use the `VOL_` prefix and can be set via environment variables or `.env` file:

| Variable | Default | Purpose |
|---|---|---|
| VOL_IMAGE_DIR | ./images | Where memory images are stored |
| VOL_OUTPUT_DIR | ./dumps | Where recovered artifacts go |
| VOL_SYMBOL_DIR | ./symbols | ISF symbol packs (kernel.json) |
| VOL_RULES_DIR | ./rules | Detection rule JSON files |
| VOL_HOST | 127.0.0.1 | API bind address |
| VOL_PORT | 8799 | API port |
| VOL_OFFLINE | true | Run Volatility in offline mode |
| VOL_TIMEOUT | 900 | Per-call timeout in seconds |
| VOL_WORKERS | 2 | Background job thread pool size |
| VOL_RATE_LIMIT_PER_MINUTE | 60 | Rate limit for mutations |
| VOL_LOG_LEVEL | INFO | Python logging level |

---

## Testing

```bash
cd backend
pytest
```

The test suite covers security guards, API endpoints, and detection logic.

---

## Demo

Watch DumpHound in action:

https://github.com/user-attachments/assets/701a06b7-48c2-438d-bad9-5fe7bfc3f75d

---

## What's Coming

- Authentication layer (API key or HTTP Basic Auth)
- Persistent storage for jobs and artifacts
- Result caching to speed up repeated queries
- Direct memory dump from running processes
- Export findings to STIX/TAXII or MISP
- Multi-image comparison view
- YARA rule matching
- MemProcFS integration for parallel analysis (Win/Linux/macOS support)
- Live memory analysis using MemProcFS API

---


## Acknowledgments

This project stands on the shoulders of giants:

**Volatility Foundation** — the gold standard in memory forensics  
**MITRE ATT&CK** — the detection engine maps directly to their framework  
**MemProcFS** — memory forensics through simple file browsing  

Inspiration came from Holmes 2025 4: The Tunnel Without Walls (Hack The Box) and the DFIR and TypeScript communities.

---

DumpHound — Sniffing out evil in memory dumps.



