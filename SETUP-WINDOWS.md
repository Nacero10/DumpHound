# Setup — Windows (PowerShell)

Full setup, start to finish. Run from the extracted project root. Replace the
example path with your own.

```powershell
cd "C:\Users\PC\Downloads\Side Projects\Dump_It"
$ROOT = "C:\Users\PC\Downloads\Side Projects\Dump_It"
```

## 1. Backend venv + dependencies (one-time)

Python 3.11/3.12 preferred; 3.9 also works (backport already in requirements).

```powershell
cd "$ROOT\backend"
py -3.12 -m venv .venv            # or: py -3.9 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt   # the -r flag matters
```

If activation is blocked by execution policy:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## 2. Volatility 3 (for the in-app Run / Activity features)

```powershell
pip install volatility3
vol --version                     # confirm it resolves in the venv
```
If `vol` isn't found later: `$env:VOL_BIN = "vol.exe"` (or full path).

## 3. Frontend — pick ONE

**A. Use the prebuilt UI (no Node).** `frontend\dist\` ships in this package —
nothing to do, skip to step 4.

**B. You edited the source / applied a delta → rebuild.** Needs Node.js LTS
(nodejs.org):
```powershell
cd "$ROOT\frontend"
npm install
npm run build                     # regenerates frontend\dist
```

## 4. Start (each session)

Easiest — the bundled script sets paths and launches:
```powershell
cd "$ROOT"
.\start.ps1
```

Or manually:
```powershell
cd "$ROOT\backend"
C
$env:VOL_FRONTEND_DIST = "$ROOT\frontend\dist"
$env:VOL_IMAGE_DIR     = "$ROOT\images"
$env:VOL_SYMBOL_DIR    = "$ROOT\symbols"
python run.py
```

Open **http://127.0.0.1:8799/**.
`{"detail":"Not Found"}` at `/` means `VOL_FRONTEND_DIST` wasn't set this session.

## 5. Verify

```powershell
curl http://127.0.0.1:8799/api/health     # volatility_available: true
curl http://127.0.0.1:8799/api/activity    # {"events":[...]} after running plugins
```

## 6. Put your image in place

```powershell
New-Item -ItemType Directory -Force "$ROOT\images","$ROOT\symbols" | Out-Null
copy <your-dump>.mem "$ROOT\images\"
dir "$ROOT\images"
```

## 7. "no data / 14 rows" on a Linux image = missing ISF symbols

Volatility 3 doesn't bundle Linux kernel symbols, and `--offline` blocks fetching.
```powershell
vol -f "$ROOT\images\memdump.mem" banners.Banners      # get the exact kernel
# build kernel.json with dwarf2json from the matching vmlinux / -dbg package, then:
New-Item -ItemType Directory -Force "$ROOT\symbols\linux" | Out-Null
copy kernel.json "$ROOT\symbols\linux\"
```
Re-run from **▸ Run Volatility**; the **☰ Activity** drawer shows each command's
exit code and the real failure reason.

## Notes

- `$env:` variables last only for the current PowerShell window — set them (or run
  `start.ps1`) every session.
- PowerShell 5 has no `&&`; keep commands on separate lines.
- Offline analysis (drag-and-drop CSVs) needs no backend at all — the detection
  engine runs in the browser.

## Dev mode (hot reload, optional)

Two terminals:
```powershell
# terminal 1
cd "$ROOT\backend"; .\.venv\Scripts\Activate.ps1; python run.py
```
```powershell
# terminal 2
cd "$ROOT\frontend"; npm install; npm run dev      # Vite proxies /api to :8799
```
