# Volatility 3 Command Reference — DumpHound

A working DFIR command set for Linux (primary) and Windows memory images, plus
exactly which CSV outputs feed each panel of the workbench.

All commands assume Volatility 3 (`vol`/`vol3`). Global flags worth standardizing:

```
vol -f <image> -r csv -q [-s <symbol_dir>] [--offline] <plugin> [plugin-args]
```

- `-r csv` — CSV renderer (what this app ingests). Use `-r pretty` for the console.
- `-q` — quiet (suppress the progress bar; keeps CSV clean).
- `-s <dir>` — local ISF/symbol cache (set this for air-gapped work).
- `--offline` — never touch the network for symbols.

> Column headers vary slightly between Volatility versions. The workbench
> **infers plugin type from the CSV header row**, not the filename, so minor
> differences are tolerated. Running plugins *through the app* (the Run panel)
> removes any ambiguity because the app already knows which plugin it invoked.

---

## 1. Triage — establish the process landscape

```bash
# Process tree with parent/child lineage  → Process Graph
vol -f mem.lime -r csv -q linux.pstree.PsTree            > pstree.csv

# Flat process list (offsets, threads)
vol -f mem.lime -r csv -q linux.pslist.PsList            > pslist.csv

# Process list WITH full argv (command lines) → enriches the tree/inspector
vol -f mem.lime -r csv -q linux.psaux.PsAux              > psaux.csv

# Carve processes from memory structures (catches unlinked/hidden procs)
vol -f mem.lime -r csv -q linux.pslist.PsList --pid 0    # (psscan equivalent varies by build)
```

Windows equivalents:

```bash
vol -f mem.raw -r csv -q windows.pstree.PsTree           > pstree.csv
vol -f mem.raw -r csv -q windows.pslist.PsList           > pslist.csv
vol -f mem.raw -r csv -q windows.psscan.PsScan           > psscan.csv   # unlinked procs
vol -f mem.raw -r csv -q windows.cmdline.CmdLine         > cmdline.csv  # argv → inspector
```

## 2. Per-process context — what each process was doing

```bash
# Shell history (timeline of typed commands) → Inspector timeline + command rules
vol -f mem.lime -r csv -q linux.bash.Bash                > bash.csv

# Open files / sockets / fds                  → Inspector "open files"
vol -f mem.lime -r csv -q linux.lsof.Lsof                > lsof.csv

# Network sockets + states                    → Inspector "sockets" + network rules
vol -f mem.lime -r csv -q linux.sockstat.Sockstat        > sockstat.csv

# Environment variables (LD_PRELOAD, etc.)    → Inspector "environment"
vol -f mem.lime -r csv -q linux.envars.Envars            > envars.csv

# Loaded libraries / proc maps (injection hunting)
vol -f mem.lime -r csv -q linux.library_list.LibraryList > libs.csv
vol -f mem.lime -r csv -q linux.proc.Maps                > maps.csv
```

## 3. Defense-evasion & injection

```bash
# Injected / RWX / shellcode regions          → malfind rules (rwx_region)
vol -f mem.lime -r csv -q linux.malware.malfind.Malfind          > malfind.csv

# Process name / argv / deleted-exe spoofing   → spoofing rules (comm_spoofed, exe_deleted)
vol -f mem.lime -r csv -q linux.malware.process_spoofing.Process_spoofing > spoof.csv
```

Windows:

```bash
vol -f mem.raw -r csv -q windows.malfind.Malfind         > malfind.csv
vol -f mem.raw -r csv -q windows.netscan.NetScan         > netscan.csv
```

## 4. Rootkit / kernel-integrity hunting → Modules & Rootkits panel

```bash
# Loaded kernel modules (lsmod view, taint flags) → modules (oot/unsigned/taint)
vol -f mem.lime -r csv -q linux.lsmod.Lsmod                       > lsmod.csv

# Modules present in memory but UNLINKED from the module list → hidden_module (alert)
vol -f mem.lime -r csv -q linux.malware.hidden_modules.Hidden_modules > hidden_modules.csv

# lsmod-vs-sysfs discrepancy (another hidden-module angle)
vol -f mem.lime -r csv -q linux.malware.check_modules.Check_modules   > check_modules.csv

# Syscall-table integrity — handlers that don't resolve = hooked → hooked_syscall (alert)
vol -f mem.lime -r csv -q linux.malware.check_syscall.Check_syscall   > check_syscall.csv
```

## 5. Page-cache analysis & file recovery → File Cache panel

```bash
# Enumerate every file resident in the page cache  → File Cache table + scoring
vol -f mem.lime -r csv -q linux.pagecache.Files                  > pagecache.csv

# Dump ONE cached file. --inode takes the InodeAddr (hex address), NOT InodeNum.
vol -f mem.lime linux.pagecache.InodePages --inode 0x88c1a2b40000 --dump

# Bulk reconstruct the cached filesystem tree
vol -o ./recovered -f mem.lime linux.pagecache.RecoverFs
```

> **The single most common dump mistake:** passing the *inode number* to
> `--inode`. It must be the **InodeAddr** column (e.g. `0x88c1a2b40000`). The
> File Cache panel's DUMP button always generates the address form for you.
> When `CachedPages < InodePages`, only part of the file was resident — the dump
> is zero-padded over the missing pages (the panel flags these rows).

---

## CSV → panel mapping (what to load to light up each view)

| Panel / feature | Plugin(s) | Header signature the app keys on | Key columns used |
|---|---|---|---|
| **Process Graph (tree)** | `linux.pstree.PsTree`, `linux.psaux.PsAux` | has `PID` + (`COMM`/`Process`/`Name`) | PID, PPID, COMM, Args |
| Inspector → history | `linux.bash.Bash` | has `Command` + `CommandTime` | PID, Command, CommandTime |
| Inspector → sockets | `linux.sockstat.Sockstat` | has `Proto`/`Protocol` + `State` | PID, Proto, State, addrs |
| Inspector → open files | `linux.lsof.Lsof` | has `PID` + `FD` + `Path` | PID, FD, Path |
| Inspector → environment | `linux.envars.Envars` | has `PID` + `Key` + `Value` | PID, Key, Value |
| Inspector → malfind | `linux.malware.malfind.Malfind` | has `PID` + `Protection` + (`Disasm`/`Hexdump`) | PID, Protection, Address |
| Inspector → spoofing | `linux.malware.process_spoofing.Process_spoofing` | has `comm_spoofed`/`exe_deleted` | spoof flags |
| **File Cache** | `linux.pagecache.Files` | has `FilePath` + (`InodeAddr`/`InodeNum`), no `PID` | FilePath, InodeAddr, InodePages, CachedPages, FileMode, MountPoint, FileType |
| **Modules & Rootkits → modules** | `linux.lsmod.Lsmod` | has `Module Name` / (`Name`+`Taints`/`Status`) | Name, Status, Taints, Address |
| Modules → hidden | `linux.malware.hidden_modules.Hidden_modules` | `Name`+`Address`/`Size`, no `Taints`/`PID` | Name, Address, Size (all rows flagged hidden) |
| Modules → syscall integrity | `linux.malware.check_syscall.Check_syscall` | has `Index` + (`Symbol`/`Handler Address`), no `PID` | Index, Symbol, Handler |

### Minimum set to exercise the whole app

```bash
vol -f mem.lime -r csv -q linux.pstree.PsTree                          > pstree.csv
vol -f mem.lime -r csv -q linux.bash.Bash                             > bash.csv
vol -f mem.lime -r csv -q linux.lsof.Lsof                             > lsof.csv
vol -f mem.lime -r csv -q linux.sockstat.Sockstat                    > sockstat.csv
vol -f mem.lime -r csv -q linux.pagecache.Files                      > pagecache.csv
vol -f mem.lime -r csv -q linux.lsmod.Lsmod                          > lsmod.csv
vol -f mem.lime -r csv -q linux.malware.hidden_modules.Hidden_modules > hidden_modules.csv
vol -f mem.lime -r csv -q linux.malware.check_syscall.Check_syscall   > check_syscall.csv
```

Drop all eight onto the **Process Graph** page (or run them from the **Run
Volatility** panel) — the tree, inspector, file-cache scoring, and rootkit views
populate automatically.
