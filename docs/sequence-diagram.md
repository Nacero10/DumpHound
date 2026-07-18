# ProcTree Platform — Sequence Diagrams

## 1. Offline CSV analysis (primary path)

The analyst drops Volatility CSV exports into the browser. Parsing, correlation,
and detection all run client-side — no image or raw data leaves the machine.

```mermaid
sequenceDiagram
    actor Analyst
    participant DropZone as FileDropZone
    participant Store as AppStore (Zustand)
    participant Parser as parser.service
    participant Engine as DetectionEngine
    participant Rules as /rules/*.json
    participant Tree as ProcessTree (D3)
    participant Dash as Dashboard

    Analyst->>DropZone: drop pslist.csv, bash.csv, pagecache.csv
    DropZone->>Store: ingestFiles(files)
    loop each CSV
        Store->>Parser: parseCsv(text)
        Parser-->>Store: {headers, rows}
        Store->>Parser: classifyPlugin(headers)
        Parser-->>Store: pluginKind
        Store->>Parser: mergeIntoRecords / parsePagecache / parseModules
    end
    Store->>Engine: loadEngine(os)
    Engine->>Rules: fetch linux.json + mitre.json
    Rules-->>Engine: rule sets (cached)
    Store->>Engine: analyze(records, pagecache, modules)
    Engine-->>Store: Finding[]
    Store-->>Tree: roots + flagged PIDs
    Store-->>Dash: findings + counts
    Tree-->>Analyst: severity-coded process tree
    Dash-->>Analyst: ATT&CK-mapped findings table
```

## 2. Live page-cache dump (backend path)

When connected to the backend, the analyst can extract a cached file straight
from the memory image. The job runs asynchronously and yields a secure,
token-addressed download.

```mermaid
sequenceDiagram
    actor Analyst
    participant FileCache
    participant API as api/client
    participant Router as jobs router
    participant Sec as security/validators
    participant Jobs as JobService
    participant Vol as VolatilityService
    participant Dump as DumpService
    participant Art as ArtifactService

    Analyst->>FileCache: click DUMP (InodeAddr)
    FileCache->>API: POST /api/jobs/inode {image, inode}
    API->>Router: request
    Router->>Sec: resolve_image() + validate_inode()
    Sec-->>Router: ok (or 400/403)
    Router->>Jobs: submit("inode", fn)
    Jobs-->>Router: Job(pending)
    Router-->>API: JobResponse(id)
    Jobs->>Dump: dump_inode(image, inode)
    Dump->>Vol: argv [vol -f img InodePages --inode <addr> --dump --offline]
    Vol-->>Dump: dumped file paths
    Dump->>Art: register(path) -> sha256 + token
    Art-->>Jobs: Artifact[]
    loop poll / SSE
        Analyst->>API: GET /api/jobs/{id}
        API-->>Analyst: state + artifacts
    end
    Analyst->>API: GET /api/dumps/download/{token}
    API-->>Analyst: file stream
```
