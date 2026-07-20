# DumpHound — Component Diagram

Full architecture: React SPA, FastAPI service tiers, and the data-driven
detection rule store shared by both ends.

```mermaid
flowchart TB
    subgraph Browser["Browser — React SPA (Vite / TypeScript)"]
        direction TB
        UI["Pages & Components<br/>WorkbenchPage · ProcessTree(D3)<br/>Inspector · Dashboard · FileCache · Modules"]
        StoreZ["AppStore (Zustand)"]
        RQ["React Query hooks"]
        SvcP["parser.service"]
        SvcD["detection.service"]
        SvcE["export.service"]
        ApiC["api/client (typed fetch)"]
        UI --> StoreZ
        UI --> RQ
        StoreZ --> SvcP
        StoreZ --> SvcD
        UI --> SvcE
        RQ --> ApiC
    end

    subgraph Edge["Reverse Proxy (nginx)"]
        NX["TLS · rate-limit · SSE buffering off<br/>static assets · /api → backend"]
    end

    subgraph Backend["FastAPI Service"]
        direction TB
        MW["Middleware<br/>RequestContext · RateLimit · CORS · error envelope"]
        subgraph APIRouters["API Routers (/api)"]
            RH["health"]
            RI["images"]
            RP["plugins (run · detect)"]
            RJ["jobs (inode · recoverfs · stream)"]
            RD["dumps (download)"]
        end
        subgraph Services["Service Layer"]
            SV["VolatilityService"]
            SJ["JobService"]
            SA["ArtifactService"]
            SDmp["DumpService"]
            SDet["DetectionService"]
        end
        subgraph Repos["Repositories"]
            RJobs["JobRepository"]
            RArt["ArtifactRepository"]
        end
        subgraph Core["Core"]
            CFG["config (Settings)"]
            SECU["security · validators"]
            LOG["structured logging · audit"]
            DI["container (DI)"]
        end
        MW --> APIRouters
        APIRouters --> Services
        SJ --> RJobs
        SA --> RArt
        SDmp --> SV
        SDmp --> SA
        SDet --> RULES
        Services --> SECU
        DI --> Services
    end

    subgraph External["Host / Tooling"]
        VOL["Volatility 3 CLI"]
        IMG[("Memory images<br/>VOL_IMAGE_DIR")]
        OUT[("Dumped artifacts<br/>VOL_OUTPUT_DIR")]
    end

    RULES[("Detection rules<br/>linux.json · windows.json · mitre.json")]

    Browser -->|HTTPS| Edge
    Edge -->|/api| MW
    Edge -->|static| Browser
    SV -->|subprocess argv| VOL
    VOL --> IMG
    SDmp --> OUT
    RD --> OUT
    SvcD -. fetch /rules .-> RULES
    SDet -. load .-> RULES
```

## Tier responsibilities

| Tier | Responsibility |
|---|---|
| React SPA | Ingest CSVs, correlate, render tree, run client-side detection, export |
| nginx | TLS termination, static serving, rate limiting, disables SSE buffering |
| API routers | Thin HTTP adapters; validation + delegation only |
| Services | All business logic; `VolatilityService` is the sole subprocess caller |
| Repositories | In-memory persistence for jobs and artifacts |
| Core | Config, security guards, DI container, structured + audit logging |
| Rules store | Data-driven ATT&CK detection rules shared by client and server |
