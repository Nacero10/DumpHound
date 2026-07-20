// FileCache: linux.pagecache.Files explorer. Forensic severity per file (from
// the detection engine), Excel-style cascading per-column filter popups, and
// per-row DUMP command generation (InodePages --inode <InodeAddr>).
import { useMemo } from "react";
import { useAppStore } from "@/stores/app.store";
import { DataTable, type Column } from "@/components/common/DataTable";
import { copyText, LevelBadge, MitreLinks, pushToast } from "@/components/common";
import { dumpCommand, exportDumpScript } from "@/services/export.service";
import type { FindingLevel, PagecacheFile } from "@/models";

const rank: Record<FindingLevel, number> = { alert: 3, warn: 2, info: 1 };

export function FileCache() {
  const pagecache = useAppStore((s) => s.pagecache);
  const findings = useAppStore((s) => s.findings);
  const image = useAppStore((s) => s.image);

  // Map filePath -> worst severity + technique (from pagecache findings).
  const sevByPath = useMemo(() => {
    const map = new Map<string, { level: FindingLevel; technique?: string }>();
    for (const f of findings) {
      const cur = map.get(f.target);
      if (!cur || rank[f.level] > rank[cur.level]) {
        map.set(f.target, { level: f.level, technique: f.technique });
      }
    }
    return map;
  }, [findings]);

  const columns: Column<PagecacheFile>[] = useMemo(
    () => [
      {
        id: "severity",
        label: "Sev",
        width: "90px",
        getValue: (f) => sevByPath.get(f.filePath)?.level ?? "",
        render: (f) => {
          const sev = sevByPath.get(f.filePath);
          return sev ? (
            <span className="sev-cell">
              <LevelBadge level={sev.level} />
              <MitreLinks technique={sev.technique} />
            </span>
          ) : (
            <span className="sev-none">·</span>
          );
        },
      },
      {
        id: "filePath",
        label: "FilePath",
        width: "320px",
        mono: true,
        getValue: (f) => f.filePath,
        render: (f) => (
          <span className="fc-path" title={f.filePath}>
            {f.filePath}
          </span>
        ),
      },
      {
        id: "fileType",
        label: "Type",
        width: "80px",
        getValue: (f) => f.fileType ?? "",
        render: (f) =>
          f.fileType ? <span className="fc-type">{f.fileType}</span> : null,
      },
      {
        id: "mountPoint",
        label: "Mount",
        width: "100px",
        mono: true,
        getValue: (f) => f.mountPoint ?? "",
        render: (f) => <span className="dim">{f.mountPoint}</span>,
      },
      {
        id: "inodeAddr",
        label: "InodeAddr",
        width: "110px",
        mono: true,
        getValue: (f) => f.inodeAddr ?? "",
        render: (f) => <span className="dim">{f.inodeAddr}</span>,
      },
      { id: "inodePages", label: "Pages", width: "70px", getValue: (f) => String(f.inodePages ?? "") },
      {
        id: "cachedPages",
        label: "Cached",
        width: "130px",
        getValue: (f) => `${f.cachedPages ?? 0}/${f.inodePages ?? 0}`,
        render: (f) => {
          const total = Number(f.inodePages) || 0;
          const cached = Number(f.cachedPages) || 0;
          const partial = !!total && !!cached && cached < total;
          const ratio = total > 0 ? Math.min(cached / total, 1) : cached > 0 ? 1 : 0;
          const covClass = ratio >= 1 ? "cov-full" : ratio > 0 ? "cov-partial" : "cov-none";
          return (
            <div className="cov" title={partial ? `Partial cache — dump will be zero-padded` : `${cached}/${total} pages cached`}>
              <div className="cov-track">
                <span className={`cov-fill ${covClass}`} style={{ width: `${ratio * 100}%` }} />
              </div>
              <span className="cov-num">
                {f.cachedPages}
                {partial ? " ⚠" : ""}
              </span>
            </div>
          );
        },
      },
      {
        id: "fileMode",
        label: "Mode",
        width: "70px",
        mono: true,
        getValue: (f) => f.fileMode ?? "",
        render: (f) => <span className="dim">{f.fileMode}</span>,
      },
      {
        id: "dump",
        label: "Dump",
        width: "70px",
        sortable: false,
        getValue: () => "",
        render: (f) => (
          <button
            className="dumpbtn"
            onClick={(e) => {
              e.stopPropagation();
              const cmd = dumpCommand(f, image);
              copyText(cmd).then((ok) =>
                pushToast(ok ? "Dump command copied" : "Copy blocked — copy manually", ok ? "ok" : "warn")
              );
            }}
            title={dumpCommand(f, image)}
          >
            DUMP
          </button>
        ),
      },
    ],
    [sevByPath, image]
  );

  const rowClass = (f: PagecacheFile) => {
    const sev = sevByPath.get(f.filePath)?.level;
    return sev ? `fc-row-${sev}` : "";
  };

  if (!pagecache.length) {
    return (
      <div className="filecache-empty">
        Load a <code>linux.pagecache.Files</code> CSV to populate the file-cache explorer.
      </div>
    );
  }

  return (
    <div className="filecache">
      <DataTable
        columns={columns}
        rows={pagecache}
        rowKey={(f, i) => `${f.filePath}-${i}`}
        rowClass={rowClass}
        searchPlaceholder="Search file path, type, mount, mode…"
        maxHeight="65vh"
        toolbar={
          <>
            <button className="btn" onClick={() => exportDumpScript(pagecache, image)}>
              Export dump script
            </button>
          </>
        }
      />
    </div>
  );
}
