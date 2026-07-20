// FileCache: linux.pagecache.Files explorer. Forensic severity per file (from
// the detection engine), Excel-style cascading per-column filter popups, and
// per-row DUMP command generation (InodePages --inode <InodeAddr>).
<<<<<<< HEAD
import { useMemo } from "react";
import { useAppStore } from "@/stores/app.store";
import { DataTable, type Column } from "@/components/common/DataTable";
=======
import { useEffect, useMemo, useRef, useState } from "react";
import { useAppStore } from "@/stores/app.store";
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
import { copyText, LevelBadge, MitreLinks, pushToast } from "@/components/common";
import { dumpCommand, exportDumpScript } from "@/services/export.service";
import type { FindingLevel, PagecacheFile } from "@/models";

<<<<<<< HEAD
const rank: Record<FindingLevel, number> = { alert: 3, warn: 2, info: 1 };

=======
type Col = {
  id: keyof PagecacheFile | "severity";
  label: string;
  mono?: boolean;
};

const COLUMNS: Col[] = [
  { id: "severity", label: "Sev" },
  { id: "filePath", label: "FilePath", mono: true },
  { id: "fileType", label: "Type" },
  { id: "mountPoint", label: "Mount", mono: true },
  { id: "inodeAddr", label: "InodeAddr", mono: true },
  { id: "inodePages", label: "Pages" },
  { id: "cachedPages", label: "Cached" },
  { id: "fileMode", label: "Mode", mono: true },
];

const rank: Record<FindingLevel, number> = { alert: 3, warn: 2, info: 1 };

function cellValue(f: PagecacheFile, col: Col, sev?: FindingLevel): string {
  if (col.id === "severity") return sev ?? "";
  const v = f[col.id as keyof PagecacheFile];
  return v == null ? "" : String(v);
}

/** Parse an Excel-style expression filter against a cell value. */
function exprMatch(value: string, expr: string): boolean {
  const terms = expr.trim().split(/\s+/).filter(Boolean);
  if (!terms.length) return true;
  const v = value.toLowerCase();
  return terms.every((t) => {
    if (t.startsWith("=")) return v === t.slice(1).toLowerCase();
    const range = t.match(/^(-?\d+)\.\.(-?\d+)$/);
    if (range) {
      const n = Number(value);
      return !Number.isNaN(n) && n >= Number(range[1]) && n <= Number(range[2]);
    }
    const cmp = t.match(/^(>=|<=|>|<)(-?\d+(?:\.\d+)?)$/);
    if (cmp) {
      const n = Number(value);
      if (Number.isNaN(n)) return false;
      const x = Number(cmp[2]);
      return cmp[1] === ">"
        ? n > x
        : cmp[1] === "<"
          ? n < x
          : cmp[1] === ">="
            ? n >= x
            : n <= x;
    }
    return v.includes(t.toLowerCase());
  });
}

>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
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

<<<<<<< HEAD
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
=======
  const [exprFilter, setExprFilter] = useState<Record<string, string>>({});
  const [valueFilter, setValueFilter] = useState<Record<string, Set<string>>>({});
  const [popCol, setPopCol] = useState<string | null>(null);
  const popRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (popRef.current && !popRef.current.contains(e.target as Node)) setPopCol(null);
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, []);

  const sevOf = (f: PagecacheFile) => sevByPath.get(f.filePath)?.level;

  // Apply all filters EXCEPT the given column (for cascading popup options).
  const applyFilters = (rows: PagecacheFile[], exceptCol?: string): PagecacheFile[] =>
    rows.filter((f) => {
      const sev = sevOf(f);
      for (const col of COLUMNS) {
        if (col.id === exceptCol) continue;
        const val = cellValue(f, col, sev);
        const expr = exprFilter[col.id];
        if (expr && !exprMatch(val, expr)) return false;
        const set = valueFilter[col.id];
        if (set && set.size && !set.has(val)) return false;
      }
      return true;
    });

  const visible = useMemo(
    () => applyFilters(pagecache),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [pagecache, exprFilter, valueFilter, sevByPath]
  );

  // Distinct values for the open popup column, reflecting other active filters.
  const popupOptions = useMemo(() => {
    if (!popCol) return [];
    const col = COLUMNS.find((c) => c.id === popCol)!;
    const subset = applyFilters(pagecache, popCol);
    const counts = new Map<string, number>();
    for (const f of subset) {
      const v = cellValue(f, col, sevOf(f));
      counts.set(v, (counts.get(v) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [popCol, pagecache, exprFilter, valueFilter, sevByPath]);

  const [popSearch, setPopSearch] = useState("");

  const toggleValue = (colId: string, value: string) => {
    setValueFilter((prev) => {
      const next = { ...prev };
      const set = new Set(next[colId] ?? []);
      if (set.has(value)) set.delete(value);
      else set.add(value);
      if (set.size) next[colId] = set;
      else delete next[colId];
      return next;
    });
  };

  const clearColumn = (colId: string) => {
    setValueFilter((prev) => {
      const next = { ...prev };
      delete next[colId];
      return next;
    });
    setExprFilter((prev) => {
      const next = { ...prev };
      delete next[colId];
      return next;
    });
  };

  const onDump = async (f: PagecacheFile) => {
    const cmd = dumpCommand(f, image);
    const ok = await copyText(cmd);
    if (ok) pushToast("Dump command copied to clipboard", "ok");
    else pushToast("Copy blocked — command shown below, copy manually", "warn");
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
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
<<<<<<< HEAD
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
=======
      <div className="fc-toolbar">
        <span className="fc-count">
          {visible.length} / {pagecache.length} files
        </span>
        <div className="spacer" />
        <button className="btn" onClick={() => exportDumpScript(visible, image)}>
          Export dump script ({visible.length})
        </button>
        <button
          className="btn btn-ghost"
          onClick={() => {
            setExprFilter({});
            setValueFilter({});
          }}
        >
          Clear filters
        </button>
      </div>

      <div className="fc-table-wrap">
        <table className="fc-table">
          <thead>
            <tr>
              {COLUMNS.map((col) => {
                const active = !!valueFilter[col.id]?.size || !!exprFilter[col.id];
                return (
                  <th key={col.id}>
                    <div className="fc-th">
                      <span>{col.label}</span>
                      <button
                        className={`funnel${active ? " funnel-active" : ""}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          setPopSearch("");
                          setPopCol(popCol === col.id ? null : col.id);
                        }}
                        title="Filter column"
                      >
                        ▾
                      </button>
                    </div>
                    {popCol === col.id && (
                      <div className="fc-popup" ref={popRef}>
                        <input
                          className="fc-popup-search"
                          placeholder="Search values…"
                          value={popSearch}
                          autoFocus
                          onChange={(e) => setPopSearch(e.target.value)}
                        />
                        <input
                          className="fc-popup-expr"
                          placeholder="Expression (e.g. >1000, =alert, tmp)"
                          value={exprFilter[col.id] ?? ""}
                          onChange={(e) =>
                            setExprFilter((prev) => ({ ...prev, [col.id]: e.target.value }))
                          }
                        />
                        <div className="fc-popup-list">
                          {popupOptions
                            .filter(([v]) =>
                              v.toLowerCase().includes(popSearch.toLowerCase())
                            )
                            .slice(0, 200)
                            .map(([v, n]) => {
                              const checked =
                                !valueFilter[col.id]?.size || valueFilter[col.id]?.has(v);
                              return (
                                <label key={v || "∅"} className="fc-popup-item">
                                  <input
                                    type="checkbox"
                                    checked={!!checked}
                                    onChange={() => toggleValue(col.id, v)}
                                  />
                                  <span className="fc-popup-val">{v || "∅ (empty)"}</span>
                                  <span className="fc-popup-num">{n}</span>
                                </label>
                              );
                            })}
                        </div>
                        <div className="fc-popup-actions">
                          <button className="btn btn-sm" onClick={() => clearColumn(col.id)}>
                            Clear
                          </button>
                          <button className="btn btn-sm" onClick={() => setPopCol(null)}>
                            Close
                          </button>
                        </div>
                      </div>
                    )}
                  </th>
                );
              })}
              <th>Dump</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((f, i) => {
              const sev = sevByPath.get(f.filePath);
              const total = Number(f.inodePages) || 0;
              const cached = Number(f.cachedPages) || 0;
              const partial = !!total && !!cached && cached < total;
              const ratio = total > 0 ? Math.min(cached / total, 1) : cached > 0 ? 1 : 0;
              const covClass =
                ratio >= 1 ? "cov-full" : ratio > 0 ? "cov-partial" : "cov-none";
              return (
                <tr key={i} className={sev ? `fc-row-${sev.level}` : ""}>
                  <td>
                    {sev ? (
                      <span className="sev-cell">
                        <LevelBadge level={sev.level} />
                        <MitreLinks technique={sev.technique} />
                      </span>
                    ) : (
                      <span className="sev-none">·</span>
                    )}
                  </td>
                  <td className="fc-path" title={f.filePath}>
                    {f.filePath}
                  </td>
                  <td>
                    {f.fileType ? <span className="fc-type">{f.fileType}</span> : null}
                  </td>
                  <td className="mono dim">{f.mountPoint}</td>
                  <td className="mono dim">{f.inodeAddr}</td>
                  <td className="num">{f.inodePages}</td>
                  <td
                    className="fc-cov-cell"
                    title={
                      partial
                        ? `Partial cache (${cached}/${total} pages) — dump will be zero-padded`
                        : `${cached}/${total} pages cached`
                    }
                  >
                    <div className="cov">
                      <div className="cov-track">
                        <span
                          className={`cov-fill ${covClass}`}
                          style={{ width: `${ratio * 100}%` }}
                        />
                      </div>
                      <span className="cov-num">
                        {f.cachedPages}
                        {partial ? " ⚠" : ""}
                      </span>
                    </div>
                  </td>
                  <td className="mono dim">{f.fileMode}</td>
                  <td>
                    <button
                      className="dumpbtn"
                      onClick={() => onDump(f)}
                      title={dumpCommand(f, image)}
                    >
                      DUMP
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
    </div>
  );
}
