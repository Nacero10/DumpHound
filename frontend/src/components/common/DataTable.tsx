import { useMemo, useState, useRef, useEffect, useCallback } from "react";

export type SortDir = "asc" | "desc";
export interface SortState { key: string; dir: SortDir }

export interface Column<T> {
  id: string;
  label: string;
  width?: string;
  mono?: boolean;
  wrap?: boolean;
  sortable?: boolean;
  /** Return the raw string value for filtering */
  getValue?: (row: T) => string;
  /** Custom render cell */
  render?: (row: T, index: number) => React.ReactNode;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  rowClass?: (row: T, index: number) => string;
  onRowClick?: (row: T, index: number) => void;
  searchPlaceholder?: string;
  toolbar?: React.ReactNode;
  emptyMessage?: string;
  maxHeight?: string;
  /** Default page size. Use 0 for "all" (no pagination). */
  defaultPageSize?: number;
  /** Show a # column with the original row index */
  showRowNumbers?: boolean;
}

/* ── helpers ── */

function normalize(v: unknown): string {
  if (v == null) return "";
  return String(v).toLowerCase();
}

function numFromCell(v: unknown): number {
  if (v == null) return NaN;
  const s = String(v).trim().replace(/[,\s]/g, (c) => (c === "," ? "." : ""));
  const n = parseFloat(s);
  return n;
}

/**
 * Compile a filter query string into a predicate function.
 * Supports:
 *   • Range:       10..20
 *   • Operators:   >100, >=50, <10, <=5, =alert, !=0
 *   • Contains:    space-separated terms (AND)
 */
function compileFilter(query: string): ((value: string) => boolean) | null {
  const q = String(query || "").trim();
  if (!q) return null;

  // Range: 10..20
  const rangeMatch = q.match(/^(-?\d+(?:[.,]\d+)?)\.\.(-?\d+(?:[.,]\d+)?)$/);
  if (rangeMatch) {
    const lo = parseFloat(rangeMatch[1].replace(",", "."));
    const hi = parseFloat(rangeMatch[2].replace(",", "."));
    return (cell) => {
      const n = numFromCell(cell);
      return !isNaN(n) && n >= lo && n <= hi;
    };
  }

  // Operator: >=, <=, !=, >, <, =
  const opMatch = q.match(/^(>=|<=|!=|>|<|=)\s*(.+)$/);
  if (opMatch) {
    const op = opMatch[1];
    const val = opMatch[2].trim();
    const asNum = parseFloat(val.replace(",", "."));
    const isNum = !isNaN(asNum) && /^-?\d+(?:[.,]\d+)?$/.test(val);
    return (cell) => {
      if (isNum) {
        const n = numFromCell(cell);
        if (isNaN(n)) return false;
        switch (op) {
          case ">": return n > asNum;
          case "<": return n < asNum;
          case ">=": return n >= asNum;
          case "<=": return n <= asNum;
          case "=": return n === asNum;
          case "!=": return n !== asNum;
        }
      }
      const cellL = String(cell == null ? "" : cell).toLowerCase();
      const valL = val.toLowerCase();
      switch (op) {
        case "=": return cellL === valL;
        case "!=": return cellL !== valL;
        default: return false;
      }
    };
  }

  // Multi-term contains (AND)
  const terms = q.toLowerCase().split(/\s+/).filter(Boolean);
  return (cell) => {
    const s = String(cell == null ? "" : cell).toLowerCase();
    return terms.every((t) => s.includes(t));
  };
}

/** Optimised global search: joins all column values once per row. */
function compileGlobalFilter<T>(columns: Column<T>[], query: string): ((row: T) => boolean) | null {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return null;
  const terms = q.split(/\s+/).filter(Boolean);
  return (row) => {
    const s = columns
      .map((c) => (c.getValue ? c.getValue(row) : normalize((row as Record<string, unknown>)[c.id])))
      .join("\u0001");
    return terms.every((t) => s.includes(t));
  };
}

/** Detect whether a column is numeric by sampling values. */
function isNumericColumn<T>(rows: T[], col: Column<T>, indices: number[]): boolean {
  const numRe = /^-?\d+(?:[.,]\d+)?$/;
  const sampleSize = Math.min(indices.length, 200);
  let numericCount = 0;
  for (let i = 0; i < sampleSize; i++) {
    const row = rows[indices[i]];
    const v = col.getValue ? col.getValue(row) : String((row as Record<string, unknown>)[col.id] ?? "");
    if (v != null && numRe.test(String(v).trim())) numericCount++;
  }
  return sampleSize > 0 && numericCount / sampleSize > 0.6;
}

const PAGE_SIZE_OPTIONS = [50, 100, 250, 500, 1000, 0]; // 0 = all

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  rowClass,
  onRowClick,
  searchPlaceholder = "Search all columns…",
  toolbar,
  emptyMessage = "No rows to display.",
  maxHeight = "60vh",
  defaultPageSize = 100,
  showRowNumbers = true,
}: DataTableProps<T>) {
  const [globalFilter, setGlobalFilter] = useState("");
  const [colFilter, setColFilter] = useState<Record<string, string>>({});
  const [sort, setSort] = useState<SortState | null>(null);
  const [popCol, setPopCol] = useState<string | null>(null);
  const [popSearch, setPopSearch] = useState("");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(defaultPageSize);
  const popRef = useRef<HTMLDivElement | null>(null);
  const isDragging = useRef(false);
  const dragOffset = useRef({ x: 0, y: 0 });

  // ── popup drag ──
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!isDragging.current || !popRef.current) return;
      const nx = e.clientX - dragOffset.current.x;
      const ny = e.clientY - dragOffset.current.y;
      popRef.current.style.left = `${Math.max(0, nx)}px`;
      popRef.current.style.top = `${Math.max(0, ny)}px`;
    };
    const onUp = () => {
      isDragging.current = false;
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
    return () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };
  }, []);

  const startDrag = (e: React.MouseEvent) => {
    if (!popRef.current) return;
    const rect = popRef.current.getBoundingClientRect();
    dragOffset.current = {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    };
    isDragging.current = true;
  };

  // Close popup on outside click / Escape
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (popRef.current && !popRef.current.contains(e.target as Node)) setPopCol(null);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPopCol(null);
    };
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, []);

  const toggleSort = useCallback((key: string) => {
    setSort((prev) => {
      if (!prev || prev.key !== key) return { key, dir: "asc" };
      if (prev.dir === "asc") return { key, dir: "desc" };
      return null;
    });
    setPage(0);
  }, []);

  // ── filtering (compiled) ──
  const filtered = useMemo(() => {
    const colFns = columns.map((c) => compileFilter(colFilter[c.id] ?? ""));
    const globalFn = compileGlobalFilter(columns, globalFilter);

    const indices: number[] = [];
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      let ok = true;
      for (let c = 0; c < colFns.length; c++) {
        const fn = colFns[c];
        if (!fn) continue;
        const col = columns[c];
        const val = col.getValue ? col.getValue(row) : String((row as Record<string, unknown>)[col.id] ?? "");
        if (!fn(val)) { ok = false; break; }
      }
      if (ok && globalFn && !globalFn(row)) ok = false;
      if (ok) indices.push(i);
    }
    return indices;
  }, [rows, columns, colFilter, globalFilter]);

  // ── sorting (smart numeric detection) ──
  const sortedIndices = useMemo(() => {
    const indices = [...filtered];
    if (sort) {
      const col = columns.find((c) => c.id === sort.key);
      if (col) {
        const isNumeric = isNumericColumn(rows, col, indices);
        const dir = sort.dir === "asc" ? 1 : -1;
        indices.sort((a, b) => {
          const va = col.getValue ? col.getValue(rows[a]) : String((rows[a] as Record<string, unknown>)[col.id] ?? "");
          const vb = col.getValue ? col.getValue(rows[b]) : String((rows[b] as Record<string, unknown>)[col.id] ?? "");
          if (isNumeric) {
            const na = numFromCell(va);
            const nb = numFromCell(vb);
            const aNaN = isNaN(na), bNaN = isNaN(nb);
            if (aNaN && bNaN) return 0;
            if (aNaN) return 1 * dir;
            if (bNaN) return -1 * dir;
            return (na - nb) * dir;
          }
          const sa = String(va == null ? "" : va).toLowerCase();
          const sb = String(vb == null ? "" : vb).toLowerCase();
          return sa.localeCompare(sb, undefined, { numeric: true, sensitivity: "base" }) * dir;
        });
      }
    }
    return indices;
  }, [filtered, sort, rows, columns]);

  // ── pagination ──
  const total = sortedIndices.length;
  const ps = pageSize === 0 ? total : pageSize;
  const maxPage = Math.max(0, Math.ceil(total / ps) - 1);
  const currentPage = Math.min(page, maxPage);
  const start = currentPage * ps;
  const end = Math.min(total, start + ps);
  const pageIndices = sortedIndices.slice(start, end);

  // Reset page when filters change
  useEffect(() => {
    setPage(0);
  }, [globalFilter, colFilter, sort]);

  // ── popup options ──
  const popupOptions = useMemo(() => {
    if (!popCol) return [];
    const col = columns.find((c) => c.id === popCol);
    if (!col) return [];
    const counts = new Map<string, number>();
    for (const idx of filtered) {
      const row = rows[idx];
      const v = normalize(col.getValue ? col.getValue(row) : (row as Record<string, unknown>)[col.id]);
      counts.set(v, (counts.get(v) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [popCol, columns, filtered, rows]);

  const handleFunnelClick = (colId: string, e: React.MouseEvent<HTMLButtonElement>) => {
    const rect = (e.target as HTMLElement).getBoundingClientRect();
    const x = Math.min(rect.left, window.innerWidth - 280);
    const y = rect.bottom + 4;
    if (popRef.current) {
      popRef.current.style.left = `${x}px`;
      popRef.current.style.top = `${y}px`;
    }
    setPopSearch("");
    setPopCol(popCol === colId ? null : colId);
  };

  const clearColFilter = (colId: string) => {
    setColFilter((prev) => {
      const next = { ...prev };
      delete next[colId];
      return next;
    });
  };

  const hasAnyFilter = globalFilter || Object.keys(colFilter).length;

  const sortIndicator = (colId: string) => {
    if (!sort || sort.key !== colId) return "↕";
    return sort.dir === "asc" ? "↑" : "↓";
  };

  return (
    <div className="dt-root">
      {/* toolbar */}
      <div className="dt-toolbar">
        <div className="search dt-global">
          <span className="dt-search-glyph">⌕</span>
          <input
            type="text"
            placeholder={searchPlaceholder}
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            autoComplete="off"
          />
        </div>
        <span className="dt-count">
          {total.toLocaleString()} / {rows.length.toLocaleString()}
        </span>
        <div className="spacer" />
        {toolbar}
        {hasAnyFilter && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => {
              setGlobalFilter("");
              setColFilter({});
              setSort(null);
              setPage(0);
            }}
          >
            Clear
          </button>
        )}
      </div>

      {/* table */}
      <div className="dt-scroll-wrap" style={{ maxHeight }}>
        <table className="dt-table">
          <thead>
            {/* header row + sort */}
            <tr>
              {showRowNumbers && <th className="dt-rownum">#</th>}
              {columns.map((col) => {
                const sorted = sort?.key === col.id;
                return (
                  <th key={col.id} style={{ width: col.width }}>
                    <div className="dt-th">
                      <button
                        className={`dt-sort${sorted ? " dt-sort-active" : ""}`}
                        onClick={() => col.sortable !== false && toggleSort(col.id)}
                        disabled={col.sortable === false}
                      >
                        {col.label}
                        <span className="dt-sort-ind">{sortIndicator(col.id)}</span>
                      </button>
                      <button
                        className={`funnel${colFilter[col.id] ? " funnel-active" : ""}`}
                        onClick={(e) => handleFunnelClick(col.id, e)}
                        title="Pick from values"
                      >
                        ▾
                      </button>
                    </div>
                  </th>
                );
              })}
            </tr>
            {/* filter row — inline inputs */}
            <tr className="dt-filter-row">
              {showRowNumbers && <th className="dt-rownum" />}
              {columns.map((col) => (
                <th key={`f-${col.id}`} style={{ width: col.width }}>
                  <input
                    className="dt-filter-input"
                    type="text"
                    placeholder="filter…"
                    value={colFilter[col.id] ?? ""}
                    onChange={(e) => {
                      setColFilter((prev) => {
                        const next = { ...prev };
                        if (e.target.value) next[col.id] = e.target.value;
                        else delete next[col.id];
                        return next;
                      });
                      setPage(0);
                    }}
                    autoComplete="off"
                  />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pageIndices.map((rowIdx) => {
              const row = rows[rowIdx];
              return (
                <tr
                  key={rowKey(row, rowIdx)}
                  className={rowClass ? rowClass(row, rowIdx) : undefined}
                  onClick={() => onRowClick?.(row, rowIdx)}
                  style={onRowClick ? { cursor: "pointer" } : undefined}
                >
                  {showRowNumbers && (
                    <td className="dt-rownum">{(rowIdx + 1).toLocaleString()}</td>
                  )}
                  {columns.map((col) => (
                    <td
                      key={col.id}
                      className={`${col.mono ? "mono" : ""} ${col.wrap ? "wrap" : ""}`}
                    >
                      {col.render
                        ? col.render(row, rowIdx)
                        : String((row as Record<string, unknown>)[col.id] ?? "")}
                    </td>
                  ))}
                </tr>
              );
            })}
            {!pageIndices.length && (
              <tr>
                <td colSpan={columns.length + (showRowNumbers ? 1 : 0)} className="empty-row">
                  {rows.length ? "No rows match the current filters." : emptyMessage}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* pagination */}
      {rows.length > 0 && (
        <div className="dt-pager">
          <div className="dt-pager-left">
            <span>Rows per page</span>
            <select
              value={pageSize}
              onChange={(e) => {
                const v = parseInt(e.target.value, 10);
                setPageSize(isNaN(v) ? 0 : v);
                setPage(0);
              }}
            >
              {PAGE_SIZE_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s === 0 ? "All" : s}
                </option>
              ))}
            </select>
          </div>
          <div className="dt-pager-right">
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setPage((p) => p - 1)}
              disabled={currentPage <= 0 || pageSize === 0}
            >
              ‹ prev
            </button>
            <span className="dt-pageinfo">
              {pageSize === 0 || total === 0
                ? total === 0
                  ? "no matches"
                  : `1–${total} of ${total}`
                : `${start + 1}–${end} of ${total} · page ${currentPage + 1}/${maxPage + 1}`}
            </span>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setPage((p) => p + 1)}
              disabled={pageSize === 0 || end >= total}
            >
              next ›
            </button>
          </div>
        </div>
      )}

      {/* popup — draggable + resizable */}
      {popCol && (
        <div
          className="fc-popup"
          ref={popRef}
          style={{ position: "fixed", zIndex: 100 }}
        >
          {/* drag handle */}
          <div className="fc-popup-drag" onMouseDown={startDrag}>
            <span className="drag-grip">☰</span>
            <span>{columns.find((c) => c.id === popCol)?.label ?? ""}</span>
          </div>

          {/* body */}
          <div className="fc-popup-body">
            <input
              className="fc-popup-search"
              placeholder="Search values…"
              value={popSearch}
              autoFocus
              onChange={(e) => setPopSearch(e.target.value)}
            />
            <input
              className="fc-popup-expr"
              placeholder={`Filter ${columns.find((c) => c.id === popCol)?.label ?? ""}…`}
              value={colFilter[popCol] ?? ""}
              onChange={(e) => {
                setColFilter((prev) => {
                  const next = { ...prev };
                  if (e.target.value) next[popCol] = e.target.value;
                  else delete next[popCol];
                  return next;
                });
                setPage(0);
              }}
            />
            <div className="fc-popup-list">
              {popupOptions
                .filter(([v]) => v.includes(popSearch.toLowerCase()))
                .slice(0, 200)
                .map(([v, n]) => (
                  <button
                    key={v || "∅"}
                    className="fc-popup-item"
                    onClick={() => {
                      setColFilter((prev) => ({ ...prev, [popCol]: v }));
                      setPopCol(null);
                      setPage(0);
                    }}
                  >
                    <span className="fc-popup-val">{v || "∅ (empty)"}</span>
                    <span className="fc-popup-num">{n.toLocaleString()}</span>
                  </button>
                ))}
              {popupOptions.filter(([v]) => v.includes(popSearch.toLowerCase())).length > 200 && (
                <div className="fc-popup-more">
                  … and {popupOptions.filter(([v]) => v.includes(popSearch.toLowerCase())).length - 200} more values
                </div>
              )}
            </div>
            <div className="fc-popup-actions">
              <button className="btn btn-sm" onClick={() => clearColFilter(popCol)}>
                Clear
              </button>
              <button className="btn btn-sm" onClick={() => setPopCol(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
