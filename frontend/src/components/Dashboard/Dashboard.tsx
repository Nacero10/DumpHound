// Dashboard: high-level forensic summary — finding counts by severity, ingested
// sources, and a filterable findings table with export.
import { useMemo, useState } from "react";
import { useAppStore } from "@/stores/app.store";
<<<<<<< HEAD
import { DataTable, type Column } from "@/components/common/DataTable";
import { LevelBadge, MitreLinks } from "@/components/common";
import { exportFindings } from "@/services/export.service";
import type { Finding, FindingLevel } from "@/models";
=======
import { LevelBadge, MitreLinks } from "@/components/common";
import { exportFindings } from "@/services/export.service";
import type { FindingLevel } from "@/models";
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e

const LEVELS: FindingLevel[] = ["alert", "warn", "info"];

export function Dashboard() {
  const findings = useAppStore((s) => s.findings);
  const sources = useAppStore((s) => s.sources);
  const records = useAppStore((s) => s.records);
  const pagecache = useAppStore((s) => s.pagecache);
  const modules = useAppStore((s) => s.modules);
  const selectPid = useAppStore((s) => s.selectPid);

  const [filter, setFilter] = useState<FindingLevel | "all">("all");
<<<<<<< HEAD
=======
  const [search, setSearch] = useState("");
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e

  const counts = useMemo(() => {
    const c: Record<string, number> = { alert: 0, warn: 0, info: 0 };
    for (const f of findings) c[f.level] = (c[f.level] ?? 0) + 1;
    return c;
  }, [findings]);

<<<<<<< HEAD
  const rows = useMemo(() => {
    return filter === "all" ? findings : findings.filter((f) => f.level === filter);
  }, [findings, filter]);

  const columns: Column<Finding>[] = useMemo(
    () => [
      {
        id: "level",
        label: "Level",
        width: "70px",
        getValue: (f) => f.level,
        render: (f) => <LevelBadge level={f.level} />,
      },
      { id: "rule", label: "Rule", width: "180px", mono: true, getValue: (f) => f.rule },
      {
        id: "technique",
        label: "ATT&CK",
        width: "120px",
        getValue: (f) => f.technique ?? "",
        render: (f) => <MitreLinks technique={f.technique} refs={f.mitre} />,
      },
      { id: "target", label: "Target", width: "200px", mono: true, wrap: true, getValue: (f) => f.target },
      { id: "detail", label: "Detail", width: "auto", wrap: true, getValue: (f) => f.detail },
    ],
    []
  );

  const onRowClick = (f: Finding) => {
    const m = f.target.match(/\((\d+)\)/);
=======
  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      if (filter !== "all" && f.level !== filter) return false;
      if (
        q &&
        !(
          f.rule.toLowerCase().includes(q) ||
          f.target.toLowerCase().includes(q) ||
          (f.technique ?? "").toLowerCase().includes(q) ||
          f.detail.toLowerCase().includes(q)
        )
      )
        return false;
      return true;
    });
  }, [findings, filter, search]);

  const onRowClick = (target: string) => {
    const m = target.match(/\((\d+)\)/);
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
    if (m) selectPid(m[1]);
  };

  return (
    <div className="dashboard">
      <div className="stat-grid">
        {LEVELS.map((lvl) => (
          <button
            key={lvl}
            className={`stat stat-${lvl}${filter === lvl ? " stat-active" : ""}`}
            onClick={() => setFilter(filter === lvl ? "all" : lvl)}
          >
            <span className="stat-num">{counts[lvl] ?? 0}</span>
            <span className="stat-label">{lvl}</span>
          </button>
        ))}
        <div className="stat stat-neutral">
          <span className="stat-num">{records.size}</span>
          <span className="stat-label">processes</span>
        </div>
        <div className="stat stat-neutral">
          <span className="stat-num">{pagecache.length}</span>
          <span className="stat-label">cached files</span>
        </div>
        <div className="stat stat-neutral">
          <span className="stat-num">{modules.length}</span>
          <span className="stat-label">modules</span>
        </div>
      </div>

      {sources.length > 0 && (
        <div className="source-chips">
          {sources.map((s, i) => (
            <span key={i} className="chip" title={`${s.rows} rows`}>
              <span className="chip-kind">{s.plugin}</span>
              {s.name}
            </span>
          ))}
        </div>
      )}

<<<<<<< HEAD
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(f, i) => `${f.rule}-${i}`}
        onRowClick={onRowClick}
        searchPlaceholder="Filter findings by rule, target, technique, detail…"
        maxHeight="55vh"
        toolbar={
          <>
            <button className="btn" disabled={!findings.length} onClick={() => exportFindings(findings, "csv")}>
              Export CSV
            </button>
            <button className="btn" disabled={!findings.length} onClick={() => exportFindings(findings, "json")}>
              Export JSON
            </button>
          </>
        }
      />
=======
      <div className="findings-toolbar">
        <input
          className="search"
          placeholder="Filter findings…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <div className="spacer" />
        <button
          className="btn"
          disabled={!findings.length}
          onClick={() => exportFindings(findings, "csv")}
        >
          Export CSV
        </button>
        <button
          className="btn"
          disabled={!findings.length}
          onClick={() => exportFindings(findings, "json")}
        >
          Export JSON
        </button>
      </div>

      <div className="findings-table-wrap">
        <table className="findings-table">
          <thead>
            <tr>
              <th>Level</th>
              <th>Rule</th>
              <th>ATT&CK</th>
              <th>Target</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((f, i) => (
              <tr key={i} onClick={() => onRowClick(f.target)}>
                <td>
                  <LevelBadge level={f.level} />
                </td>
                <td className="mono">{f.rule}</td>
                <td>
                  <MitreLinks technique={f.technique} refs={f.mitre} />
                </td>
                <td className="mono wrap">{f.target}</td>
                <td className="wrap">{f.detail}</td>
              </tr>
            ))}
            {!visible.length && (
              <tr>
                <td colSpan={5} className="empty-row">
                  {findings.length
                    ? "No findings match the current filter."
                    : "No findings yet — load CSV exports to begin analysis."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
    </div>
  );
}
