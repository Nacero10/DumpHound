// Dashboard: high-level forensic summary — finding counts by severity, ingested
// sources, and a filterable findings table with export.
import { useMemo, useState } from "react";
import { useAppStore } from "@/stores/app.store";
import { DataTable, type Column } from "@/components/common/DataTable";
import { LevelBadge, MitreLinks } from "@/components/common";
import { exportFindings } from "@/services/export.service";
import type { Finding, FindingLevel } from "@/models";

const LEVELS: FindingLevel[] = ["alert", "warn", "info"];

export function Dashboard() {
  const findings = useAppStore((s) => s.findings);
  const sources = useAppStore((s) => s.sources);
  const records = useAppStore((s) => s.records);
  const pagecache = useAppStore((s) => s.pagecache);
  const modules = useAppStore((s) => s.modules);
  const selectPid = useAppStore((s) => s.selectPid);

  const [filter, setFilter] = useState<FindingLevel | "all">("all");

  const counts = useMemo(() => {
    const c: Record<string, number> = { alert: 0, warn: 0, info: 0 };
    for (const f of findings) c[f.level] = (c[f.level] ?? 0) + 1;
    return c;
  }, [findings]);

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
    </div>
  );
}
