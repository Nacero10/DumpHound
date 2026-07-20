// Modules & rootkit indicators. Surfaces three signals Volatility's
// linux.malware.* plugins feed: loaded kernel modules (lsmod / check_modules),
// hidden modules (unlinked from the module list), and syscall-table integrity
// (check_syscall). Severity comes from the shared detection engine.
import { useMemo, useState } from "react";
import { useAppStore } from "@/stores/app.store";
<<<<<<< HEAD
import { DataTable, type Column } from "@/components/common/DataTable";
import { LevelBadge, MitreLinks } from "@/components/common";
import type { FindingLevel, KernelModule, SyscallEntry } from "@/models";
=======
import { LevelBadge, MitreLinks } from "@/components/common";
import type { FindingLevel } from "@/models";
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e

const rank: Record<FindingLevel, number> = { alert: 3, warn: 2, info: 1 };

// Linux kernel taint letters most relevant to rootkit / tampering triage.
const TAINT_MEANINGS: Record<string, { text: string; bad?: boolean }> = {
  O: { text: "out-of-tree module", bad: true },
  E: { text: "unsigned module", bad: true },
  F: { text: "force-loaded module (insmod -f)", bad: true },
  R: { text: "force-unloaded module", bad: true },
  P: { text: "proprietary module" },
  C: { text: "staging driver" },
  D: { text: "kernel oops/died", bad: true },
  K: { text: "live-patched kernel" },
  G: { text: "GPL / clean" },
};

function decodeTaints(taints?: string): { letter: string; text: string; bad: boolean }[] {
  if (!taints) return [];
  return [...taints]
    .filter((c) => /[A-Za-z]/.test(c))
    .map((c) => {
      const up = c.toUpperCase();
      const m = TAINT_MEANINGS[up];
      return { letter: c, text: m?.text ?? "taint flag", bad: !!m?.bad };
    });
}

const isHooked = (sym?: string): boolean => !sym || /unknown|n\/?a|^-$/i.test(sym);

type View = "modules" | "syscalls";

export function Modules() {
  const modules = useAppStore((s) => s.modules);
  const syscalls = useAppStore((s) => s.syscalls);
  const findings = useAppStore((s) => s.findings);
  const [view, setView] = useState<View>("modules");
<<<<<<< HEAD
=======
  const [search, setSearch] = useState("");
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e

  const sevByTarget = useMemo(() => {
    const map = new Map<string, { level: FindingLevel; technique?: string }>();
    for (const f of findings) {
      const key = f.target.replace(/\s*\(hidden\)\s*$/, "");
      const cur = map.get(key);
      if (!cur || rank[f.level] > rank[cur.level]) {
        map.set(key, { level: f.level, technique: f.technique });
      }
    }
    return map;
  }, [findings]);

  const hiddenCount = useMemo(() => modules.filter((m) => m.hidden).length, [modules]);
<<<<<<< HEAD
  const hookedCount = useMemo(() => syscalls.filter((s) => isHooked(s.symbol)).length, [syscalls]);

  const modColumns: Column<KernelModule>[] = useMemo(
    () => [
      {
        id: "severity",
        label: "Sev",
        width: "90px",
        getValue: (m) => sevByTarget.get(m.name)?.level ?? "",
        render: (m) => {
          const sev = sevByTarget.get(m.name);
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
        id: "name",
        label: "Module",
        width: "180px",
        mono: true,
        getValue: (m) => m.name,
        render: (m) => (
          <>
            {m.name}
            {m.hidden && <span className="tag tag-alert">HIDDEN</span>}
          </>
        ),
      },
      { id: "source", label: "Source", width: "120px", mono: true, getValue: (m) => m.source ?? "", render: (m) => <span className="dim">{m.source}</span> },
      { id: "status", label: "Status", width: "100px", mono: true, getValue: (m) => m.status ?? "" },
      {
        id: "taints",
        label: "Taints",
        width: "140px",
        getValue: (m) => m.taints ?? "",
        render: (m) => {
          const taints = decodeTaints(m.taints);
          return taints.length ? (
            <span className="taints">
              {taints.map((t, j) => (
                <span key={j} className={`taint${t.bad ? " taint-bad" : ""}`} title={t.text}>
                  {t.letter}
                </span>
              ))}
            </span>
          ) : (
            <span className="sev-none">·</span>
          );
        },
      },
      { id: "address", label: "Address", width: "120px", mono: true, getValue: (m) => m.address ?? "", render: (m) => <span className="dim">{m.address}</span> },
    ],
    [sevByTarget]
  );

  const modRows = useMemo(() => {
    return [...modules].sort((a, b) => {
=======
  const hookedCount = useMemo(
    () => syscalls.filter((s) => isHooked(s.symbol)).length,
    [syscalls]
  );

  const visibleModules = useMemo(() => {
    const q = search.trim().toLowerCase();
    const rows = q
      ? modules.filter(
          (m) =>
            m.name.toLowerCase().includes(q) ||
            (m.taints ?? "").toLowerCase().includes(q) ||
            (m.source ?? "").toLowerCase().includes(q)
        )
      : modules;
    return [...rows].sort((a, b) => {
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
      const av = (a.hidden ? 2 : 0) + (decodeTaints(a.taints).some((t) => t.bad) ? 1 : 0);
      const bv = (b.hidden ? 2 : 0) + (decodeTaints(b.taints).some((t) => t.bad) ? 1 : 0);
      return bv - av;
    });
<<<<<<< HEAD
  }, [modules]);

  const modRowClass = (m: KernelModule) => {
    const sev = sevByTarget.get(m.name)?.level;
    return sev ? `fc-row-${sev}` : "";
  };

  const syscallColumns: Column<SyscallEntry>[] = useMemo(
    () => [
      {
        id: "severity",
        label: "Sev",
        width: "90px",
        getValue: (s) => (isHooked(s.symbol) ? "alert" : ""),
        render: (s) =>
          isHooked(s.symbol) ? (
            <span className="sev-cell">
              <LevelBadge level="alert" />
              <MitreLinks technique="T1014" />
            </span>
          ) : (
            <span className="sev-none">·</span>
          ),
      },
      { id: "table", label: "Table", width: "120px", mono: true, getValue: (s) => s.table ?? "" },
      { id: "index", label: "Index", width: "80px", getValue: (s) => String(s.index ?? ""), render: (s) => <span className="num">{s.index}</span> },
      { id: "handler", label: "Handler", width: "140px", mono: true, getValue: (s) => s.handler ?? "", render: (s) => <span className="dim">{s.handler}</span> },
      {
        id: "symbol",
        label: "Resolved symbol",
        width: "200px",
        mono: true,
        getValue: (s) => s.symbol ?? "",
        render: (s) => s.symbol || <span className="tag tag-alert">UNKNOWN</span>,
      },
    ],
    []
  );

  const syscallRows = useMemo(
    () => [...syscalls].sort((a, b) => Number(isHooked(b.symbol)) - Number(isHooked(a.symbol))),
    [syscalls]
  );

  const syscallRowClass = (s: SyscallEntry) => (isHooked(s.symbol) ? "fc-row-alert" : "");
=======
  }, [modules, search]);

  const visibleSyscalls = useMemo(() => {
    const q = search.trim().toLowerCase();
    const rows = q
      ? syscalls.filter(
          (s) =>
            (s.symbol ?? "").toLowerCase().includes(q) ||
            (s.table ?? "").toLowerCase().includes(q) ||
            (s.index ?? "").includes(q)
        )
      : syscalls;
    return [...rows].sort((a, b) => Number(isHooked(b.symbol)) - Number(isHooked(a.symbol)));
  }, [syscalls, search]);
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e

  if (!modules.length && !syscalls.length) {
    return (
      <div className="modules-empty">
        Load <code>linux.lsmod</code>, <code>linux.malware.hidden_modules</code>, or{" "}
        <code>linux.malware.check_syscall</code> CSVs to inspect kernel-level rootkit
        indicators.
      </div>
    );
  }

  return (
    <div className="modules">
      <div className="rk-summary">
        <div className={`rk-stat${hiddenCount ? " rk-stat-alert" : ""}`}>
          <span className="rk-num">{hiddenCount}</span>
          <span className="rk-label">hidden modules</span>
        </div>
        <div className={`rk-stat${hookedCount ? " rk-stat-alert" : ""}`}>
          <span className="rk-num">{hookedCount}</span>
          <span className="rk-label">hooked syscalls</span>
        </div>
        <div className="rk-stat">
          <span className="rk-num">{modules.length}</span>
          <span className="rk-label">modules total</span>
        </div>
        <div className="rk-stat">
          <span className="rk-num">{syscalls.length}</span>
          <span className="rk-label">syscalls checked</span>
        </div>
      </div>

      <div className="modules-toolbar">
        <div className="seg">
<<<<<<< HEAD
          <button className={view === "modules" ? "seg-btn seg-active" : "seg-btn"} onClick={() => setView("modules")}>
            Modules {hiddenCount > 0 && <span className="seg-dot" />}
          </button>
          <button className={view === "syscalls" ? "seg-btn seg-active" : "seg-btn"} onClick={() => setView("syscalls")} disabled={!syscalls.length}>
            Syscall integrity {hookedCount > 0 && <span className="seg-dot" />}
          </button>
        </div>
      </div>

      {view === "modules" ? (
        <DataTable
          columns={modColumns}
          rows={modRows}
          rowKey={(m, i) => `${m.name}-${i}`}
          rowClass={modRowClass}
          searchPlaceholder="Search modules, taints, sources…"
          maxHeight="60vh"
        />
      ) : (
        <DataTable
          columns={syscallColumns}
          rows={syscallRows}
          rowKey={(s, i) => `${s.table}-${s.index}-${i}`}
          rowClass={syscallRowClass}
          searchPlaceholder="Search syscalls, handlers, symbols…"
          maxHeight="60vh"
        />
=======
          <button
            className={view === "modules" ? "seg-btn seg-active" : "seg-btn"}
            onClick={() => setView("modules")}
          >
            Modules {hiddenCount > 0 && <span className="seg-dot" />}
          </button>
          <button
            className={view === "syscalls" ? "seg-btn seg-active" : "seg-btn"}
            onClick={() => setView("syscalls")}
            disabled={!syscalls.length}
          >
            Syscall integrity {hookedCount > 0 && <span className="seg-dot" />}
          </button>
        </div>
        <input
          className="search"
          placeholder={view === "modules" ? "Filter modules…" : "Filter syscalls…"}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {view === "modules" ? (
        <div className="fc-table-wrap">
          <table className="fc-table">
            <thead>
              <tr>
                <th>Sev</th>
                <th>Module</th>
                <th>Source</th>
                <th>Status</th>
                <th>Taints</th>
                <th>Address</th>
              </tr>
            </thead>
            <tbody>
              {visibleModules.map((m, i) => {
                const sev = sevByTarget.get(m.name);
                const taints = decodeTaints(m.taints);
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
                    <td className="mono">
                      {m.name}
                      {m.hidden && <span className="tag tag-alert">HIDDEN</span>}
                    </td>
                    <td className="mono dim">{m.source}</td>
                    <td className="mono">{m.status}</td>
                    <td>
                      {taints.length ? (
                        <span className="taints">
                          {taints.map((t, j) => (
                            <span
                              key={j}
                              className={`taint${t.bad ? " taint-bad" : ""}`}
                              title={t.text}
                            >
                              {t.letter}
                            </span>
                          ))}
                        </span>
                      ) : (
                        <span className="sev-none">·</span>
                      )}
                    </td>
                    <td className="mono dim">{m.address}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="fc-table-wrap">
          <table className="fc-table">
            <thead>
              <tr>
                <th>Sev</th>
                <th>Table</th>
                <th>Index</th>
                <th>Handler</th>
                <th>Resolved symbol</th>
              </tr>
            </thead>
            <tbody>
              {visibleSyscalls.map((s, i) => {
                const hooked = isHooked(s.symbol);
                return (
                  <tr key={i} className={hooked ? "fc-row-alert" : ""}>
                    <td>
                      {hooked ? (
                        <span className="sev-cell">
                          <LevelBadge level="alert" />
                          <MitreLinks technique="T1014" />
                        </span>
                      ) : (
                        <span className="sev-none">·</span>
                      )}
                    </td>
                    <td className="mono">{s.table}</td>
                    <td className="num">{s.index}</td>
                    <td className="mono dim">{s.handler}</td>
                    <td className="mono">
                      {s.symbol || <span className="tag tag-alert">UNKNOWN</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
>>>>>>> 81efc0d5055ee4ef155d33fcb883a5f742a7494e
      )}
    </div>
  );
}
