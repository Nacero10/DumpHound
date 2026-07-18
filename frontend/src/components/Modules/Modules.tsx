// Modules & rootkit indicators. Surfaces three signals Volatility's
// linux.malware.* plugins feed: loaded kernel modules (lsmod / check_modules),
// hidden modules (unlinked from the module list), and syscall-table integrity
// (check_syscall). Severity comes from the shared detection engine.
import { useMemo, useState } from "react";
import { useAppStore } from "@/stores/app.store";
import { LevelBadge, MitreLinks } from "@/components/common";
import type { FindingLevel } from "@/models";

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
  const [search, setSearch] = useState("");

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
      const av = (a.hidden ? 2 : 0) + (decodeTaints(a.taints).some((t) => t.bad) ? 1 : 0);
      const bv = (b.hidden ? 2 : 0) + (decodeTaints(b.taints).some((t) => t.bad) ? 1 : 0);
      return bv - av;
    });
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
      )}
    </div>
  );
}
