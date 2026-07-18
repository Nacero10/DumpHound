// Process Graph page: the D3 process tree with the live Inspector, plus a
// compact severity strip for at-a-glance triage of process-level findings.
import { useMemo } from "react";
import { useAppStore } from "@/stores/app.store";
import { ProcessTree } from "@/components/ProcessTree/ProcessTree";
import { Inspector } from "@/components/Inspector/Inspector";
import type { FindingLevel } from "@/models";

const LEVELS: FindingLevel[] = ["alert", "warn", "info"];

export function ProcessGraphPage() {
  const findings = useAppStore((s) => s.findings);
  const records = useAppStore((s) => s.records);

  const counts = useMemo(() => {
    const c: Record<string, number> = { alert: 0, warn: 0, info: 0 };
    for (const f of findings) c[f.level] = (c[f.level] ?? 0) + 1;
    return c;
  }, [findings]);

  return (
    <div className="page page-graph">
      <div className="graph-strip">
        {LEVELS.map((lvl) => (
          <span key={lvl} className={`pill pill-${lvl}`}>
            <b>{counts[lvl] ?? 0}</b> {lvl}
          </span>
        ))}
        <span className="pill pill-neutral">
          <b>{records.size}</b> processes
        </span>
        <span className="graph-hint">scroll to zoom · drag to pan · click a node to inspect</span>
      </div>
      <div className="graph-main">
        <section className="graph-tree">
          <ProcessTree />
        </section>
        <Inspector />
      </div>
    </div>
  );
}
