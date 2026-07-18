// Activity log drawer. Polls /api/activity and shows every Volatility execution
// the app has launched, with exit code, duration, row count, and — crucially —
// the trimmed stderr/reason for failures, so an analyst can see *why* a command
// failed without leaving the UI.
import { useState } from "react";
import { api } from "@/api/client";
import type { ActivityEvent } from "@/api/client";
import { useActivity, useHealth } from "@/hooks";
import { useQueryClient } from "@tanstack/react-query";

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString();
}

function StatusBadge({ status }: { status: ActivityEvent["status"] }) {
  const label = status === "ok" ? "ok" : status === "empty" ? "no data" : "failed";
  return <span className={`act-badge act-${status}`}>{label}</span>;
}

export function ActivityDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { data: health } = useHealth();
  const backendUp = !!health;
  const { data: events, isLoading } = useActivity(open && backendUp);
  const [expanded, setExpanded] = useState<number | null>(null);
  const qc = useQueryClient();

  if (!open) return null;

  const clear = async () => {
    await api.clearActivity();
    qc.invalidateQueries({ queryKey: ["activity"] });
  };

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()}>
        <header className="drawer-header">
          <h3>Activity log</h3>
          <div className="drawer-head-actions">
            <button className="btn btn-sm" onClick={clear} disabled={!backendUp}>
              Clear
            </button>
            <button className="modal-close" onClick={onClose}>
              ✕
            </button>
          </div>
        </header>

        {!backendUp ? (
          <div className="drawer-empty">
            Backend not connected. The activity log records server-side Volatility
            executions; it's available once the backend is running.
          </div>
        ) : isLoading ? (
          <div className="drawer-empty">Loading…</div>
        ) : !events || events.length === 0 ? (
          <div className="drawer-empty">
            No executions yet. Run plugins from the <strong>Run Volatility</strong> panel and
            each command — success or failure — will appear here with its full reason.
          </div>
        ) : (
          <div className="act-list">
            {events.map((e) => (
              <div key={e.id} className={`act-row act-row-${e.status}`}>
                <button
                  className="act-main"
                  onClick={() => setExpanded(expanded === e.id ? null : e.id)}
                >
                  <StatusBadge status={e.status} />
                  <span className="act-plugin">{e.plugin ?? e.kind}</span>
                  <span className="act-meta">
                    {e.rows != null && e.status === "ok" && <span>{e.rows} rows</span>}
                    {e.returncode != null && <span>rc {e.returncode}</span>}
                    <span>{e.duration_ms} ms</span>
                    <span className="act-time">{fmtTime(e.ts)}</span>
                  </span>
                </button>
                {e.message && e.status !== "ok" && (
                  <div className="act-reason">{e.message}</div>
                )}
                {expanded === e.id && (
                  <div className="act-detail">
                    <div className="act-detail-label">command</div>
                    <pre className="act-pre">{e.argv.join(" ")}</pre>
                    {e.stderr && (
                      <>
                        <div className="act-detail-label">stderr</div>
                        <pre className="act-pre act-pre-err">{e.stderr}</pre>
                      </>
                    )}
                    <div className="act-detail-label">
                      stdout {e.stdout_bytes} bytes · stderr {e.stderr_bytes} bytes
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </aside>
    </div>
  );
}
