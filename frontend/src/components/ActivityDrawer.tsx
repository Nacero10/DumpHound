// Displays every Volatility invocation, including its result and failure context.
import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { ActivityEvent } from "@/api/client";
import { useActivity, useHealth } from "@/hooks";
import { pushToast } from "@/components/common";

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString();
}

function StatusBadge({ status }: { status: ActivityEvent["status"] }) {
  const label = status === "ok" ? "ok" : status === "empty" ? "no data" : "failed";
  return <span className={`act-badge act-${status}`}>{label}</span>;
}

export function ActivityLog({ inline = false, showHeader = true }: { inline?: boolean; showHeader?: boolean }) {
  const { data: health } = useHealth();
  const backendUp = !!health;
  const { data: events, isLoading } = useActivity(backendUp);
  const [expanded, setExpanded] = useState<number | null>(null);
  const qc = useQueryClient();

  const clear = async () => {
    try {
      await api.clearActivity();
      qc.invalidateQueries({ queryKey: ["activity"] });
    } catch {
      pushToast("Unable to clear the activity log", "err");
    }
  };

  return (
    <section className={`activity-log${inline ? " activity-log-inline" : ""}`} aria-label="Activity log">
      {showHeader && (
        <header className="activity-log-header">
          <div>
            <h3>Activity log</h3>
            {inline && <p>Volatility command results and errors appear here as they run.</p>}
          </div>
          <button className="btn btn-sm" onClick={clear} disabled={!backendUp}>
            Clear
          </button>
        </header>
      )}

      {!backendUp ? (
        <div className="drawer-empty">
          Backend not connected. The activity log records server-side Volatility executions; it
          will become available once the backend is running.
        </div>
      ) : isLoading ? (
        <div className="drawer-empty">Loading…</div>
      ) : !events || events.length === 0 ? (
        <div className="drawer-empty">
          No executions yet. Run plugins from the <strong>Run Volatility</strong> panel and each
          command — success or failure — will appear here with its full reason.
        </div>
      ) : (
        <div className="act-list">
          {events.map((e) => (
            <div key={e.id} className={`act-row act-row-${e.status}`}>
              <button
                className="act-main"
                onClick={() => setExpanded(expanded === e.id ? null : e.id)}
                aria-expanded={expanded === e.id}
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
              {e.message && e.status !== "ok" && <div className="act-reason">{e.message}</div>}
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
    </section>
  );
}

export function ActivityDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const { data: health } = useHealth();
  const closeRef = useRef<HTMLButtonElement>(null);
  const lastFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    lastFocused.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const frame = requestAnimationFrame(() => closeRef.current?.focus());
    return () => {
      cancelAnimationFrame(frame);
      lastFocused.current?.focus();
    };
  }, [open]);

  if (!open) return null;

  const clear = async () => {
    try {
      await api.clearActivity();
      qc.invalidateQueries({ queryKey: ["activity"] });
    } catch {
      pushToast("Unable to clear the activity log", "err");
    }
  };

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="activity-drawer-title"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") onClose();
          if (e.key === "Tab") {
            const focusable = Array.from(
              e.currentTarget.querySelectorAll<HTMLElement>(
                'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
              )
            );
            const first = focusable[0];
            const last = focusable.at(-1);
            if (!first || !last) return;
            if (e.shiftKey && document.activeElement === first) {
              e.preventDefault();
              last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
              e.preventDefault();
              first.focus();
            }
          }
        }}
      >
        <header className="drawer-header">
          <h3 id="activity-drawer-title">Activity log</h3>
          <div className="drawer-head-actions">
            <button className="btn btn-sm" onClick={clear} disabled={!health}>
              Clear
            </button>
            <button ref={closeRef} className="modal-close" onClick={onClose} aria-label="Close activity log">×</button>
          </div>
        </header>
        <ActivityLog showHeader={false} />
      </aside>
    </div>
  );
}
