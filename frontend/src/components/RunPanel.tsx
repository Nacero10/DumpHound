// In-app Volatility automation. Pulls the FULL allowlisted plugin set live from
// the backend (/api/plugins), groups it by category, and runs the selected ones
// against a chosen image. Each CSV is fed straight into the analysis store with
// an explicit plugin hint (no header guessing). Non-table plugins (dump-only,
// e.g. InodePages / RecoverFs) are shown but disabled — they use dump endpoints.
import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "@/api/client";
import type { PluginInfo } from "@/api/client";
import { useHealth, useImages, usePlugins } from "@/hooks";
import { useAppStore } from "@/stores/app.store";
import { pushToast } from "@/components/common";
import type { OsName } from "@/models";

// Plugins worth pre-selecting for a standard triage sweep.
const RECOMMENDED = new Set([
  "linux.pstree.PsTree",
  "linux.psaux.PsAux",
  "linux.bash.Bash",
  "linux.sockstat.Sockstat",
  "linux.lsof.Lsof",
  "linux.pagecache.Files",
  "linux.lsmod.Lsmod",
  "linux.malware.hidden_modules.Hidden_modules",
  "linux.malware.check_syscall.Check_syscall",
  "windows.pstree.PsTree",
  "windows.cmdline.CmdLine",
  "windows.netscan.NetScan",
]);

const CATEGORY_ORDER = ["process", "network", "modules", "malware", "registry", "pagecache", "other"];
const CATEGORY_LABEL: Record<string, string> = {
  process: "Process & memory",
  network: "Network",
  modules: "Kernel modules / drivers",
  malware: "Malware / rootkit / defense evasion",
  registry: "Registry",
  pagecache: "Page cache",
  other: "Other",
};

type RunState = "idle" | "running" | "ok" | "empty" | "error" | "skipped";
interface RunStatus {
  state: RunState;
  rows?: number;
  message?: string;
}

export function RunPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const os = useAppStore((s) => s.os) as OsName;
  const storeImage = useAppStore((s) => s.image);
  const setImage = useAppStore((s) => s.setImage);
  const ingestFiles = useAppStore((s) => s.ingestFiles);

  const { data: health } = useHealth();
  const backendUp = !!health;
  const volReady = !!health?.volatility_available;
  const { data: images } = useImages(open && backendUp);
  const { data: allPlugins, isLoading: pluginsLoading } = usePlugins(open && backendUp);

  const [showOtherOs, setShowOtherOs] = useState(false);
  const [image, setLocalImage] = useState(storeImage);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [status, setStatus] = useState<Record<string, RunStatus>>({});
  const [running, setRunning] = useState(false);
  const [maximized, setMaximized] = useState(false);

  // Plugins for the active OS (optionally show the other OS too).
  const plugins = useMemo(() => {
    const list = allPlugins ?? [];
    return showOtherOs ? list : list.filter((p) => p.os === os);
  }, [allPlugins, os, showOtherOs]);

  // Group by category, ordered.
  const grouped = useMemo(() => {
    const map = new Map<string, PluginInfo[]>();
    for (const p of plugins) {
      const arr = map.get(p.category) ?? [];
      arr.push(p);
      map.set(p.category, arr);
    }
    for (const arr of map.values()) arr.sort((a, b) => a.name.localeCompare(b.name));
    return CATEGORY_ORDER.filter((c) => map.has(c)).map((c) => ({
      category: c,
      label: CATEGORY_LABEL[c] ?? c,
      items: map.get(c)!,
    }));
  }, [plugins]);

  // Seed the recommended selection once plugins load / OS changes.
  useEffect(() => {
    const runnable = plugins.filter((p) => p.produces_table).map((p) => p.name);
    setSelected(new Set(runnable.filter((n) => RECOMMENDED.has(n))));
    setStatus({});
  }, [allPlugins, os, showOtherOs]); // eslint-disable-line react-hooks/exhaustive-deps

  const firstMessage = useMemo(() => {
    for (const v of Object.values(status)) {
      if ((v.state === "empty" || v.state === "error") && v.message) return v.message;
    }
    return null;
  }, [status]);

  if (!open) return null;

  const tableNames = plugins.filter((p) => p.produces_table).map((p) => p.name);

  const toggle = (name: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  const setAll = (on: boolean) => setSelected(on ? new Set(tableNames) : new Set());
  const setRecommended = () =>
    setSelected(new Set(tableNames.filter((n) => RECOMMENDED.has(n))));

  const run = async () => {
    if (!image.trim()) {
      pushToast("Enter or select a memory image first", "warn");
      return;
    }
    setImage(image.trim());
    setRunning(true);
    const order = plugins.filter((p) => selected.has(p.name) && p.produces_table);
    const collected: { name: string; text: string; plugin: string }[] = [];
    for (const def of order) {
      setStatus((s) => ({ ...s, [def.name]: { state: "running" } }));
      try {
        const res = await api.run({ image: image.trim(), plugin: def.name, renderer: "csv" });
        const firstLine = (res.csv ?? "").split(/\r?\n/, 1)[0] ?? "";
        const looksTabular = res.rows > 0 && firstLine.length > 0;
        if (looksTabular) {
          collected.push({ name: def.name, text: res.csv, plugin: def.name });
          setStatus((s) => ({ ...s, [def.name]: { state: "ok", rows: res.rows } }));
        } else {
          // No real table — almost always missing symbols. Surface vol's message.
          setStatus((s) => ({
            ...s,
            [def.name]: {
              state: "empty",
              rows: 0,
              message: res.stderr ?? "No tabular output (symbols missing?)",
            },
          }));
        }
      } catch (e) {
        const msg = e instanceof ApiError ? e.message : (e as Error).message;
        setStatus((s) => ({ ...s, [def.name]: { state: "error", message: msg } }));
      }
    }
    if (collected.length) {
      await ingestFiles(collected);
      pushToast(`Ingested ${collected.length} plugin output(s)`, "ok");
    } else {
      pushToast("No usable output — likely missing ISF symbols for this kernel", "warn");
    }
    setRunning(false);
  };

  const selectedCount = selected.size;

  return (
    <div className="modal-backdrop" onClick={running ? undefined : onClose}>
      <div
        className={`modal modal-lg modal-resizable${maximized ? " modal-max" : ""}`}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="modal-header">
          <h3>Run Volatility</h3>
          <div className="modal-head-actions">
            <button
              className="modal-icon"
              onClick={() => setMaximized((m) => !m)}
              title={maximized ? "Restore size" : "Maximize"}
            >
              {maximized ? "❐" : "⤢"}
            </button>
            <button className="modal-close" onClick={onClose} disabled={running}>
              ✕
            </button>
          </div>
        </header>

        {!backendUp ? (
          <div className="modal-notice">
            Backend not reachable. Start it (<code>python run.py</code>) or use drag-and-drop
            CSV ingestion instead. The analysis engine runs fully offline either way.
          </div>
        ) : !volReady ? (
          <div className="modal-notice modal-notice-warn">
            Backend is up but the <code>vol</code> binary wasn't found. Install Volatility 3 on
            the backend host, or load CSVs manually.
          </div>
        ) : null}

        {firstMessage && (
          <div className="modal-notice modal-notice-warn run-diag">
            <strong>Volatility couldn't parse the image.</strong> This usually means the
            kernel's ISF symbol table is missing (Linux symbols aren't bundled and{" "}
            <code>--offline</code> blocks fetching). vol said:
            <pre className="run-diag-pre">{firstMessage.slice(0, 1200)}</pre>
            Get the kernel banner with <code>vol -f &lt;image&gt; banners.Banners</code>, then
            supply the matching ISF in <code>VOL_SYMBOL_DIR</code>.
          </div>
        )}

        <div className="modal-body">
          <label className="run-field">
            <span>Memory image</span>
            {images && images.length > 0 ? (
              <select value={image} onChange={(e) => setLocalImage(e.target.value)}>
                {!images.some((i) => i.name === image) && <option value={image}>{image}</option>}
                {images.map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.name} ({(i.size_bytes / 1e9).toFixed(1)} GB)
                  </option>
                ))}
              </select>
            ) : (
              <input
                value={image}
                onChange={(e) => setLocalImage(e.target.value)}
                placeholder="memdump.lime (must live in VOL_IMAGE_DIR)"
                spellCheck={false}
              />
            )}
          </label>

          <div className="run-actions">
            <button className="btn btn-sm" onClick={() => setAll(true)} disabled={running}>
              Select all ({tableNames.length})
            </button>
            <button className="btn btn-sm" onClick={() => setAll(false)} disabled={running}>
              Clear
            </button>
            <button className="btn btn-sm" onClick={setRecommended} disabled={running}>
              Recommended
            </button>
            <label className="run-toggle">
              <input
                type="checkbox"
                checked={showOtherOs}
                disabled={running}
                onChange={(e) => setShowOtherOs(e.target.checked)}
              />
              Show all OS plugins
            </label>
          </div>

          {pluginsLoading ? (
            <div className="run-loading">Loading plugin list from backend…</div>
          ) : (
            grouped.map((group) => (
              <div key={group.category} className="run-group">
                <div className="run-group-head">{group.label}</div>
                {group.items.map((p) => {
                  const st = status[p.name]?.state ?? "idle";
                  const runnable = p.produces_table;
                  return (
                    <label
                      key={p.name}
                      className={`run-item run-${st}${runnable ? "" : " run-disabled"}`}
                    >
                      <input
                        type="checkbox"
                        checked={selected.has(p.name)}
                        disabled={running || !runnable}
                        onChange={() => toggle(p.name)}
                      />
                      <span className="run-label">
                        <code className="run-plugin-name">{p.name}</code>
                        {RECOMMENDED.has(p.name) && <span className="run-rec">recommended</span>}
                        {!runnable && <span className="run-dump">dump-only</span>}
                      </span>
                      <span className="run-os">{p.os}</span>
                      <span className="run-status">
                        {st === "running" && <span className="run-spin">running…</span>}
                        {st === "ok" && (
                          <span className="run-ok">✓ {status[p.name]?.rows ?? 0} rows</span>
                        )}
                        {st === "empty" && (
                          <span className="run-empty" title={status[p.name]?.message}>
                            ⚠ no data
                          </span>
                        )}
                        {st === "error" && (
                          <span className="run-err" title={status[p.name]?.message}>
                            ✕ failed
                          </span>
                        )}
                      </span>
                    </label>
                  );
                })}
              </div>
            ))
          )}
        </div>

        <footer className="modal-footer">
          <span className="run-hint">
            {selectedCount} selected · runs sequentially, results stream into the workbench
          </span>
          <div className="spacer" />
          <button className="btn btn-ghost" onClick={onClose} disabled={running}>
            Close
          </button>
          <button
            className="btn btn-primary"
            onClick={run}
            disabled={running || !volReady || !selectedCount}
          >
            {running ? "Running…" : `Run ${selectedCount} plugin${selectedCount === 1 ? "" : "s"}`}
          </button>
        </footer>
      </div>
    </div>
  );
}
