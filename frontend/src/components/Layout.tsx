// Shared shell: header (OS/image + nav), the persistent CSV load bar,
// and a routed <Outlet/>. Global Zustand state means switching pages keeps the
// parsed evidence and findings intact.
import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useAppStore } from "@/stores/app.store";
import { FileDropZone, ToastHost } from "@/components/common";
import { RunPanel } from "@/components/RunPanel";
import { ActivityDrawer, ActivityLog } from "@/components/ActivityDrawer";
import type { OsName } from "@/models";

export function Layout() {
  const os = useAppStore((s) => s.os);
  const image = useAppStore((s) => s.image);
  const setOs = useAppStore((s) => s.setOs);
  const setImage = useAppStore((s) => s.setImage);
  const ingestFiles = useAppStore((s) => s.ingestFiles);
  const reset = useAppStore((s) => s.reset);
  const analyzing = useAppStore((s) => s.analyzing);
  const error = useAppStore((s) => s.error);
  const sources = useAppStore((s) => s.sources);

  const [runOpen, setRunOpen] = useState(false);
  const [activityOpen, setActivityOpen] = useState(false);
  const loaded = sources.length > 0;

  return (
    <div className="workbench">
      <header className="wb-header">
        <div className="wb-title">
          <img src="/logo.png" alt="DumpHound" className="app-logo" />
          <h1>DumpHound</h1>
          <span className="subtitle">Volatility 3 memory-forensics platform</span>
        </div>
        <nav className="wb-nav">
          <NavLink to="/" end className={({ isActive }) => (isActive ? "navlink active" : "navlink")}>
            Process Graph
          </NavLink>
          <NavLink
            to="/files"
            className={({ isActive }) => (isActive ? "navlink active" : "navlink")}
          >
            Files &amp; Modules
          </NavLink>
        </nav>
        <div className="wb-controls">
          <label className="ctl">
            OS
            <select value={os} onChange={(e) => setOs(e.target.value as OsName)}>
              <option value="linux">linux</option>
              <option value="windows">windows</option>
            </select>
          </label>
          <label className="ctl">
            Image
            <input value={image} onChange={(e) => setImage(e.target.value)} spellCheck={false} />
          </label>
          <button className="btn btn-primary" onClick={() => setRunOpen(true)}>
            ▸ Run Volatility
          </button>
          <button className="btn btn-ghost" onClick={() => setActivityOpen(true)} title="View every command the app ran and why it failed">
            ☰ Activity
          </button>
          <button className="btn btn-ghost" onClick={reset} disabled={!loaded}>
            Reset
          </button>
        </div>
      </header>

      {!loaded ? (
        <div className="wb-intro">
          <ActivityLog inline />
          <FileDropZone onFiles={ingestFiles} />
          <div className="intro-or">
            <span>or</span>
          </div>
          <button className="btn btn-primary btn-lg" onClick={() => setRunOpen(true)}>
            ▸ Run Volatility plugins from a memory image
          </button>
          <p className="wb-hint">
            Export Volatility 3 plugins as CSV (<code>-r csv</code>) and drop them here:{" "}
            <code>linux.pstree</code>, <code>linux.bash.Bash</code>, <code>linux.sockstat</code>,{" "}
            <code>linux.lsof</code>, <code>linux.pagecache.Files</code>, <code>linux.lsmod</code>,{" "}
            <code>linux.malware.hidden_modules</code>, <code>linux.malware.check_syscall</code>.
            Plugin type is inferred from headers — filenames don't matter.
          </p>
        </div>
      ) : (
        <>
          <div className="wb-loadbar">
            <FileDropZone onFiles={ingestFiles} label="Drop more CSVs to merge" />
            {analyzing && <span className="analyzing">analyzing…</span>}
          </div>
          <Outlet />
        </>
      )}

      {error && <div className="wb-error">⚠ {error}</div>}
      <RunPanel open={runOpen} onClose={() => setRunOpen(false)} />
      <ActivityDrawer open={activityOpen} onClose={() => setActivityOpen(false)} />
      <ToastHost />
    </div>
  );
}
