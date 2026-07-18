// Files & Modules page: artifact-level analysis. Tabs for the findings
// dashboard, the page-cache file explorer, and the kernel module / rootkit view.
import { useState } from "react";
import { useAppStore } from "@/stores/app.store";
import { Dashboard } from "@/components/Dashboard/Dashboard";
import { FileCache } from "@/components/FileCache/FileCache";
import { Modules } from "@/components/Modules/Modules";

type Tab = "findings" | "filecache" | "modules";

export function FilesModulesPage() {
  const [tab, setTab] = useState<Tab>("findings");
  const pagecache = useAppStore((s) => s.pagecache);
  const modules = useAppStore((s) => s.modules);
  const syscalls = useAppStore((s) => s.syscalls);

  return (
    <div className="page page-files">
      <div className="wb-tabs">
        <button
          className={tab === "findings" ? "tab tab-active" : "tab"}
          onClick={() => setTab("findings")}
        >
          Findings
        </button>
        <button
          className={tab === "filecache" ? "tab tab-active" : "tab"}
          onClick={() => setTab("filecache")}
        >
          File Cache
          {pagecache.length > 0 && <span className="tab-badge">{pagecache.length}</span>}
        </button>
        <button
          className={tab === "modules" ? "tab tab-active" : "tab"}
          onClick={() => setTab("modules")}
        >
          Modules &amp; Rootkits
          {modules.length + syscalls.length > 0 && (
            <span className="tab-badge">{modules.length + syscalls.length}</span>
          )}
        </button>
      </div>
      <div className="wb-panel wb-panel-scroll">
        {tab === "findings" && <Dashboard />}
        {tab === "filecache" && <FileCache />}
        {tab === "modules" && <Modules />}
      </div>
    </div>
  );
}
