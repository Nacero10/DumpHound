// Central client state (Zustand). Holds parsed artifacts, derived process
// records, detection findings, and UI selection. Parsing/detection are invoked
// from here so components stay declarative.
import { create } from "zustand";
import type {
  CsvSource,
  Finding,
  KernelModule,
  OsName,
  PagecacheFile,
  ProcessRecord,
  SyscallEntry,
  TreeNode,
} from "@/models";
import {
  classifyPlugin,
  mergeIntoRecords,
  parseCsv,
  parseModules,
  parseSyscalls,
  parsePagecache,
} from "@/services/parser.service";
import { loadEngine } from "@/services/detection.service";

/** Map an exact Volatility plugin name to a parser kind (used when the app runs
 *  the plugin itself, so classification never has to guess from headers). */
const PLUGIN_KIND: Record<string, string> = {
  "linux.pstree.pstree": "pstree",
  "linux.pslist.pslist": "pstree",
  "linux.psaux.psaux": "pstree",
  "windows.pstree.pstree": "pstree",
  "windows.pslist.pslist": "pstree",
  "windows.psscan.psscan": "pstree",
  "windows.cmdline.cmdline": "pstree",
  "linux.bash.bash": "history",
  "linux.sockstat.sockstat": "sockets",
  "windows.netscan.netscan": "sockets",
  "windows.netstat.netstat": "sockets",
  "linux.lsof.lsof": "lsof",
  "linux.envars.envars": "envars",
  "linux.malware.malfind.malfind": "malfind",
  "windows.malfind.malfind": "malfind",
  "linux.malware.process_spoofing.process_spoofing": "spoofing",
  "linux.lsmod.lsmod": "modules",
  "linux.malware.check_modules.check_modules": "modules",
  "linux.malware.hidden_modules.hidden_modules": "hidden_modules",
  "linux.malware.check_syscall.check_syscall": "syscalls",
  "linux.pagecache.files": "pagecache",
};

function pluginToKind(plugin?: string): string | undefined {
  return plugin ? PLUGIN_KIND[plugin.toLowerCase()] : undefined;
}

function buildTree(records: Map<string, ProcessRecord>): {
  roots: TreeNode[];
  orphans: TreeNode[];
} {
  const nodes = new Map<string, TreeNode>();
  for (const rec of records.values()) {
    nodes.set(rec.pid, { pid: rec.pid, record: rec, children: [] });
  }
  const roots: TreeNode[] = [];
  const orphans: TreeNode[] = [];
  for (const node of nodes.values()) {
    const ppid = node.record.ppid;
    if (ppid && ppid !== node.pid && nodes.has(ppid)) {
      nodes.get(ppid)!.children.push(node);
    } else if (!ppid || ppid === "0") {
      roots.push(node);
    } else {
      orphans.push(node);
    }
  }
  // Orphans (parent not captured) are surfaced as additional roots.
  return { roots: [...roots, ...orphans], orphans };
}

interface AppState {
  os: OsName;
  image: string;
  sources: CsvSource[];
  records: Map<string, ProcessRecord>;
  recordList: ProcessRecord[];
  pagecache: PagecacheFile[];
  modules: KernelModule[];
  syscalls: SyscallEntry[];
  findings: Finding[];
  roots: TreeNode[];
  selectedPid: string | null;
  analyzing: boolean;
  error: string | null;

  setOs: (os: OsName) => void;
  setImage: (image: string) => void;
  selectPid: (pid: string | null) => void;
  ingestFiles: (files: { name: string; text: string; plugin?: string }[]) => Promise<void>;
  reset: () => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  os: "linux",
  image: "memdump.mem",
  sources: [],
  records: new Map(),
  recordList: [],
  pagecache: [],
  modules: [],
  syscalls: [],
  findings: [],
  roots: [],
  selectedPid: null,
  analyzing: false,
  error: null,

  setOs: (os) => set({ os }),
  setImage: (image) => set({ image }),
  selectPid: (pid) => set({ selectedPid: pid }),

  ingestFiles: async (files) => {
    set({ analyzing: true, error: null });
    try {
      const state = get();
      const records = new Map(state.records);
      let pagecache = [...state.pagecache];
      let modules = [...state.modules];
      let syscalls = [...state.syscalls];
      const sources = [...state.sources];

      for (const file of files) {
        const parsed = parseCsv(file.text);
        if (!parsed.headers.length) continue;
        const kind = (pluginToKind(file.plugin) ??
          classifyPlugin(parsed.headers)) as ReturnType<typeof classifyPlugin>;
        sources.push({ name: file.name, plugin: kind, rows: parsed.rows.length });
        if (kind === "pagecache") {
          pagecache = pagecache.concat(parsePagecache(parsed));
        } else if (kind === "modules") {
          modules = modules.concat(parseModules(parsed));
        } else if (kind === "hidden_modules") {
          modules = modules.concat(
            parseModules(parsed, { hidden: true, source: "hidden_modules" })
          );
        } else if (kind === "syscalls") {
          syscalls = syscalls.concat(parseSyscalls(parsed));
        } else {
          mergeIntoRecords(records, kind, parsed);
        }
      }

      const recordList = [...records.values()];
      const { roots } = buildTree(records);

      const engine = await loadEngine(state.os);
      const findings = engine.analyze({ records: recordList, pagecache, modules, syscalls });

      set({
        records,
        recordList,
        pagecache,
        modules,
        syscalls,
        sources,
        roots,
        findings,
        analyzing: false,
      });
    } catch (e) {
      set({ analyzing: false, error: (e as Error).message });
    }
  },

  reset: () =>
    set({
      sources: [],
      records: new Map(),
      recordList: [],
      pagecache: [],
      modules: [],
      syscalls: [],
      findings: [],
      roots: [],
      selectedPid: null,
      error: null,
    }),
}));
