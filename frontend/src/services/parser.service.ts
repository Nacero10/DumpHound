// CSV parsing + Volatility plugin classification (no external deps).
import type {
  KernelModule,
  PagecacheFile,
  PluginKind,
  ProcessRecord,
  SyscallEntry,
} from "@/models";

export interface ParsedCsv {
  headers: string[];
  rows: Record<string, string>[];
}

/** Minimal RFC-4180-ish CSV parser handling quoted fields and embedded commas. */
export function parseCsv(text: string): ParsedCsv {
  const rows: string[][] = [];
  let field = "";
  let row: string[] = [];
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      if (row.some((v) => v !== "")) rows.push(row);
      row = [];
    } else {
      field += c;
    }
  }
  if (field !== "" || row.length) {
    row.push(field);
    if (row.some((v) => v !== "")) rows.push(row);
  }
  if (!rows.length) return { headers: [], rows: [] };
  const headers = rows[0].map((h) => h.trim());
  const records = rows.slice(1).map((r) => {
    const obj: Record<string, string> = {};
    headers.forEach((h, idx) => (obj[h] = (r[idx] ?? "").trim()));
    return obj;
  });
  return { headers, rows: records };
}

const has = (set: Set<string>, ...keys: string[]) => keys.some((k) => set.has(k));

/** Infer which Volatility plugin produced a CSV from its header columns alone. */
export function classifyPlugin(headers: string[]): PluginKind {
  const h = new Set(headers.map((x) => x.toLowerCase().trim()));
  if (has(h, "filepath") && (has(h, "inodeaddr") || has(h, "inodenum")) && !h.has("pid"))
    return "pagecache";
  if (has(h, "comm_spoofed", "cmdline_spoofed", "exe_deleted")) return "spoofing";
  if (h.has("pid") && h.has("protection") && (h.has("disasm") || h.has("hexdump")))
    return "malfind";
  if (has(h, "command") && has(h, "commandtime", "command time")) return "history";
  if (has(h, "proto", "protocol") && h.has("state")) return "sockets";
  if (h.has("pid") && h.has("fd") && h.has("path")) return "lsof";
  if (h.has("pid") && h.has("key") && h.has("value")) return "envars";
  // check_syscall: index + (symbol|handler address), no pid.
  if (!h.has("pid") && has(h, "index", "idx") && has(h, "symbol", "handler address", "handler"))
    return "syscalls";
  // lsmod / check_modules: has the "taints" or "status" column.
  if (has(h, "module name") || (has(h, "name", "module") && has(h, "taints", "status")))
    return "modules";
  // hidden_modules: name + address/size, no taints/status, no pid/filepath.
  if (
    !h.has("pid") &&
    !h.has("filepath") &&
    has(h, "name", "module name", "module") &&
    has(h, "address", "module address", "offset", "size", "module size") &&
    !has(h, "taints", "status")
  )
    return "hidden_modules";
  if (h.has("pid") && has(h, "comm", "process", "name")) return "pstree";
  return "unknown";
}

const pick = (row: Record<string, string>, ...keys: string[]): string => {
  const lower: Record<string, string> = {};
  for (const k of Object.keys(row)) lower[k.toLowerCase()] = row[k];
  for (const k of keys) {
    const v = lower[k.toLowerCase()];
    if (v) return v;
  }
  return "";
};

function blankRecord(pid: string, raw: Record<string, string>): ProcessRecord {
  return {
    pid,
    history: [],
    sockets: [],
    files: [],
    envars: {},
    malfind: [],
    raw,
  };
}

/** Merge a classified CSV into the per-PID process map (mutates + returns it). */
export function mergeIntoRecords(
  records: Map<string, ProcessRecord>,
  kind: PluginKind,
  parsed: ParsedCsv
): void {
  for (const row of parsed.rows) {
    const pid = pick(row, "pid");
    if (!pid && kind !== "modules") continue;
    let rec = records.get(pid);
    if (!rec && pid) {
      rec = blankRecord(pid, row);
      records.set(pid, rec);
    }
    if (!rec) continue;

    switch (kind) {
      case "pstree":
        rec.ppid = pick(row, "ppid", "parent", "parentpid") || rec.ppid;
        rec.comm = pick(row, "comm", "process", "name") || rec.comm;
        rec.cmdline = pick(row, "args", "cmdline") || rec.cmdline;
        rec.uid = pick(row, "uid", "user") || rec.uid;
        break;
      case "history":
        rec.history.push({
          command: pick(row, "command", "cmd"),
          commandTime: pick(row, "commandtime", "command time"),
        });
        break;
      case "sockets":
        rec.sockets.push({
          proto: pick(row, "proto", "protocol"),
          state: pick(row, "state"),
          localAddr: pick(row, "localaddr", "local", "source"),
          localPort: pick(row, "localport", "local_port"),
          remoteAddr: pick(row, "remoteaddr", "remote", "destination"),
        });
        break;
      case "lsof":
        rec.files.push({ fd: pick(row, "fd"), path: pick(row, "path") });
        break;
      case "envars":
        rec.envars[pick(row, "key")] = pick(row, "value");
        break;
      case "spoofing":
        rec.spoof = {
          commSpoofed: pick(row, "comm_spoofed"),
          cmdlineSpoofed: pick(row, "cmdline_spoofed"),
          exeDeleted: pick(row, "exe_deleted"),
        };
        break;
      case "malfind":
        rec.malfind.push({
          protection: pick(row, "protection", "prot"),
          address: pick(row, "address", "start"),
        });
        break;
      default:
        break;
    }
  }
}

export function parsePagecache(parsed: ParsedCsv): PagecacheFile[] {
  return parsed.rows.map((row) => ({
    superblockAddr: pick(row, "superblockaddr"),
    mountPoint: pick(row, "mountpoint"),
    device: pick(row, "device"),
    inodeNum: pick(row, "inodenum"),
    inodeAddr: pick(row, "inodeaddr"),
    fileType: pick(row, "filetype"),
    inodePages: Number(pick(row, "inodepages")) || 0,
    cachedPages: Number(pick(row, "cachedpages")) || 0,
    fileMode: pick(row, "filemode"),
    accessTime: pick(row, "accesstime"),
    modificationTime: pick(row, "modificationtime"),
    changeTime: pick(row, "changetime"),
    filePath: pick(row, "filepath", "path", "file"),
    inodeSize: Number(pick(row, "inodesize")) || 0,
    raw: row,
  }));
}

export function parseModules(
  parsed: ParsedCsv,
  opts: { hidden?: boolean; source?: string } = {}
): KernelModule[] {
  return parsed.rows.map((row) => {
    const status = pick(row, "status");
    const taints = pick(row, "taints");
    // Infer source when not supplied: a row carrying neither taints nor status
    // but an address/size most likely came from hidden_modules.
    const address = pick(row, "module address", "address", "offset");
    const inferredHidden =
      opts.hidden ?? (!status && !taints && !!address);
    return {
      name: pick(row, "module name", "name", "module"),
      status,
      taints,
      address,
      size: pick(row, "module size", "size"),
      hidden: inferredHidden,
      source:
        opts.source ?? (inferredHidden ? "hidden_modules" : "lsmod"),
      raw: { ...row, hidden: inferredHidden ? "true" : "" },
    };
  });
}

export function parseSyscalls(parsed: ParsedCsv): SyscallEntry[] {
  return parsed.rows.map((row) => {
    const symbol = pick(row, "symbol", "handler symbol");
    const changedRaw = pick(row, "changed", "hooked").toLowerCase();
    const changed =
      changedRaw === "true" || changedRaw === "1" || changedRaw === "yes";
    return {
      table: pick(row, "table name", "table", "table address", "name"),
      index: pick(row, "index", "idx"),
      handler: pick(row, "handler address", "handler", "address"),
      symbol,
      changed,
      raw: row,
    };
  });
}
