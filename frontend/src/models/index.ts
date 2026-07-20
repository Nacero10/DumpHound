// Domain models shared across the frontend.

export type OsName = "linux" | "windows";

export type PluginKind =
  | "pstree"
  | "history"
  | "sockets"
  | "lsof"
  | "envars"
  | "modules"
  | "hidden_modules"
  | "syscalls"
  | "spoofing"
  | "malfind"
  | "pagecache"
  | "unknown";

export interface CsvSource {
  name: string;
  plugin: PluginKind;
  rows: number;
}

export interface ProcessRecord {
  pid: string;
  ppid?: string;
  comm?: string;
  cmdline?: string;
  uid?: string;
  // Merged from history/sockets/lsof/envars/spoofing/malfind plugins:
  history: HistoryEntry[];
  sockets: SocketEntry[];
  files: FileEntry[];
  envars: Record<string, string>;
  spoof?: SpoofInfo;
  malfind: MalfindEntry[];
  raw: Record<string, string>;
}

export interface HistoryEntry {
  command: string;
  commandTime?: string;
}

export interface SocketEntry {
  proto?: string;
  state?: string;
  localAddr?: string;
  localPort?: string;
  remoteAddr?: string;
}

export interface FileEntry {
  fd?: string;
  path?: string;
}

export interface SpoofInfo {
  commSpoofed?: string;
  cmdlineSpoofed?: string;
  exeDeleted?: string;
}

export interface MalfindEntry {
  protection?: string;
  address?: string;
}

export interface PagecacheFile {
  superblockAddr?: string;
  mountPoint?: string;
  device?: string;
  inodeNum?: string;
  inodeAddr?: string;
  fileType?: string;
  inodePages?: number;
  cachedPages?: number;
  fileMode?: string;
  accessTime?: string;
  modificationTime?: string;
  changeTime?: string;
  filePath: string;
  inodeSize?: number;
  raw: Record<string, string>;
}

export interface KernelModule {
  name: string;
  status?: string;
  taints?: string;
  address?: string;
  size?: string;
  /** True when sourced from hidden_modules (unlinked from the module list). */
  hidden?: boolean;
  /** Originating plugin: "lsmod" | "hidden_modules" | "check_modules". */
  source?: string;
  raw: Record<string, string>;
}

export interface SyscallEntry {
  table?: string;
  index?: string;
  handler?: string;
  symbol?: string;
  /** True when Volatility flagged the entry changed/hooked. */
  changed?: boolean;
  raw: Record<string, string>;
}

export type FindingLevel = "alert" | "warn" | "info";

export interface MitreRef {
  id: string;
  name?: string;
  tactic?: string;
  url: string;
}

export interface Finding {
  level: FindingLevel;
  rule: string;
  technique?: string;
  target: string;
  detail: string;
  mitre?: MitreRef[];
}

// Tree node used by the D3 renderer.
export interface TreeNode {
  pid: string;
  record: ProcessRecord;
  children: TreeNode[];
}
