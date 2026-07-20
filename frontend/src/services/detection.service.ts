// Client-side detection engine. Loads the same data-driven rule files the
// backend uses (served from /rules/*.json) so analysis works fully offline.
import type {
  Finding,
  KernelModule,
  MitreRef,
  OsName,
  PagecacheFile,
  ProcessRecord,
  SyscallEntry,
} from "@/models";

interface MatchBlock {
  path_eq?: string;
  path_contains?: string;
  path_not_contains?: string;
  path_contains_any?: string[];
  path_ext?: string[];
  path_regex?: string;
  parent_comm_in?: string[];
  child_comm_in?: string[];
  cmd_regex?: string;
  cmd_flags?: string;
  state_in?: string[];
  proto_in?: string[];
  local_port_gte?: number;
  local_port_not_in?: number[];
  field_truthy?: string;
  field_eq?: Record<string, string>;
  field_regex?: { field: string; pattern: string; flags?: string };
  comm_in?: string[];
}

interface Rule {
  id: string;
  level: Finding["level"];
  technique?: string;
  detail: string;
  match: MatchBlock;
}

interface RuleSet {
  os: string;
  pagecache: Rule[];
  lineage: Rule[];
  command: Rule[];
  network: Rule[];
  spoofing: Rule[];
  malfind: Rule[];
  modules: Rule[];
  syscalls?: Rule[];
}

interface MitreData {
  base_url: string;
  techniques: Record<string, { name?: string; tactic?: string }>;
}

const truthy = (v: string | undefined): boolean => {
  if (!v) return false;
  const s = v.trim().toLowerCase();
  if (["0", "false", "no", "n", "-", "none", ""].includes(s)) return false;
  return true;
};

function pathMatches(path: string, m: MatchBlock): boolean {
  const p = path.toLowerCase();
  if (m.path_eq && path !== m.path_eq) return false;
  if (m.path_contains && !p.includes(m.path_contains.toLowerCase())) return false;
  if (m.path_not_contains && p.includes(m.path_not_contains.toLowerCase())) return false;
  if (m.path_contains_any && !m.path_contains_any.some((s) => p.includes(s.toLowerCase())))
    return false;
  if (m.path_ext && !m.path_ext.some((e) => p.endsWith(e.toLowerCase()))) return false;
  if (m.path_regex && !new RegExp(m.path_regex).test(path)) return false;
  return true;
}

const commOf = (r: ProcessRecord): string => (r.comm ?? r.raw["Comm"] ?? "").toLowerCase();
const commIn = (r: ProcessRecord, names?: string[]): boolean =>
  !!names && names.some((n) => commOf(r) === n.toLowerCase() || commOf(r).startsWith(n.toLowerCase()));

/** Look up a field by name from an explicit map then a raw row (case-insensitive). */
function fieldValue(
  fields: Record<string, string | boolean | undefined>,
  raw: Record<string, string>,
  key: string
): string {
  const direct = fields[key];
  if (direct !== undefined && direct !== "") {
    return typeof direct === "boolean" ? (direct ? "true" : "") : direct;
  }
  const lower = key.toLowerCase();
  for (const k of Object.keys(raw)) {
    if (k.toLowerCase() === lower) return raw[k];
  }
  return "";
}

/** Evaluate field_truthy / field_eq / field_regex against a flat evidence row. */
function fieldMatches(
  m: MatchBlock,
  fields: Record<string, string | boolean | undefined>,
  raw: Record<string, string>
): boolean {
  if (m.field_truthy && !truthy(fieldValue(fields, raw, m.field_truthy))) return false;
  if (m.field_eq) {
    for (const [k, v] of Object.entries(m.field_eq)) {
      if (fieldValue(fields, raw, k).trim().toUpperCase() !== v.trim().toUpperCase())
        return false;
    }
  }
  if (m.field_regex) {
    const re = new RegExp(m.field_regex.pattern, m.field_regex.flags ?? "");
    if (!re.test(fieldValue(fields, raw, m.field_regex.field))) return false;
  }
  return true;
}

export class MitreMapper {
  constructor(private data: MitreData) {}
  url(tid: string): string {
    const parts = tid.split(".");
    return parts.length === 2
      ? `${this.data.base_url}${parts[0]}/${parts[1]}/`
      : `${this.data.base_url}${parts[0]}/`;
  }
  refs(technique?: string): MitreRef[] | undefined {
    if (!technique) return undefined;
    return technique
      .split(/[·,]/)
      .map((t) => t.trim())
      .filter(Boolean)
      .map((id) => ({
        id,
        name: this.data.techniques[id]?.name,
        tactic: this.data.techniques[id]?.tactic,
        url: this.url(id),
      }));
  }
}

export class DetectionEngine {
  constructor(
    private rules: RuleSet,
    private mapper: MitreMapper
  ) {}

  private mk(rule: Rule, target: string): Finding {
    return {
      level: rule.level,
      rule: rule.id,
      technique: rule.technique,
      target,
      detail: rule.detail,
      mitre: this.mapper.refs(rule.technique),
    };
  }

  analyze(input: {
    records: ProcessRecord[];
    pagecache: PagecacheFile[];
    modules: KernelModule[];
    syscalls?: SyscallEntry[];
  }): Finding[] {
    const out: Finding[] = [];
    out.push(...this.lineage(input.records));
    out.push(...this.command(input.records));
    out.push(...this.network(input.records));
    out.push(...this.malfind(input.records));
    out.push(...this.spoofing(input.records));
    out.push(...this.pagecache(input.pagecache));
    out.push(...this.modules(input.modules));
    out.push(...this.syscalls(input.syscalls ?? []));
    return out;
  }

  private lineage(records: ProcessRecord[]): Finding[] {
    const byPid = new Map(records.map((r) => [r.pid, r]));
    const out: Finding[] = [];
    for (const child of records) {
      const parent = child.ppid ? byPid.get(child.ppid) : undefined;
      if (!parent) continue;
      for (const rule of this.rules.lineage) {
        if (commIn(parent, rule.match.parent_comm_in) && commIn(child, rule.match.child_comm_in)) {
          out.push(this.mk(rule, `${commOf(parent)}(${parent.pid}) -> ${commOf(child)}(${child.pid})`));
        }
      }
    }
    return out;
  }

  private command(records: ProcessRecord[]): Finding[] {
    const out: Finding[] = [];
    for (const r of records) {
      const cmds = [r.cmdline ?? "", ...r.history.map((h) => h.command)].filter(Boolean);
      for (const cmd of cmds) {
        for (const rule of this.rules.command) {
          if (!rule.match.cmd_regex) continue;
          const re = new RegExp(rule.match.cmd_regex, rule.match.cmd_flags ?? "");
          if (re.test(cmd)) out.push(this.mk(rule, cmd.slice(0, 160)));
        }
      }
    }
    return out;
  }

  private network(records: ProcessRecord[]): Finding[] {
    const out: Finding[] = [];
    for (const r of records) {
      for (const s of r.sockets) {
        for (const rule of this.rules.network) {
          const m = rule.match;
          const proto = (s.proto ?? "").toUpperCase();
          const state = (s.state ?? "").toUpperCase();
          if (m.proto_in && !m.proto_in.map((x) => x.toUpperCase()).includes(proto)) continue;
          if (m.state_in && !m.state_in.map((x) => x.toUpperCase()).includes(state)) continue;
          const port = Number(s.localPort) || Number(s.localAddr?.split(":").pop());
          if (m.local_port_gte !== undefined && (!port || port < m.local_port_gte)) continue;
          if (m.local_port_not_in && m.local_port_not_in.includes(port)) continue;
          out.push(this.mk(rule, `${proto || "sock"} ${s.localAddr ?? ""}:${port || "?"} ${state}`));
        }
      }
    }
    return out;
  }

  private malfind(records: ProcessRecord[]): Finding[] {
    const out: Finding[] = [];
    const jitRule = this.rules.malfind.find((r) => r.id === "rwx_region_jit");
    for (const r of records) {
      for (const mf of r.malfind) {
        const rwx = (mf.protection ?? "").toLowerCase().includes("rwx");
        if (!rwx) continue;
        for (const rule of this.rules.malfind) {
          if (rule.match.comm_in && !commIn(r, rule.match.comm_in)) continue;
          if (
            rule.id === "rwx_region" &&
            jitRule &&
            commIn(r, jitRule.match.comm_in)
          )
            continue;
          out.push(this.mk(rule, `${commOf(r)}(${r.pid}) ${mf.address ?? ""}`));
        }
      }
    }
    return out;
  }

  private spoofing(records: ProcessRecord[]): Finding[] {
    const out: Finding[] = [];
    for (const r of records) {
      if (!r.spoof) continue;
      for (const rule of this.rules.spoofing) {
        const key = rule.match.field_truthy;
        const val =
          key === "comm_spoofed"
            ? r.spoof.commSpoofed
            : key === "exe_deleted"
              ? r.spoof.exeDeleted
              : undefined;
        if (truthy(val)) out.push(this.mk(rule, `${commOf(r)}(${r.pid})`));
      }
    }
    return out;
  }

  private pagecache(files: PagecacheFile[]): Finding[] {
    const out: Finding[] = [];
    for (const f of files) {
      if (!f.filePath) continue;
      for (const rule of this.rules.pagecache) {
        if (pathMatches(f.filePath, rule.match)) out.push(this.mk(rule, f.filePath));
      }
    }
    return out;
  }

  private modules(mods: KernelModule[]): Finding[] {
    const out: Finding[] = [];
    for (const mod of mods) {
      const fields = {
        name: mod.name,
        status: mod.status,
        taints: mod.taints,
        address: mod.address,
        hidden: mod.hidden,
        source: mod.source,
      };
      for (const rule of this.rules.modules) {
        if (fieldMatches(rule.match, fields, mod.raw)) {
          const label = mod.hidden ? `${mod.name} (hidden)` : mod.name;
          out.push(this.mk(rule, label));
        }
      }
    }
    return out;
  }

  private syscalls(entries: SyscallEntry[]): Finding[] {
    const rules = this.rules.syscalls ?? [];
    if (!rules.length) return [];
    const out: Finding[] = [];
    for (const e of entries) {
      const fields = {
        table: e.table,
        index: e.index,
        handler: e.handler,
        symbol: e.symbol,
        changed: e.changed,
      };
      for (const rule of rules) {
        if (fieldMatches(rule.match, fields, e.raw)) {
          const sym = e.symbol || "UNKNOWN";
          out.push(this.mk(rule, `${e.table || "syscall"}[${e.index ?? "?"}] ${sym}`));
        }
      }
    }
    return out;
  }
}

let cache: { os: OsName; engine: DetectionEngine } | null = null;

/** Load rule files (cached) and build an engine for the given OS. */
export async function loadEngine(os: OsName): Promise<DetectionEngine> {
  if (cache && cache.os === os) return cache.engine;
  const [rules, mitre] = await Promise.all([
    fetch(`/rules/${os}.json`).then((r) => r.json() as Promise<RuleSet>),
    fetch(`/rules/mitre.json`).then((r) => r.json() as Promise<MitreData>),
  ]);
  const engine = new DetectionEngine(rules, new MitreMapper(mitre));
  cache = { os, engine };
  return engine;
}
