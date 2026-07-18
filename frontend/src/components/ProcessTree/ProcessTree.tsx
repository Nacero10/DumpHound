// Interactive process graph. Two layouts share one render:
//   • "tree"  — tidy hierarchical lineage (nodes pinned to a dendrogram)
//   • "force" — organic force-directed graph (free physics)
// In both, nodes are draggable (drag pins a node; double-click releases it),
// and the canvas supports scroll-zoom + pan. Severity coloring comes from the
// detection findings; selecting a node drives the Inspector.
import { useEffect, useMemo, useRef, useState } from "react";
import * as d3 from "d3";
import type { TreeNode } from "@/models";
import { useAppStore } from "@/stores/app.store";

interface GNode extends d3.SimulationNodeDatum {
  id: string;
  node: TreeNode;
  depth: number;
  category: ProcCategory;
}
interface GLink extends d3.SimulationLinkDatum<GNode> {
  source: string | GNode;
  target: string | GNode;
}

type LayoutMode = "tree" | "force";

const R = 16;
const ROW_GAP = 160;           // more vertical breathing room
const COL_GAP = 100;           // wider between levels in tree mode
const FORCE_LINK_DIST = { tree: 110, force: 140 };
const FORCE_CHARGE = { tree: -180, force: -480 };

type ProcCategory = "clean" | "suspicious" | "alert" | "hidden" | "system";

const SUSPICIOUS_PATTERNS = /\b(kworker|kthread|systemd|init|kernel|ksoftirqd|migration|watchdog|kswapd|kthrotld|kdevtmpfs)\b/i;
const MALWARE_PATTERNS = /\b(rootkit|diamorphine|evilrk|injected|mimikatz|metasploit|shellcode|dropper|loader|payload)\b/i;

const commOf = (n: TreeNode): string =>
  n.record?.comm ?? n.record?.raw?.["Comm"] ?? "?";

function flaggedPids(findings: { level: string; target: string }[]): Map<string, "alert" | "warn"> {
  const map = new Map<string, "alert" | "warn">();
  for (const f of findings) {
    const matches = f.target.match(/\((\d+)\)/g);
    if (!matches) continue;
    for (const g of matches) {
      const pid = g.replace(/[()]/g, "");
      const cur = map.get(pid);
      if (f.level === "alert") map.set(pid, "alert");
      else if (f.level === "warn" && cur !== "alert") map.set(pid, "warn");
    }
  }
  return map;
}

function categorizeProcess(
  n: TreeNode,
  depth: number,
  flagged: Map<string, "alert" | "warn">,
  orphan: boolean
): ProcCategory {
  const pid = n.pid;
  const comm = commOf(n);

  // Findings take absolute priority.
  if (flagged.has(pid)) {
    return flagged.get(pid) === "alert" ? "alert" : "suspicious";
  }

  // Orphan or deep-hidden process → flag for closer inspection.
  if (orphan || depth > 8) {
    return "hidden";
  }

  // System / kernel processes → de-emphasize.
  if (SUSPICIOUS_PATTERNS.test(comm)) {
    return "system";
  }

  // Known malware patterns in the process name.
  if (MALWARE_PATTERNS.test(comm)) {
    return "alert";
  }

  // Unusual process names or suspicious spawning patterns can go here.
  if (/^[A-Z]{3,}\.exe$/i.test(comm) || comm === "?" || !comm) {
    return "suspicious";
  }

  return "clean";
}

function buildGraph(
  roots: TreeNode[],
  flagged: Map<string, "alert" | "warn">
): { nodes: GNode[]; links: GLink[] } {
  const nodes: GNode[] = [];
  const links: GLink[] = [];
  const seen = new Set<string>();
  const walk = (n: TreeNode, depth: number, isOrphan: boolean) => {
    if (seen.has(n.pid)) return;
    seen.add(n.pid);
    nodes.push({
      id: n.pid,
      node: n,
      depth,
      category: categorizeProcess(n, depth, flagged, isOrphan),
    });
    for (const c of n.children) {
      links.push({ source: n.pid, target: c.pid });
      walk(c, depth + 1, false);
    }
  };
  roots.forEach((r) => walk(r, 0, false));
  return { nodes, links };
}

/** Tidy (dendrogram) coordinates keyed by pid, for the "tree" layout. */
function tidyPositions(roots: TreeNode[]): Map<string, { x: number; y: number }> {
  const synthetic: TreeNode = {
    pid: "__root__",
    record: undefined as unknown as TreeNode["record"],
    children: roots,
  };
  const h = d3.hierarchy<TreeNode>(synthetic, (d) => d.children);
  const layout = d3.tree<TreeNode>().nodeSize([COL_GAP, ROW_GAP]);
  const laid = layout(h);
  const pos = new Map<string, { x: number; y: number }>();
  laid.descendants().forEach((d) => {
    if (d.data.pid !== "__root__") pos.set(d.data.pid, { x: d.x, y: d.y });
  });
  return pos;
}

export function ProcessTree() {
  const roots = useAppStore((s) => s.roots);
  const findings = useAppStore((s) => s.findings);
  const selectedPid = useAppStore((s) => s.selectedPid);
  const selectPid = useAppStore((s) => s.selectPid);

  const [layout, setLayout] = useState<LayoutMode>("tree");

  const svgRef = useRef<SVGSVGElement | null>(null);
  const gRef = useRef<SVGGElement | null>(null);
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const simRef = useRef<d3.Simulation<GNode, GLink> | null>(null);
  const selRef = useRef<string | null>(selectedPid);
  const flaggedRef = useRef<Map<string, "alert" | "warn">>(new Map());

  const flagged = useMemo(() => flaggedPids(findings), [findings]);
  flaggedRef.current = flagged;
  selRef.current = selectedPid;

  const graph = useMemo(() => buildGraph(roots, flagged), [roots, flagged]);
  const tidy = useMemo(() => tidyPositions(roots), [roots]);

  const fit = () => {
    const svg = svgRef.current;
    const sim = simRef.current;
    if (!svg || !zoomRef.current) return;
    const ns = (sim?.nodes() ?? []) as GNode[];
    if (!ns.length) return;
    const xs = ns.map((n) => n.x ?? 0);
    const ys = ns.map((n) => n.y ?? 0);
    const minX = Math.min(...xs) - 60;
    const maxX = Math.max(...xs) + 60;
    const minY = Math.min(...ys) - 60;
    const maxY = Math.max(...ys) + 60;
    const w = svg.clientWidth || 800;
    const h = svg.clientHeight || 600;
    const scale = Math.min(2, 0.9 / Math.max((maxX - minX) / w, (maxY - minY) / h));
    const tx = w / 2 - ((minX + maxX) / 2) * scale;
    const ty = h / 2 - ((minY + maxY) / 2) * scale;
    d3.select(svg)
      .transition()
      .duration(300)
      .call(
        zoomRef.current.transform,
        d3.zoomIdentity.translate(tx, ty).scale(Number.isFinite(scale) ? scale : 1)
      );
  };

  // Build / rebuild the graph + simulation when the data or layout changes.
  useEffect(() => {
    if (!svgRef.current || !gRef.current) return;
    const svgEl = svgRef.current;
    const svg = d3.select<SVGSVGElement, unknown>(svgEl);
    const g = d3.select<SVGGElement, unknown>(gRef.current);

    const nodes = graph.nodes.map((n) => ({ ...n }));
    const links = graph.links.map((l) => ({ ...l }));

    // Seed positions from the tidy layout so both modes start readable.
    for (const n of nodes) {
      const p = tidy.get(n.id);
      if (p) {
        n.x = p.x;
        n.y = p.y;
      }
    }

    const sim = d3
      .forceSimulation<GNode>(nodes)
      .force(
        "link",
        d3
          .forceLink<GNode, GLink>(links)
          .id((d) => d.id)
          .distance(FORCE_LINK_DIST[layout])
          .strength(layout === "tree" ? 0.2 : 0.5)
      )
      .force("charge", d3.forceManyBody<GNode>().strength(FORCE_CHARGE[layout]))
      .force("collide", d3.forceCollide<GNode>(R + 18))
      .force("y", d3.forceY<GNode>((d) => d.depth * ROW_GAP).strength(layout === "tree" ? 0.95 : 0.3))
      .force("x", d3.forceX<GNode>(0).strength(layout === "tree" ? 0.02 : 0.03));

    if (layout === "tree") {
      // Pin every node to its tidy coordinate; dragging overrides individually.
      for (const n of nodes) {
        const p = tidy.get(n.id);
        if (p) {
          n.fx = p.x;
          n.fy = p.y;
        }
      }
    }
    simRef.current = sim;

    // Links
    const link = g
      .selectAll<SVGLineElement, GLink>("line.glink")
      .data(links)
      .join("line")
      .attr("class", "glink");

    // Nodes
    const drag = d3
      .drag<SVGGElement, GNode>()
      .on("start", (event, d) => {
        if (!event.active) sim.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", (event) => {
        if (!event.active) sim.alphaTarget(0);
        // Keep the node pinned where the user dropped it (manual positioning).
      });

    const node = g
      .selectAll<SVGGElement, GNode>("g.gnode")
      .data(nodes, (d) => d.id)
      .join((enter) => {
        const ge = enter.append("g").attr("class", "gnode");
        ge.append("circle").attr("r", R);
        ge.append("text")
          .attr("class", "gnode-comm")
          .attr("x", R + 6)
          .attr("dy", -1);
        ge.append("text")
          .attr("class", "gnode-pid")
          .attr("x", R + 6)
          .attr("dy", 11);
        return ge;
      })
      .call(drag)
      .style("cursor", "grab")
      .on("click", (_e, d) => selectPid(d.id === selRef.current ? null : d.id))
      .on("dblclick", (_e, d) => {
        // Release a pinned node back into the simulation (force mode).
        d.fx = null;
        d.fy = null;
        sim.alphaTarget(0.3).restart();
        window.setTimeout(() => sim.alphaTarget(0), 400);
      });

    node.select<SVGTextElement>("text.gnode-comm").text((d) => {
      const c = commOf(d.node);
      return c.length > 22 ? c.slice(0, 21) + "…" : c;
    });
    node.select<SVGTextElement>("text.gnode-pid").text((d) => `pid ${d.id}`);

    const restyle = () => {
      node
        .classed("selected", (d) => d.id === selRef.current)
        .classed("cat-clean", (d) => d.category === "clean")
        .classed("cat-system", (d) => d.category === "system")
        .classed("cat-suspicious", (d) => d.category === "suspicious")
        .classed("cat-alert", (d) => d.category === "alert")
        .classed("cat-hidden", (d) => d.category === "hidden");
    };
    restyle();
    (svgEl as unknown as { __restyle?: () => void }).__restyle = restyle;

    sim.on("tick", () => {
      link
        .attr("x1", (d) => (d.source as GNode).x ?? 0)
        .attr("y1", (d) => (d.source as GNode).y ?? 0)
        .attr("x2", (d) => (d.target as GNode).x ?? 0)
        .attr("y2", (d) => (d.target as GNode).y ?? 0);
      node.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
    });

    // Zoom / pan (set up once).
    if (!zoomRef.current) {
      zoomRef.current = d3
        .zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.15, 2.8])
        .filter((event) => !(event.target as Element).closest(".gnode"))
        .on("zoom", (event) => g.attr("transform", event.transform.toString()));
      svg.call(zoomRef.current);
      svg.on("dblclick.zoom", null);
    }

    sim.alpha(0.9).restart();
    const fitTimer = window.setTimeout(fit, layout === "tree" ? 120 : 600);

    return () => {
      window.clearTimeout(fitTimer);
      sim.stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, tidy, layout, selectPid]);

  // Restyle only (selection / findings) without rebuilding the simulation.
  useEffect(() => {
    const r = (svgRef.current as unknown as { __restyle?: () => void })?.__restyle;
    if (r) r();
  }, [selectedPid, flagged]);

  // Safe to branch now — every hook above runs unconditionally on every render.
  if (!roots.length) {
    return (
      <div className="tree-empty">
        No process records yet. Load a <code>pstree</code> CSV to build the graph.
      </div>
    );
  }

  return (
    <div className="proctree-wrap">
      <div className="graph-toolbar">
        <div className="seg">
          <button
            className={layout === "tree" ? "seg-btn seg-active" : "seg-btn"}
            onClick={() => setLayout("tree")}
          >
            Tree
          </button>
          <button
            className={layout === "force" ? "seg-btn seg-active" : "seg-btn"}
            onClick={() => setLayout("force")}
          >
            Force
          </button>
        </div>
        <button className="btn btn-sm" onClick={fit} title="Fit graph to view">
          Fit
        </button>
      </div>
      <div className="graph-legend">
        <span className="legend-item">
          <span className="legend-dot legend-clean" />
          Benign
        </span>
        <span className="legend-item">
          <span className="legend-dot legend-system" />
          System
        </span>
        <span className="legend-item">
          <span className="legend-dot legend-suspicious" />
          Suspicious
        </span>
        <span className="legend-item">
          <span className="legend-dot legend-alert" />
          Alert
        </span>
        <span className="legend-item">
          <span className="legend-dot legend-hidden" />
          Hidden
        </span>
      </div>
      <svg ref={svgRef} className="proctree-svg" width="100%" height="100%">
        <g ref={gRef} />
      </svg>
    </div>
  );
}
