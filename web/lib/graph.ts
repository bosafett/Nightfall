import type { GEdge, GNode, GraphData, GraphNodeData, ProjectGraph, Severity } from "./api/types";

export type Positioned = GraphNodeData & { x: number; y: number };

const COL_X = { organization: 0, project: 320 } as const;
const ROW = 72;
const GROUP_GAP = 32;

/**
 * Deterministic two-column layout: each organization sits level with the middle of its
 * projects. Pure function (unit-tested); later phases add columns for assets/findings.
 */
export function layoutGraph(graph: GraphData): Positioned[] {
  const children = new Map<string, string[]>();
  for (const e of graph.edges) children.set(e.source, [...(children.get(e.source) ?? []), e.target]);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const out: Positioned[] = [];
  let y = 0;
  for (const n of graph.nodes) {
    if (n.kind !== "organization") continue;
    const kids = (children.get(n.id) ?? []).map((id) => byId.get(id)).filter((k): k is GraphNodeData => !!k);
    const rows = Math.max(kids.length, 1);
    out.push({ ...n, x: COL_X.organization, y: y + ((rows - 1) * ROW) / 2 });
    kids.forEach((k, i) => out.push({ ...k, x: COL_X.project, y: y + i * ROW }));
    y += rows * ROW + GROUP_GAP;
  }
  return out;
}

/** Where a node opens: its record in the Target Registry. */
export function nodeHref(ws: string, node: GraphNodeData, graph: GraphData): string {
  if (node.kind === "organization") return `/w/${ws}/targets/${node.record_id}`;
  const parent = graph.edges.find((e) => e.target === node.id)?.source.replace(/^org:/, "");
  return `/w/${ws}/targets/${parent}/projects/${node.record_id}`;
}


export type GraphFilters = {
  edgeKinds: Set<GEdge["kind"]>;
  minSeverity: Severity;
  showHypotheses: boolean;
  collapsed: Set<string>; // asset node ids whose subdomains are hidden
};

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const COLUMN: Record<string, number> = { domain: 0, hostname: 1, ip_range: 2, ip_address: 2 };

/** Which nodes and edges survive the filters. Pure; unit-tested. */
export function filterGraph(g: ProjectGraph, f: GraphFilters): { nodes: GNode[]; edges: GEdge[] } {
  const hidden = new Set<string>();
  // Collapsing an asset hides its subdomains (recursively) and what hangs off them.
  const childrenOf = new Map<string, string[]>();
  for (const e of g.edges) if (e.kind === "subdomain_of") childrenOf.set(e.target, [...(childrenOf.get(e.target) ?? []), e.source]);
  const hideTree = (id: string) => (childrenOf.get(id) ?? []).forEach((c) => { if (!hidden.has(c)) { hidden.add(c); hideTree(c); } });
  f.collapsed.forEach(hideTree);
  const maxRank = SEV_ORDER.indexOf(f.minSeverity);
  for (const n of g.nodes) {
    if (n.kind !== "finding") continue;
    if (n.severity && SEV_ORDER.indexOf(n.severity) > maxRank) hidden.add(n.id);
    if (!f.showHypotheses && n.status === "hypothesis") hidden.add(n.id);
    if (n.status === "false_positive" || n.status === "remediated") hidden.add(n.id);
  }
  for (const e of g.edges) if (e.kind === "affects" && hidden.has(e.target)) hidden.add(e.source);
  const nodes = g.nodes.filter((n) => !hidden.has(n.id));
  const keep = new Set(nodes.map((n) => n.id));
  const edges = g.edges.filter((e) => f.edgeKinds.has(e.kind) && keep.has(e.source) && keep.has(e.target)
    && (f.showHypotheses || (e.status !== "hypothesis")));
  return { nodes, edges };
}

/** Deterministic columns: domains → hostnames → IPs → findings (next to their asset). */
export function layoutProjectGraph(nodes: GNode[], edges: GEdge[]): Map<string, { x: number; y: number }> {
  const pos = new Map<string, { x: number; y: number }>();
  const rows = [0, 0, 0, 0];
  const assets = nodes.filter((n) => n.kind === "asset");
  for (const n of assets) {
    const col = COLUMN[n.asset_kind ?? ""] ?? 1;
    pos.set(n.id, { x: col * 300, y: rows[col]! * 80 });
    rows[col]! += 1;
  }
  const affects = new Map(edges.filter((e) => e.kind === "affects").map((e) => [e.source, e.target]));
  const used = new Set<number>();
  for (const n of nodes.filter((x) => x.kind === "finding")) {
    const anchor = pos.get(affects.get(n.id) ?? "");
    let y = anchor ? anchor.y : rows[3]! * 80;
    while (used.has(y)) y += 80;
    used.add(y);
    pos.set(n.id, { x: 3 * 300 + 40, y });
    rows[3]! += 1;
  }
  return pos;
}
