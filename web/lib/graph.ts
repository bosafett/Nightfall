import type { GraphData, GraphNodeData } from "./api/types";

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
