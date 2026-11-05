"use client";

import "@xyflow/react/dist/style.css";
import { Background, Controls, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import Link from "next/link";
import { useMemo, useState } from "react";
import type { GEdge, GNode, ProjectGraph, Severity } from "@/lib/api/types";
import { filterGraph, layoutProjectGraph } from "@/lib/graph";
import { SEVERITIES, severityLabel, statusLabel } from "@/lib/labels";
import { colors } from "@/lib/tokens";
import { SeverityBadge, StatusBadge } from "@/components/findings/Badges";
import { Button, Select, cx } from "@/components/ui/primitives";

const EDGE_KINDS: { kind: GEdge["kind"]; label: string }[] = [
  { kind: "subdomain_of", label: "Subdomain of" }, { kind: "resolves_to", label: "Resolves to" },
  { kind: "cname_to", label: "CNAME to" }, { kind: "affects", label: "Finding affects" }, { kind: "path_step", label: "Attack path step" },
];

type Data = GNode & Record<string, unknown> & { collapsed: boolean; hasChildren: boolean };

function GraphNode({ data, selected }: NodeProps<Node<Data>>) {
  const finding = data.kind === "finding";
  const hyp = data.status === "hypothesis";
  return (
    <div className={cx("w-60 rounded-md border bg-surface px-3 py-2 text-left", finding ? "border-border-strong" : "border-blue/60",
      hyp && "border-dashed", selected && "ring-2 ring-crimson-text")}>
      <Handle type="target" position={Position.Left} isConnectable={false} className="!size-1.5 !border-0 !bg-gray" />
      <p className={cx("text-[10px] uppercase tracking-wider", finding ? "text-muted" : "text-blue-text")}>
        {finding ? "Finding" : (data.asset_kind ?? "asset").replace("_", " ")}{data.collapsed && " · collapsed"}
      </p>
      <p className="truncate text-sm text-text">{data.label}</p>
      {finding && data.severity && <div className="mt-1 flex gap-1"><SeverityBadge severity={data.severity} />{data.status && <StatusBadge status={data.status} />}</div>}
      <Handle type="source" position={Position.Right} isConnectable={false} className="!size-1.5 !border-0 !bg-gray" />
    </div>
  );
}
const nodeTypes = { n: GraphNode };

function edgeStyle(e: GEdge, highlighted: boolean): Partial<Edge> {
  const dashed = e.status === "hypothesis";
  if (e.kind === "path_step") {
    const stroke = e.status === "validated" ? colors.crimson : colors.orange;
    return {
      style: { stroke, strokeWidth: highlighted ? 3.5 : 2.5, strokeDasharray: dashed ? "8 5" : undefined },
      label: `${e.path_title} · ${e.status === "validated" ? "validated" : e.status === "rejected" ? "rejected" : "hypothesis"}`,
      labelStyle: { fill: colors.text, fontSize: 11 }, labelBgStyle: { fill: colors.surface },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke }, animated: false,
    };
  }
  return { style: { stroke: colors.gray, strokeWidth: 1.25, strokeDasharray: dashed ? "6 4" : undefined } };
}

export function AttackGraph({ ws, orgId, graph, highlightPath }: { ws: string; orgId: string; graph: ProjectGraph; highlightPath?: string }) {
  const [edgeKinds, setEdgeKinds] = useState(new Set(EDGE_KINDS.map((k) => k.kind)));
  const [minSeverity, setMinSeverity] = useState<Severity>("info");
  const [showHypotheses, setShowHypotheses] = useState(true);
  const [collapsed, setCollapsed] = useState(new Set<string>());
  const [selected, setSelected] = useState<{ node?: GNode; edge?: GEdge } | null>(null);

  const childCount = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of graph.edges) if (e.kind === "subdomain_of") m.set(e.target, (m.get(e.target) ?? 0) + 1);
    return m;
  }, [graph]);

  const { nodes, edges } = useMemo(() => {
    const view = filterGraph(graph, { edgeKinds, minSeverity, showHypotheses, collapsed });
    const pos = layoutProjectGraph(view.nodes, view.edges);
    return {
      nodes: view.nodes.map((n): Node<Data> => ({
        id: n.id, type: "n", position: pos.get(n.id) ?? { x: 0, y: 0 },
        data: { ...n, collapsed: collapsed.has(n.id), hasChildren: (childCount.get(n.id) ?? 0) > 0 },
        ariaLabel: `${n.kind} ${n.label}`,
      })),
      edges: view.edges.map((e): Edge => ({ id: e.id, source: e.source, target: e.target, ...edgeStyle(e, e.path_id === highlightPath) })),
    };
  }, [graph, edgeKinds, minSeverity, showHypotheses, collapsed, childCount, highlightPath]);

  const toggleKind = (k: GEdge["kind"]) => setEdgeKinds((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  const node = selected?.node;
  const edge = selected?.edge;

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_20rem]">
      <div className="space-y-3">
        <div className="flex flex-wrap items-end gap-x-5 gap-y-2 text-sm">
          <fieldset className="flex flex-wrap gap-3"><legend className="sr-only">Relationship types</legend>
            {EDGE_KINDS.map(({ kind, label }) => (
              <label key={kind} className="flex items-center gap-1.5"><input type="checkbox" checked={edgeKinds.has(kind)} onChange={() => toggleKind(kind)} className="accent-[#CC1426]" />{label}</label>
            ))}
          </fieldset>
          <label className="flex items-center gap-2">Minimum severity
            <Select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value as Severity)} className="w-auto py-1">
              {SEVERITIES.map((s) => <option key={s} value={s}>{severityLabel[s]}</option>)}
            </Select>
          </label>
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={showHypotheses} onChange={(e) => setShowHypotheses(e.target.checked)} className="accent-[#CC1426]" />Show hypotheses</label>
        </div>
        <div className="h-[34rem] overflow-hidden rounded-md border border-border bg-bg" data-testid="attack-graph">
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.15 }} minZoom={0.15}
            nodesDraggable={false} nodesConnectable={false} colorMode="dark"
            onNodeClick={(_, n) => setSelected({ node: graph.nodes.find((x) => x.id === n.id) })}
            onEdgeClick={(_, e) => setSelected({ edge: graph.edges.find((x) => x.id === e.id) })}
            onPaneClick={() => setSelected(null)}>
            <Background color={colors.border} gap={24} />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
        <p className="text-xs text-muted">Solid lines are recorded relationships; dashed lines are hypotheses. Attack-path steps are arrows (crimson = validated by a person, orange = hypothesis). Click anything to see its evidence.</p>
      </div>

      <aside className="rounded-lg border border-border bg-surface p-4 text-sm" aria-live="polite" data-testid="graph-details">
        {!selected && <p className="text-muted">Select a node or a line to see what it is and the evidence behind it.</p>}
        {node && (
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-wider text-muted">{node.kind === "finding" ? "Finding" : node.asset_kind}</p>
            <p className="break-all font-medium">{node.label}</p>
            {node.kind === "finding" && node.severity && node.status && <div className="flex gap-1"><SeverityBadge severity={node.severity} /><StatusBadge status={node.status} /></div>}
            <Link className="block text-crimson-text hover:underline" href={node.kind === "finding" ? `/w/${ws}/findings/${node.record_id}` : `/w/${ws}/targets/${orgId}/assets/${node.record_id}`}>Open record and evidence</Link>
            {node.kind === "asset" && (childCount.get(node.id) ?? 0) > 0 && (
              <Button onClick={() => setCollapsed((s) => { const n = new Set(s); if (n.has(node.id)) n.delete(node.id); else n.add(node.id); return n; })}>
                {collapsed.has(node.id) ? `Expand ${childCount.get(node.id)} subdomains` : `Collapse ${childCount.get(node.id)} subdomains`}
              </Button>
            )}
          </div>
        )}
        {edge && (
          <dl className="space-y-2">
            <div><dt className="text-muted">Relationship</dt><dd>{EDGE_KINDS.find((k) => k.kind === edge.kind)?.label}{edge.path_title && `: ${edge.path_title}`}</dd></div>
            <div><dt className="text-muted">Status</dt><dd className={cx(edge.status === "hypothesis" && "text-yellow")}>
              {edge.status === "observed" ? "Observed (recorded fact)" : edge.status === "hypothesis" ? "Hypothesis — not demonstrated" : edge.status === "validated" ? "Validated by a person" : "Rejected"}
            </dd></div>
            {edge.rule_id && <div><dt className="text-muted">Rule</dt><dd className="font-mono text-xs">{edge.rule_id}</dd></div>}
            {edge.evidence_id ? <a className="block text-crimson-text hover:underline" href={`/api/workspaces/${ws}/evidence/${edge.evidence_id}/content`} download>Download the evidence</a>
              : edge.kind === "affects" ? <p className="text-xs text-muted">The finding page lists its evidence.</p>
              : edge.kind === "path_step" ? <p className="text-xs text-muted">Each step&apos;s finding carries its own evidence.</p> : null}
          </dl>
        )}
        {graph.truncated && <p className="mt-4 text-xs text-yellow">Showing the first assets only.</p>}
        <p className="mt-4 text-xs text-muted">{statusLabel.false_positive} and {statusLabel.remediated.toLowerCase()} findings are hidden.</p>
      </aside>
    </div>
  );
}
