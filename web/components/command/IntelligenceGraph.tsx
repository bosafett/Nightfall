"use client";

import "@xyflow/react/dist/style.css";
import { Background, Controls, Handle, MiniMap, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { useRouter } from "next/navigation";
import { useMemo } from "react";
import type { GraphData, GraphNodeData, ProjectStatus } from "@/lib/api/types";
import { layoutGraph, nodeHref } from "@/lib/graph";
import { projectStatusLabel } from "@/lib/labels";
import { colors } from "@/lib/tokens";

type Data = GraphNodeData & Record<string, unknown>;

/** Distinct style per entity kind. The overview emits organizations and projects; asset, finding and
 *  evidence nodes live in each project's Attack Graph, so they are not invented here. */
const KIND: Record<string, { label: string; border: string; text: string }> = {
  organization: { label: "Organization", border: "border-blue/70", text: "text-blue-text" },
  project: { label: "Project", border: "border-crimson/50", text: "text-crimson-text" },
};
const statusTone: Partial<Record<ProjectStatus, string>> = { active: "text-green", paused: "text-orange", planning: "text-muted" };

function EntityNode({ data }: NodeProps<Node<Data>>) {
  const k = KIND[data.kind] ?? { label: data.kind, border: "border-border-strong", text: "text-muted" };
  return (
    <div className={`w-60 cursor-pointer rounded-md border border-l-4 bg-surface px-3 py-2 text-left shadow-sm hover:bg-surface-2 ${k.border}`}>
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-gray" isConnectable={false} />
      <p className={`font-mono text-[10px] uppercase tracking-wider ${k.text}`}>{k.label}</p>
      <p className="truncate text-sm font-medium text-text" title={data.label}>{data.label}</p>
      {data.status && <p className={`text-xs ${statusTone[data.status as ProjectStatus] ?? "text-muted"}`}>{projectStatusLabel[data.status as ProjectStatus]}</p>}
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0 !bg-gray" isConnectable={false} />
    </div>
  );
}

const nodeTypes = { entity: EntityNode };

export function IntelligenceGraph({ ws, graph }: { ws: string; graph: GraphData }) {
  const router = useRouter();
  const { nodes, edges } = useMemo(() => {
    const nodes: Node<Data>[] = layoutGraph(graph).map((n) => ({
      id: n.id, type: "entity", position: { x: n.x, y: n.y }, data: n as Data,
      ariaLabel: `${KIND[n.kind]?.label ?? n.kind} ${n.label}. Open record.`,
    }));
    const edges: Edge[] = graph.edges.map((e) => ({
      id: e.id, source: e.source, target: e.target,
      // Recorded relationships are solid; hypotheses (phase 4+) are dashed. Never colour alone.
      style: { stroke: colors.gray, strokeWidth: 1.5, strokeDasharray: e.status === "hypothesis" ? "6 4" : undefined },
    }));
    return { nodes, edges };
  }, [graph]);

  return (
    <div className="h-[26rem] overflow-hidden rounded-md border border-border bg-bg" data-testid="intelligence-graph">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, n) => router.push(nodeHref(ws, n.data, graph))}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        fitView
        fitViewOptions={{ padding: 0.15, maxZoom: 1 }}
        minZoom={0.2}
        colorMode="dark"
        proOptions={{ hideAttribution: false }}
      >
        <Background color={colors.border} gap={24} />
        <Controls showInteractive={false} position="bottom-left" />
        {nodes.length > 12 && <MiniMap pannable zoomable position="bottom-right" bgColor={colors.bg} maskColor="rgba(0,0,0,0.6)" nodeColor={colors.border} />}
      </ReactFlow>
    </div>
  );
}
