"use client";

import "@xyflow/react/dist/style.css";
import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { useRouter } from "next/navigation";
import { useMemo } from "react";
import type { GraphData, GraphNodeData, ProjectStatus } from "@/lib/api/types";
import { layoutGraph, nodeHref } from "@/lib/graph";
import { projectStatusLabel } from "@/lib/labels";
import { colors } from "@/lib/tokens";

type Data = GraphNodeData & Record<string, unknown>;

function EntityNode({ data }: NodeProps<Node<Data>>) {
  const org = data.kind === "organization";
  return (
    <div className={`w-56 cursor-pointer rounded-md border bg-surface px-3 py-2 text-left shadow-sm ${org ? "border-blue/70" : "border-border-strong"}`}>
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-gray" isConnectable={false} />
      <p className={`text-[10px] uppercase tracking-wider ${org ? "text-blue-text" : "text-muted"}`}>{org ? "Organization" : "Project"}</p>
      <p className="truncate text-sm font-medium text-text">{data.label}</p>
      {data.status && <p className="text-xs text-muted">{projectStatusLabel[data.status as ProjectStatus]}</p>}
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
      ariaLabel: `${n.kind === "organization" ? "Organization" : "Project"} ${n.label}. Open record.`,
    }));
    const edges: Edge[] = graph.edges.map((e) => ({
      id: e.id, source: e.source, target: e.target,
      // Recorded relationships are solid; hypotheses (phase 4+) are dashed. Never colour alone.
      style: { stroke: colors.gray, strokeWidth: 1.5, strokeDasharray: e.status === "hypothesis" ? "6 4" : undefined },
    }));
    return { nodes, edges };
  }, [graph]);

  return (
    <div className="h-[22rem] overflow-hidden rounded-md border border-border bg-bg" data-testid="intelligence-graph">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, n) => router.push(nodeHref(ws, n.data, graph))}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        fitView
        fitViewOptions={{ padding: 0.2, maxZoom: 1.1 }}
        minZoom={0.2}
        colorMode="dark"
        proOptions={{ hideAttribution: false }}
      >
        <Background color={colors.border} gap={24} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
