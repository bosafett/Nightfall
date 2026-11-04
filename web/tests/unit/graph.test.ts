import { describe, expect, it } from "vitest";
import type { GraphData } from "@/lib/api/types";
import { layoutGraph, nodeHref } from "@/lib/graph";

const graph: GraphData = {
  truncated: false,
  nodes: [
    { id: "org:a", kind: "organization", label: "A", record_id: "a" },
    { id: "project:p1", kind: "project", label: "P1", record_id: "p1", status: "active" },
    { id: "project:p2", kind: "project", label: "P2", record_id: "p2", status: "planning" },
    { id: "org:b", kind: "organization", label: "B", record_id: "b" },
  ],
  edges: [
    { id: "e1", source: "org:a", target: "project:p1", kind: "has_project", status: "observed" },
    { id: "e2", source: "org:a", target: "project:p2", kind: "has_project", status: "observed" },
  ],
};

describe("layoutGraph", () => {
  it("places every node once, orgs left and projects right, without overlaps", () => {
    const placed = layoutGraph(graph);
    expect(placed.map((n) => n.id).sort()).toEqual(graph.nodes.map((n) => n.id).sort());
    const pos = Object.fromEntries(placed.map((n) => [n.id, n]));
    expect(pos["org:a"]!.x).toBeLessThan(pos["project:p1"]!.x);
    expect(pos["org:a"]!.y).toBe((pos["project:p1"]!.y + pos["project:p2"]!.y) / 2);
    expect(pos["org:b"]!.y).toBeGreaterThan(pos["project:p2"]!.y);
    const keys = placed.map((n) => `${n.x},${n.y}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("is deterministic", () => {
    expect(layoutGraph(graph)).toEqual(layoutGraph(graph));
  });
});

describe("nodeHref", () => {
  it("opens the node's record", () => {
    expect(nodeHref("w", graph.nodes[0]!, graph)).toBe("/w/w/targets/a");
    expect(nodeHref("w", graph.nodes[1]!, graph)).toBe("/w/w/targets/a/projects/p1");
  });
});
