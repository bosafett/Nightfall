import { describe, expect, it } from "vitest";
import type { GEdge, ProjectGraph } from "@/lib/api/types";
import { filterGraph, layoutProjectGraph, type GraphFilters } from "@/lib/graph";

const g: ProjectGraph = {
  truncated: false,
  nodes: [
    { id: "asset:d", kind: "asset", label: "example.com", record_id: "d", asset_kind: "domain" },
    { id: "asset:w", kind: "asset", label: "www.example.com", record_id: "w", asset_kind: "hostname" },
    { id: "asset:a", kind: "asset", label: "a.www.example.com", record_id: "a", asset_kind: "hostname" },
    { id: "asset:ip", kind: "asset", label: "192.0.2.10", record_id: "ip", asset_kind: "ip_address" },
    { id: "finding:1", kind: "finding", label: "NF-0001", record_id: "1", severity: "low", status: "unverified" },
    { id: "finding:2", kind: "finding", label: "NF-0002", record_id: "2", severity: "critical", status: "hypothesis" },
    { id: "finding:3", kind: "finding", label: "NF-0003", record_id: "3", severity: "high", status: "false_positive" },
  ],
  edges: [
    { id: "e1", source: "asset:w", target: "asset:d", kind: "subdomain_of", status: "observed" },
    { id: "e2", source: "asset:a", target: "asset:w", kind: "subdomain_of", status: "observed" },
    { id: "e3", source: "asset:w", target: "asset:ip", kind: "resolves_to", status: "observed" },
    { id: "e4", source: "finding:1", target: "asset:w", kind: "affects", status: "observed" },
    { id: "e5", source: "finding:2", target: "asset:a", kind: "affects", status: "hypothesis" },
    { id: "e6", source: "finding:1", target: "finding:2", kind: "path_step", status: "hypothesis" },
  ],
};
const all = new Set<GEdge["kind"]>(["subdomain_of", "resolves_to", "cname_to", "affects", "path_step"]);
const base: GraphFilters = { edgeKinds: all, minSeverity: "info", showHypotheses: true, collapsed: new Set() };
const ids = (r: { nodes: { id: string }[] }) => r.nodes.map((n) => n.id).sort();

describe("filterGraph", () => {
  it("hides dismissed findings and keeps everything else by default", () => {
    const r = filterGraph(g, base);
    expect(ids(r)).not.toContain("finding:3");
    expect(r.edges).toHaveLength(6);
  });
  it("can hide hypotheses (nodes and edges)", () => {
    const r = filterGraph(g, { ...base, showHypotheses: false });
    expect(ids(r)).not.toContain("finding:2");
    expect(r.edges.some((e) => e.status === "hypothesis")).toBe(false);
  });
  it("filters by minimum severity", () => {
    expect(ids(filterGraph(g, { ...base, minSeverity: "high" }))).not.toContain("finding:1");
  });
  it("collapsing an asset hides its subdomain tree and findings on it", () => {
    const r = filterGraph(g, { ...base, collapsed: new Set(["asset:w"]) });
    expect(ids(r)).not.toContain("asset:a");
    expect(ids(r)).not.toContain("finding:2");
    expect(ids(r)).toContain("asset:w");
  });
  it("filters by relationship type", () => {
    const r = filterGraph(g, { ...base, edgeKinds: new Set(["resolves_to"]) });
    expect(r.edges.map((e) => e.kind)).toEqual(["resolves_to"]);
  });
});

describe("layoutProjectGraph", () => {
  it("places columns by kind with no overlaps", () => {
    const p = layoutProjectGraph(g.nodes, g.edges);
    expect(p.get("asset:d")!.x).toBeLessThan(p.get("asset:w")!.x);
    expect(p.get("asset:w")!.x).toBeLessThan(p.get("asset:ip")!.x);
    expect(p.get("finding:1")!.x).toBeGreaterThan(p.get("asset:ip")!.x);
    const keys = [...p.values()].map((v) => `${v.x},${v.y}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});
