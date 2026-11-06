import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { PlaybookLibrary, PlaybookRun } from "@/lib/api/types";
import { membership } from "@/lib/workspace";
import { Library } from "@/components/blackops/Library";
import { RunsTable } from "@/components/blackops/RunsTable";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { Alert, Badge, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "BLACK OPS" };

/** Playbook library and execution history. BLACKSITE is owner-only; the API enforces who may launch. */
export default async function BlackOps({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const m = await membership(ws);
  if (m.role !== "owner") {
    return (
      <>
        <PageHeader title="BLACK OPS" subtitle="Playbook library" actions={<Badge tone="crimson">Restricted</Badge>} />
        <Alert tone="blue">BLACK OPS is part of BLACKSITE and limited to workspace owners.</Alert>
      </>
    );
  }
  const [lib, runs] = await Promise.all([
    apiGet<PlaybookLibrary>(`/workspaces/${ws}/blackops/playbooks`),
    apiGet<PlaybookRun[]>(`/workspaces/${ws}/blackops/runs?limit=25`),
  ]);
  return (
    <>
      <nav className="mb-2 text-sm text-muted"><Link href={`/w/${ws}/blacksite`} className="hover:text-text">BLACKSITE</Link> /</nav>
      <PageHeader title="BLACK OPS" subtitle="Prebuilt operations. Controlled execution. Verifiable results." actions={<Badge tone="crimson">Owner only</Badge>} />
      <AutoRefresh ws={ws} active={runs.some((r) => r.status === "running")} />
      <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3" data-testid="profiles">
        {lib.profiles.map((p) => (
          <div key={p.key} className="rounded-lg border border-border bg-surface p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-medium">Profile {p.code} · {p.label}</span>
              <Badge tone={p.available ? (p.key === "lab" ? "orange" : "green") : "gray"}>{p.available ? (p.key === "lab" ? "Lab only" : "Available") : "Not built"}</Badge>
            </div>
            <p className="mt-1 text-xs text-muted">{p.available ? p.description : p.unavailable_reason}</p>
          </div>
        ))}
      </div>
      <Panel title="Playbook library" className="mb-6">
        <Library ws={ws} playbooks={lib.playbooks} />
      </Panel>
      <Panel title="Execution history">
        <RunsTable ws={ws} runs={runs} />
      </Panel>
    </>
  );
}
