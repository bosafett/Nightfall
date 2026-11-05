import type { Metadata } from "next";
import { apiGet } from "@/lib/api/server";
import type { Operation, Sources } from "@/lib/api/types";
import { SourcesPanel } from "@/components/blackice/SourcesPanel";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { OperationsTable } from "@/components/recon/OperationsTable";
import { EmptyState, LinkButton, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Reconnaissance" };

export default async function ReconPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [ops, sources] = await Promise.all([
    apiGet<Operation[]>(`/workspaces/${ws}/operations?limit=200`),
    apiGet<Sources>(`/workspaces/${ws}/sources`),
  ]);
  const pending = ops.some((o) => o.status === "queued" || o.status === "running");
  return (
    <>
      <PageHeader title="Reconnaissance" subtitle="Collection history. Every run is checked against its project's authorized scope; anything above passive needs a second person's approval." />
      <SourcesPanel data={sources} now={new Date()} />
      {ops.length === 0 ? (
        <EmptyState title="No collection yet" body="Open a project, authorize its scope, then run certificate-transparency or DNS collection."
          action={<LinkButton href={`/w/${ws}/targets`} variant="primary">Go to Target Registry</LinkButton>} />
      ) : (
        <>
        {ops.some((o) => o.status === "awaiting_approval") && (
          <Panel title="Awaiting approval" className="mb-6">
            <OperationsTable ws={ws} ops={ops.filter((o) => o.status === "awaiting_approval")} />
          </Panel>
        )}
        <Panel title="Discovery history">
          <AutoRefresh ws={ws} active={pending} />
          <OperationsTable ws={ws} ops={ops} />
        </Panel>
        </>
      )}
    </>
  );
}
