import type { Metadata } from "next";
import { apiGet } from "@/lib/api/server";
import type { Operation } from "@/lib/api/types";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { OperationsTable } from "@/components/recon/OperationsTable";
import { EmptyState, LinkButton, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Reconnaissance" };

export default async function ReconPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const ops = await apiGet<Operation[]>(`/workspaces/${ws}/operations?limit=200`);
  const pending = ops.some((o) => o.status === "queued" || o.status === "running");
  return (
    <>
      <PageHeader title="Reconnaissance" subtitle="Passive collection history. Every run is checked against its project's authorized scope." />
      {ops.length === 0 ? (
        <EmptyState title="No collection yet" body="Open a project, authorize its scope, then run certificate-transparency or DNS collection."
          action={<LinkButton href={`/w/${ws}/targets`} variant="primary">Go to Target Registry</LinkButton>} />
      ) : (
        <Panel title="Discovery history">
          <AutoRefresh active={pending} />
          <OperationsTable ws={ws} ops={ops} />
        </Panel>
      )}
    </>
  );
}
