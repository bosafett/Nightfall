import type { Metadata } from "next";
import { EmptyState, LinkButton, PageHeader } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Command Center" };

export default async function CommandCenter({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  return (
    <>
      <PageHeader title="Command Center" subtitle="Your adversarial intelligence overview" />
      <EmptyState
        title="Arrives in phase 2"
        body="Metrics, active assessments, findings and agent activity will appear here once there's real data behind them. Start by registering an organization and a project."
        action={<LinkButton href={`/w/${ws}/targets`} variant="primary">Go to Target Registry</LinkButton>}
      />
    </>
  );
}
