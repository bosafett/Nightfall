import type { Metadata } from "next";
import { apiGet } from "@/lib/api/server";
import type { IntrusionView } from "@/lib/api/types";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { Intrusion } from "@/components/shield/Intrusion";
import { PageHeader } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Intrusion Detection" };

export default async function IntrusionPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [view, me] = await Promise.all([apiGet<IntrusionView>(`/workspaces/${ws}/shield/intrusion`), membership(ws)]);
  return (
    <>
      <PageHeader title="Intrusion Detection"
        subtitle="CrowdSec sensors on machines you run. GUARD blocks single addresses automatically only under the standing authorization you record; every block expires and can be lifted." />
      <Intrusion ws={ws} view={view} isOwner={me.role === "owner"} isAdmin={can.manageIncidents(me.role)} canAct={can.editFindings(me.role)} />
    </>
  );
}
