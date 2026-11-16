import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Incident } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { severityTone, incidentStateLabel } from "@/components/shield/labels";
import { Badge, EmptyState, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Incident Response" };

export default async function IncidentsPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const incidents = await apiGet<Incident[]>(`/workspaces/${ws}/incidents`);
  const open = incidents.filter((i) => ["open", "contained", "recovering"].includes(i.state));
  const done = incidents.filter((i) => !open.includes(i));
  const row = (i: Incident) => (
    <li key={i.id} className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-bg p-3" data-testid="incident-row">
      <Badge tone={severityTone[i.severity] ?? "gray"}>{i.severity}</Badge>
      <Badge tone="gray">{incidentStateLabel[i.state] ?? i.state}</Badge>
      <Link className="font-medium hover:text-crimson-text" href={`/w/${ws}/shield/incidents/${i.id}`}>{i.title}</Link>
      <span className="ml-auto font-mono text-xs text-muted tabular">
        {i.project_name} · {i.alert_count} alert{i.alert_count === 1 ? "" : "s"} · lead {i.lead} · opened {formatDateTime(i.opened_at)}
      </span>
    </li>
  );
  return (
    <>
      <PageHeader title="Incident Response" subtitle="A record of what was noticed, decided and done, and a check that the problem is gone. JANUS records actions; it doesn't perform them." />
      {incidents.length === 0 ? (
        <EmptyState title="No incidents" body="Open one from an alert on the Alerts & Detection page: “Open incident”." />
      ) : (
        <>
          <Panel title="In progress" className="mb-4">
            {open.length ? <ul className="space-y-3">{open.map(row)}</ul> : <p className="text-sm text-muted">None.</p>}
          </Panel>
          {done.length > 0 && <Panel title="Closed and cancelled"><ul className="space-y-3">{done.map(row)}</ul></Panel>}
        </>
      )}
    </>
  );
}
