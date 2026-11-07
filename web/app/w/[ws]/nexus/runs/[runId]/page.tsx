import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { WorkflowRunDetail } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { severityLabel, statusLabel } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { runStateLabel } from "@/components/nexus/labels";
import { RunView } from "@/components/nexus/RunView";
import { Alert, Badge, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Workflow run" };

export default async function WorkflowRunPage({ params }: { params: Promise<{ ws: string; runId: string }> }) {
  const { ws, runId } = await params;
  const [run, me] = await Promise.all([apiGet<WorkflowRunDetail>(`/workspaces/${ws}/workflow-runs/${runId}`), membership(ws)]);
  const [label, tone] = runStateLabel[run.state] ?? [run.state, "gray"];
  return (
    <>
      <nav className="mb-2 text-sm text-muted">
        <Link href={`/w/${ws}/nexus`} className="hover:text-text">NEXUS</Link> /{" "}
        <Link href={`/w/${ws}/targets/${run.organization_id}/projects/${run.project_id}`} className="hover:text-text">{run.project_name}</Link> /
      </nav>
      <PageHeader title={`${run.workflow_name}: ${run.subject}`} subtitle={`v${run.version} · started ${formatDateTime(run.started_at)} by ${run.started_by}`}
        actions={<Badge tone={tone}>{label}</Badge>} />
      {run.state === "cancelled" && run.cancel_reason && <Alert tone="yellow">Cancelled: {run.cancel_reason}</Alert>}
      <div className="mt-4 grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Steps"><RunView ws={ws} run={run} role={me.role} /></Panel>
        <div className="space-y-6">
          <Panel title="Findings this run follows">
            {run.tracked.length === 0 ? <p className="text-sm text-muted">None yet. They come from the first step&apos;s results.</p> : (
              <ul className="space-y-2 text-sm">
                {run.tracked.map((f) => (
                  <li key={f.id}>
                    <Link className="hover:text-crimson-text" href={`/w/${ws}/findings/${f.id}`}><span className="font-mono text-xs text-muted">{f.ref}</span> {f.title}</Link>
                    <span className="block text-xs text-muted">{severityLabel[f.severity as keyof typeof severityLabel] ?? f.severity} · {statusLabel[f.status] ?? f.status}</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel title="Step history">
            <ol className="space-y-1.5 text-xs">
              {run.events.map((e, i) => (
                <li key={i}>
                  <span className="font-mono text-muted tabular">{formatDateTime(e.occurred_at)}</span>{" "}
                  <span className="font-medium">{e.step_key}</span> → {e.to_state.replace(/_/g, " ")} <span className="text-muted">({e.actor})</span>
                </li>
              ))}
            </ol>
            <p className="mt-3 text-xs text-muted">Recorded by the database on every change; it can&apos;t be edited. Definition {run.definition_sha256.slice(0, 16)}…</p>
          </Panel>
        </div>
      </div>
    </>
  );
}
