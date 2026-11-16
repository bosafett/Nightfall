import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { IncidentDetail, ShieldAlert } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { IncidentPanel } from "@/components/shield/IncidentPanel";
import { incidentStateLabel, severityTone } from "@/components/shield/labels";
import { Alert, Badge, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Incident" };
const ENTRY: Record<string, string> = { event: "Event", note: "Note", action: "Action (recorded)", check: "Checklist", verification: "Verification" };

export default async function IncidentPage({ params }: { params: Promise<{ ws: string; incidentId: string }> }) {
  const { ws, incidentId } = await params;
  const [inc, me] = await Promise.all([apiGet<IncidentDetail>(`/workspaces/${ws}/incidents/${incidentId}`), membership(ws)]);
  const inProgress = ["open", "contained", "recovering"].includes(inc.state);
  const canWork = can.editFindings(me.role), canManage = can.manageIncidents(me.role);
  const linked = new Set(inc.items.filter((i) => i.kind === "alert").map((i) => i.item_id));
  const addable = inProgress && canWork
    ? (await apiGet<ShieldAlert[]>(`/workspaces/${ws}/alerts?state=active&project_id=${inc.project_id}&limit=200`)).filter((a) => !linked.has(a.id) && !a.incident_id)
    : [];
  const href = (kind: string, id: string) => kind === "finding" ? `/w/${ws}/findings/${id}` : null;
  return (
    <>
      <PageHeader title={inc.title} subtitle={`${inc.project_name} · lead ${inc.lead} · opened by ${inc.opened_by}, ${formatDateTime(inc.opened_at)}`}
        actions={<><Badge tone={severityTone[inc.severity] ?? "gray"}>{inc.severity}</Badge><Badge tone="gray">{incidentStateLabel[inc.state] ?? inc.state}</Badge></>} />
      <p className="mb-4 text-sm"><Link className="text-muted hover:text-crimson-text" href={`/w/${ws}/shield/incidents`}>← All incidents</Link></p>
      {inc.state === "cancelled" && <Alert tone="yellow">Cancelled: {inc.cancel_reason}</Alert>}
      {inc.state === "closed" && inc.review && (
        <Panel title={`Closed by ${inc.closed_by}, ${formatDateTime(inc.closed_at)}`} className="mb-4">
          {inc.override_reason && <Alert tone="yellow">Closed with an override, not verified: {inc.override_reason}</Alert>}
          <dl className="space-y-2 text-sm" data-testid="incident-review">
            <div><dt className="text-muted">What happened</dt><dd>{inc.review.what_happened}</dd></div>
            {inc.review.cause && <div><dt className="text-muted">Cause</dt><dd>{inc.review.cause}</dd></div>}
            <div><dt className="text-muted">What was done</dt><dd>{inc.review.what_was_done}</dd></div>
            {inc.review.lessons && <div><dt className="text-muted">What would catch it sooner</dt><dd>{inc.review.lessons}</dd></div>}
          </dl>
        </Panel>
      )}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-6">
          {inc.summary && <Panel title="Summary"><p className="text-sm">{inc.summary}</p></Panel>}
          <Panel title="Linked alerts, findings and assets">
            {inc.items.length === 0 ? <p className="text-sm text-muted">Nothing linked.</p> : (
              <ul className="space-y-2 text-sm" data-testid="incident-items">
                {inc.items.map((i) => {
                  const to = href(i.kind, i.item_id);
                  return (
                    <li key={i.id}>
                      {to ? <Link className="font-medium hover:text-crimson-text" href={to}>{i.label}</Link> : <span className="font-medium">{i.label}</span>}
                      <span className="text-muted"> · {i.detail} · added by {i.added_by}</span>
                    </li>
                  );
                })}
              </ul>
            )}
          </Panel>
          <IncidentPanel ws={ws} incident={inc} addable={addable.map((a) => ({ id: a.id, title: a.title }))} canWork={canWork && inProgress} canManage={canManage} mfaHint={inProgress} />
          <Panel title="Timeline">
            <ol className="space-y-2 text-sm" data-testid="incident-timeline">
              {inc.timeline.map((e) => (
                <li key={e.id} className="border-l-2 border-border pl-3">
                  <span className="font-mono text-xs text-muted tabular">{formatDateTime(e.created_at)} · {ENTRY[e.kind] ?? e.kind} · {e.actor ?? "JANUS"}</span>
                  <p>{e.body}</p>
                </li>
              ))}
            </ol>
            <p className="mt-3 text-xs text-muted">Entries can&apos;t be edited or deleted. Actions are statements by the people named, about work done outside JANUS.{" "}
              <a className="hover:text-crimson-text" href={`/api/workspaces/${ws}/incidents/${inc.id}/export`} download={`incident-${inc.id}.json`}>Download the record (JSON)</a></p>
          </Panel>
        </div>
        <div className="space-y-6">
          <Panel title="Verification">
            {inc.verification.length === 0 ? (
              <p className="text-sm text-muted">None of the linked alerts describes a condition a check can look for again. Change reports (a different certificate, changed DNS records, new names) are closed on the review alone.</p>
            ) : (
              <ul className="space-y-3 text-sm" data-testid="incident-verification">
                {inc.verification.map((v) => (
                  <li key={v.alert_id}>
                    <Badge tone={v.counts ? "green" : v.state === "still_present" ? "crimson" : "gray"}>{verifyLabel[v.state] ?? v.state}</Badge>{" "}
                    <span className="font-medium">{v.title}</span>
                    <p className="text-muted">{v.detail}{v.at && ` (${formatDateTime(v.at)})`}
                      {v.operation_id && <> · <Link className="hover:text-crimson-text" href={`/w/${ws}/recon/${v.operation_id}`}>check →</Link></>}</p>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-3 text-xs text-muted">“Not observed” means JANUS&apos;s own check didn&apos;t see the condition. It isn&apos;t a statement that the system is secure.</p>
          </Panel>
          {!(canWork && inProgress) && <Panel title="Checklist (recommendations)">
            {inc.checklist.length === 0 ? <p className="text-sm text-muted">No items.</p> : (
              <ul className="space-y-1 text-sm">
                {inc.checklist.map((c) => <li key={c.key}>{c.done ? "☑" : "☐"} {c.text}</li>)}
              </ul>
            )}
            <p className="mt-3 text-xs text-muted">Advice for people. Nothing here is run by JANUS.</p>
          </Panel>}
        </div>
      </div>
    </>
  );
}

const verifyLabel: Record<string, string> = {
  not_requested: "Not checked", pending: "Waiting", not_observed: "Not observed", still_present: "Still present",
  undecided: "Undecided", failed: "Check didn't run",
};
