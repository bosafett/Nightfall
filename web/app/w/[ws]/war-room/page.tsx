import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { WarRoom } from "@/lib/api/types";
import { formatDateTime, formatRelative } from "@/lib/format";
import { AiBadge } from "@/components/agents/AgentBadges";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { QuickDecision } from "@/components/warroom/QuickDecision";
import { Badge, PageHeader, Panel, type Tone } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "War Room" };

const risk: Record<string, [Tone, string]> = {
  passive: ["gray", "Passive"], low: ["blue", "Low risk"], moderate: ["yellow", "Moderate risk"], high: ["crimson", "High risk"],
};

const actionText: Record<string, string> = {
  "operation.approved": "approved an operation",
  "operation.rejected": "rejected an operation",
  "operation.denied": "Operation denied by the scope check",
  "scope.authorized": "authorized a scope",
  "finding.status_changed": "changed a finding's status",
  "attack_path.reviewed": "reviewed an attack path",
  "agent.proposal_refused": "Gateway refused an agent proposal",
  "agent_task.requested": "started an agent",
  "agent_task.cancelled": "cancelled an agent task",
  "report.generated": "generated a report",
};

const plural = (n: number, word: string) => (n === 1 ? word : `${word}s`);

function entityHref(ws: string, type: string | null, id: string | null): string | null {
  if (!id) return null;
  if (type === "operation") return `/w/${ws}/recon/${id}`;
  if (type === "finding") return `/w/${ws}/findings/${id}`;
  if (type === "agent_task") return `/w/${ws}/agents/${id}`;
  if (type === "report") return `/w/${ws}/reports/${id}`;
  if (type === "attack_path") return `/w/${ws}/attack-graph`;
  return null;
}

function reviewHref(ws: string, kind: string, id: string, linkId: string): string {
  if (kind === "finding") return `/w/${ws}/findings/${id}`;
  if (kind === "attack_path") return `/w/${ws}/attack-graph?project=${linkId}`;
  return `/w/${ws}/targets`;
}

export default async function WarRoomPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const room = await apiGet<WarRoom>(`/workspaces/${ws}/war-room`);
  const now = new Date(room.generated_at);
  const c = room.review_counts;
  return (
    <>
      <PageHeader title="War Room" subtitle="Everything waiting on a person, in one place" />
      <AutoRefresh ws={ws} active={room.in_flight.length > 0} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Panel title={`Awaiting a decision · ${room.awaiting.length}`}>
          {room.awaiting.length === 0 ? <p className="text-sm text-muted">Nothing is waiting for approval.</p> : (
            <ul className="-my-2 divide-y divide-border">
              {room.awaiting.map((o) => {
                const [tone, label] = risk[o.risk_class] ?? ["gray", o.risk_class];
                return (
                  <li key={o.id} className="space-y-2 py-3" data-testid="awaiting-op">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link href={`/w/${ws}/recon/${o.id}`} className="font-medium hover:text-crimson-text">{o.tool} · <span className="font-mono">{o.target}</span></Link>
                      <Badge tone={tone}>{label}</Badge>
                      {o.proposed_by_task_id && <Link href={`/w/${ws}/agents/${o.proposed_by_task_id}`}><AiBadge /></Link>}
                    </div>
                    <p className="text-xs text-muted">
                      {o.organization_name} — {o.project_name} · scope <span className="font-mono">v{o.scope_version}</span> · requested by {o.requested_by ?? "—"}{" "}
                      <span className="font-mono tabular">{formatRelative(o.queued_at, now)}</span>
                    </p>
                    {o.purpose && <p className="text-sm text-muted">{o.purpose}</p>}
                    {o.can_decide ? <QuickDecision ws={ws} opId={o.id} target={o.target} scopeVersion={o.scope_version} />
                      : <p className="text-xs text-muted">{o.why_not}</p>}
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>

        <Panel title={`In flight · ${room.in_flight.length}`}>
          {room.in_flight.length === 0 ? <p className="text-sm text-muted">Nothing is queued or running.</p> : (
            <ul className="-my-2 divide-y divide-border">
              {room.in_flight.map((f) => (
                <li key={f.id} className="flex items-center gap-3 py-2.5">
                  <div className="min-w-0 flex-1">
                    <Link href={f.kind === "operation" ? `/w/${ws}/recon/${f.id}` : `/w/${ws}/agents/${f.id}`} className="block truncate text-sm hover:text-crimson-text">
                      {f.label} · <span className={f.kind === "operation" ? "font-mono" : undefined}>{f.detail}</span>
                    </Link>
                    <p className="text-xs text-muted">{f.kind === "operation" ? "Collection" : "AI agent"} · since <span className="font-mono tabular">{formatRelative(f.since, now)}</span></p>
                  </div>
                  <Badge tone={f.status === "running" ? "blue" : "gray"}>{f.status === "running" ? "Running" : "Queued"}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title={`AI proposals to review · ${c.findings + c.attack_paths + c.relationships}`}>
          <p className="mb-3 text-xs text-muted">
            Hypotheses from agents: <span className="font-mono tabular">{c.findings}</span> {plural(c.findings, "finding")},{" "}
            <span className="font-mono tabular">{c.attack_paths}</span> {plural(c.attack_paths, "attack path")},{" "}
            <span className="font-mono tabular">{c.relationships}</span> {plural(c.relationships, "relationship")}. None of them is verified until a person decides.
          </p>
          {room.to_review.length === 0 ? <p className="text-sm text-muted">Nothing to review.</p> : (
            <ul className="-my-2 divide-y divide-border">
              {room.to_review.map((r) => (
                <li key={`${r.kind}-${r.id}`} className="flex items-center gap-3 py-2.5">
                  <div className="min-w-0 flex-1">
                    <Link href={reviewHref(ws, r.kind, r.id, r.link_id)} className="block truncate text-sm hover:text-crimson-text">{r.label}</Link>
                    <p className="text-xs text-muted">{r.detail}</p>
                  </div>
                  <Badge tone="yellow">Hypothesis</Badge>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Decision log">
          {room.decisions.length === 0 ? <p className="text-sm text-muted">No decisions recorded yet.</p> : (
            <ul className="-my-2 divide-y divide-border">
              {room.decisions.map((d) => {
                const href = entityHref(ws, d.entity_type, d.entity_id);
                const text = actionText[d.action] ?? d.action;
                const sentence = d.actor_type === "user" && d.action !== "operation.denied" ? `${d.actor} ${text}` : text;
                const details = Object.entries(d.details).map(([k, v]) => `${k.replace("_", " ")}: ${String(v)}`).join(" · ");
                return (
                  <li key={d.id} className="py-2.5">
                    <p className="text-sm">{href ? <Link href={href} className="hover:text-crimson-text">{sentence}</Link> : sentence}</p>
                    {details && <p className="truncate text-xs text-muted">{details}</p>}
                    <p className="font-mono text-xs text-muted tabular">{formatDateTime(d.occurred_at)}</p>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>
      </div>
    </>
  );
}
