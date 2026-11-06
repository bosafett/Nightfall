import { LabBadge } from "@/components/scope/LabBadge";
import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Me, OperationDetail } from "@/lib/api/types";
import { can, decidesOwn } from "@/lib/labels";
import { CancelRequest, DecisionPanel } from "@/components/recon/DecisionPanel";
import { formatDateTime } from "@/lib/format";
import { EvidenceList } from "@/components/assets/EvidenceList";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { OperationStatusBadge } from "@/components/recon/OperationStatusBadge";
import { Alert, Badge, DataTable, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Operation" };

export default async function OperationPage({ params }: { params: Promise<{ ws: string; opId: string }> }) {
  const { ws, opId } = await params;
  const [op, me] = await Promise.all([apiGet<OperationDetail>(`/workspaces/${ws}/operations/${opId}`), apiGet<Me>("/auth/me")]);
  const membership = me.workspaces.find((w) => w.id === ws);
  const role = membership?.role ?? "viewer";
  const mine = op.requested_by_user_id === me.user.id && !decidesOwn(role, membership?.approval_policy);
  const techs = (op.result_summary.technologies ?? []) as { name: string; version: string | null; rule_id: string; confidence: string; evidence: string }[];
  const http = ((op.result_summary as { http?: unknown }).http ?? []) as { status?: number; title?: string | null; location?: string | null; tls?: { version?: string; subject_cn?: string; issuer_cn?: string; not_after?: string } | null }[];
  const s = op.result_summary as Record<string, number | string | undefined>;
  const checks = ((op.result_summary as { checks?: unknown }).checks ?? []) as { template_id: string; check_id: string; title: string; matched_at: string }[];
  const changes = ((op.result_summary as { findings?: unknown }).findings ?? []) as { finding_id: string; check_id: string; change: string }[];
  const egress = ((op.result_summary as { egress?: unknown }).egress ?? {}) as { allowed?: number; refused?: number };
  const changeLabel: Record<string, string> = { new: "New finding", seen_again: "Seen again", reopened: "Reopened (was marked remediated)" };
  const rows: [string, string][] = [
    ["Project", `${op.organization_name} — ${op.project_name}`],
    ["Scope version", `v${op.scope_version}`],
    ["Risk class", op.risk_class],
    ["Requested by", op.requested_by ?? "—"],
    ["Queued", formatDateTime(op.queued_at)],
    ["Started", formatDateTime(op.started_at)],
    ["Finished", formatDateTime(op.finished_at)],
    ["Attempts", String(op.attempts)],
  ];
  return (
    <>
      <nav className="mb-2 text-sm text-muted"><Link href={`/w/${ws}/recon`} className="hover:text-text">Reconnaissance</Link> /</nav>
      <PageHeader title={op.target} subtitle={op.tool_label} actions={<span className="flex items-center gap-2">{op.is_lab && <LabBadge />}<OperationStatusBadge status={op.status} /></span>} />
      <AutoRefresh ws={ws} active={op.status === "queued" || op.status === "running"} />
      {op.status === "denied" && <Alert tone="yellow">Refused: {op.denial_reason}</Alert>}
      {op.status === "failed" && <Alert>Failed: {op.error}</Alert>}
      {op.status === "awaiting_approval" && (
        <Panel title="Awaiting approval" className="mb-4">
          {op.is_lab ? (
            <p className="text-sm text-muted">Lab work is approved in BLACKSITE on the lab machine, not from the hosted app.</p>
          ) : mine ? (
            <div className="space-y-3"><p className="text-sm text-muted">You requested this, so an operator, admin or owner other than you has to approve it.</p><CancelRequest ws={ws} opId={op.id} /></div>
          ) : can.approveOperations(role) ? <DecisionPanel ws={ws} op={op} />
            : <p className="text-sm text-muted">An operator, admin or owner has to approve this.</p>}
        </Panel>
      )}
      {op.approval && (
        <Alert tone={op.approval.decision === "approved" ? "green" : "yellow"}>
          {op.approval.decision === "approved" ? "Approved" : "Rejected"} by {op.approval.decided_by} on {formatDateTime(op.approval.decided_at)}{op.approval.reason && `: ${op.approval.reason}`}
        </Alert>
      )}
      <div className="mt-4 grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <Panel title="Provenance">
          <dl className="space-y-2 text-sm">
            {rows.map(([k, v]) => <div key={k} className="flex justify-between gap-4"><dt className="text-muted">{k}</dt><dd className="text-right font-mono text-xs tabular">{v}</dd></div>)}
          </dl>
        </Panel>
        <Panel title="Result">
          {op.status === "succeeded" && op.tool === "http" ? (
            <div className="space-y-4">
              {http[0] && (
                <p className="text-sm">HTTP <span className="font-mono tabular">{http[0].status}</span>{http[0].title && <> · “{http[0].title}”</>}{http[0].location && <> · redirects to <span className="font-mono">{http[0].location}</span> (not followed)</>}
                  {http[0].tls && <span className="block text-xs text-muted">TLS {http[0].tls.version} · certificate for {http[0].tls.subject_cn ?? "—"} from {http[0].tls.issuer_cn ?? "—"}</span>}
                </p>
              )}
              {techs.length === 0 ? <p className="text-sm text-muted">No technology markers matched.</p> : (
                <DataTable head={["Technology", "Version", "Confidence", "Rule", "Matched"]}>
                  {techs.map((t) => (
                    <tr key={`${t.name}-${t.rule_id}`}>
                      <td className="px-4 py-2.5 font-medium">{t.name}</td>
                      <td className="px-4 py-2.5 font-mono text-sm tabular">{t.version ?? "—"}</td>
                      <td className="px-4 py-2.5"><Badge tone={t.confidence === "high" ? "green" : "blue"}>{t.confidence === "high" ? "High: stated by server" : "Medium: inferred"}</Badge></td>
                      <td className="px-4 py-2.5 font-mono text-xs text-muted">{t.rule_id}</td>
                      <td className="max-w-xs truncate px-4 py-2.5 font-mono text-xs text-muted" title={t.evidence}>{t.evidence}</td>
                    </tr>
                  ))}
                </DataTable>
              )}
            </div>
          ) : op.status === "succeeded" && op.tool === "nuclei" ? (
            <div className="space-y-4">
              <p className="text-sm text-muted">
                <span className="font-mono tabular text-text">{egress.allowed ?? 0}</span> connections through the scope proxy · <span className="font-mono tabular text-text">{egress.refused ?? 0}</span> refused
              </p>
              {checks.length === 0 ? <p className="text-sm">None of the reviewed checks matched.</p> : (
                <DataTable head={["Check", "Matched at", "Finding"]}>
                  {checks.map((c) => {
                    const ch = changes.find((x) => x.check_id === c.check_id);
                    return (
                      <tr key={`${c.template_id}-${c.matched_at}`}>
                        <td className="px-4 py-2.5"><span className="block text-sm">{c.title}</span><span className="block font-mono text-xs text-muted">{c.template_id}</span></td>
                        <td className="max-w-xs truncate px-4 py-2.5 font-mono text-xs text-muted" title={c.matched_at}>{c.matched_at}</td>
                        <td className="px-4 py-2.5 text-sm">{ch ? <Link className="hover:text-crimson-text" href={`/w/${ws}/findings/${ch.finding_id}`}>{changeLabel[ch.change] ?? ch.change}</Link> : "—"}</td>
                      </tr>
                    );
                  })}
                </DataTable>
              )}
              <p className="text-xs text-muted">Matches create unverified findings. Someone has to review the evidence before a finding counts as validated.</p>
            </div>
          ) : op.status === "succeeded" ? (
            <ul className="space-y-1 text-sm">
              <li><span className="font-mono tabular">{s.assets_new ?? 0}</span> new assets, <span className="font-mono tabular">{s.assets_seen ?? 0}</span> seen again</li>
              <li><span className="font-mono tabular">{s.out_of_scope ?? 0}</span> names outside scope or excluded: kept in raw evidence, not registered</li>
              <li><span className="font-mono tabular">{s.rejected ?? 0}</span> malformed values dropped</li>
              <li><span className="font-mono tabular">{s.relationships ?? 0}</span> relationships recorded (ruleset {String(s.ruleset ?? "—")})</li>
            </ul>
          ) : <p className="text-sm text-muted">No result yet.</p>}
          <div className="mt-4"><EvidenceList ws={ws} items={op.evidence} /></div>
        </Panel>
      </div>
    </>
  );
}
