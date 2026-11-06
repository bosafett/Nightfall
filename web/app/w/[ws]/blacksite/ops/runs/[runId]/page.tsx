import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Me, PlaybookRunDetail } from "@/lib/api/types";
import { can, decidesOwn } from "@/lib/labels";
import { formatDateTime } from "@/lib/format";
import { profileLabel, riskLabel, riskTone, runStatusLabel, runStatusTone } from "@/lib/blackops";
import { EvidenceList } from "@/components/assets/EvidenceList";
import { CancelRun, RunDecision } from "@/components/blackops/Controls";
import { SeverityBadge, StatusBadge } from "@/components/findings/Badges";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { OperationStatusBadge } from "@/components/recon/OperationStatusBadge";
import { LabBadge } from "@/components/scope/LabBadge";
import { Alert, Badge, DataTable, EmptyState, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Playbook run" };

const changeLabel: Record<string, string> = { new: "New", seen_again: "Seen again", reopened: "Reopened" };

export default async function RunPage({ params }: { params: Promise<{ ws: string; runId: string }> }) {
  const { ws, runId } = await params;
  const [r, me] = await Promise.all([apiGet<PlaybookRunDetail>(`/workspaces/${ws}/blackops/runs/${runId}`), apiGet<Me>("/auth/me")]);
  const membership = me.workspaces.find((w) => w.id === ws);
  const role = membership?.role ?? "viewer";
  const mine = r.requested_by_user_id === me.user.id && !decidesOwn(role, membership?.approval_policy);
  const open = r.steps.some((s) => s.status === "queued" || s.status === "awaiting_approval");
  const facts: [string, string][] = [
    ["Project", r.project_name],
    ["Scope version", `v${r.scope_version}`],
    ["Definition", `v${r.playbook_version} · ${r.definition_sha256.slice(0, 12)}…`],
    ["Requested by", r.requested_by ?? "—"],
    ["Launched", formatDateTime(r.created_at)],
  ];
  return (
    <>
      <nav className="mb-2 text-sm text-muted">
        <Link href={`/w/${ws}/blacksite`} className="hover:text-text">BLACKSITE</Link> / <Link href={`/w/${ws}/blacksite/ops`} className="hover:text-text">BLACK OPS</Link> /{" "}
        <Link href={`/w/${ws}/blacksite/ops/${r.playbook_id}`} className="hover:text-text">{r.playbook_name}</Link> /
      </nav>
      <PageHeader title={r.target} subtitle={`${r.playbook_name} · profile ${profileLabel[r.profile]}`}
        actions={<span className="flex items-center gap-2">{r.profile === "lab" && <LabBadge />}<Badge tone={runStatusTone[r.status]}>{runStatusLabel[r.status]}</Badge></span>} />
      <AutoRefresh ws={ws} active={r.status === "running"} />
      {!r.definition_current && <Alert tone="yellow">This run used a definition that has since changed (now a newer version). Its record keeps the original hash.</Alert>}
      {r.status === "awaiting_approval" && (
        <Panel title="Awaiting approval" className="mb-4">
          {r.profile === "lab" ? (
            <p className="text-sm text-muted">Lab runs are approved in BLACKSITE on the lab machine, not from the hosted app.</p>
          ) : mine ? (
            <div className="space-y-3"><p className="text-sm text-muted">You launched this run, so an operator, admin or owner other than you has to approve it.</p><CancelRun ws={ws} runId={r.id} /></div>
          ) : can.approveOperations(role) ? <RunDecision ws={ws} run={r} />
            : <p className="text-sm text-muted">An operator, admin or owner has to approve this.</p>}
        </Panel>
      )}
      {r.status !== "awaiting_approval" && open && can.writeRegistry(role) && <div className="mb-4"><CancelRun ws={ws} runId={r.id} /></div>}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-6">
          <Panel title="Steps">
            <DataTable head={["#", "Step", "Risk", "Status", "Finished", ""]}>
              {r.steps.map((s) => (
                <tr key={s.operation_id}>
                  <td className="px-4 py-2.5 font-mono text-xs text-muted">{s.step}</td>
                  <td className="px-4 py-2.5">{s.label}
                    {s.denial_reason && <span className="block text-xs text-orange">Refused: {s.denial_reason}</span>}
                    {s.error && <span className="block text-xs text-crimson-text">Failed: {s.error}</span>}
                  </td>
                  <td className="px-4 py-2.5"><Badge tone={riskTone[s.risk_class]}>{riskLabel[s.risk_class]}</Badge></td>
                  <td className="px-4 py-2.5"><OperationStatusBadge status={s.status} /></td>
                  <td className="px-4 py-2.5 font-mono text-xs text-muted tabular">{formatDateTime(s.finished_at)}</td>
                  <td className="px-4 py-2.5 text-right"><Link href={`/w/${ws}/recon/${s.operation_id}`} className="text-sm hover:underline">Operation</Link></td>
                </tr>
              ))}
            </DataTable>
          </Panel>
          <Panel title="Findings (BLACK ICE)">
            {r.findings.length === 0 ? <EmptyState title="No findings" body={r.status === "succeeded" ? "The rules found nothing to report in this run's evidence." : "Findings appear when steps finish."} /> : (
              <DataTable head={["Severity", "Finding", "Status", "This run"]}>
                {r.findings.map((f) => (
                  <tr key={f.id}>
                    <td className="px-4 py-2.5"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-4 py-2.5"><Link href={`/w/${ws}/findings/${f.id}`} className="hover:underline">{f.title}</Link><span className="block font-mono text-xs text-muted">{f.check_id}</span></td>
                    <td className="px-4 py-2.5"><StatusBadge status={f.validation_status} /></td>
                    <td className="px-4 py-2.5 text-xs">{changeLabel[f.change] ?? f.change}</td>
                  </tr>
                ))}
              </DataTable>
            )}
            <p className="mt-3 text-xs text-muted">Rule-made findings start unverified. Only a person can mark one validated, a false positive or remediated.</p>
          </Panel>
          <Panel title="Evidence"><EvidenceList ws={ws} items={r.evidence} /></Panel>
        </div>
        <Panel title="Provenance">
          <dl className="space-y-2 text-sm">
            {facts.map(([k, v]) => <div key={k} className="flex justify-between gap-4"><dt className="text-muted">{k}</dt><dd className="text-right font-mono text-xs tabular">{v}</dd></div>)}
          </dl>
        </Panel>
      </div>
    </>
  );
}
