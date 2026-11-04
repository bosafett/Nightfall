import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { OperationDetail } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { EvidenceList } from "@/components/assets/EvidenceList";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { OperationStatusBadge } from "@/components/recon/OperationStatusBadge";
import { Alert, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Operation" };

export default async function OperationPage({ params }: { params: Promise<{ ws: string; opId: string }> }) {
  const { ws, opId } = await params;
  const op = await apiGet<OperationDetail>(`/workspaces/${ws}/operations/${opId}`);
  const s = op.result_summary as Record<string, number | string | undefined>;
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
      <PageHeader title={op.target} subtitle={op.tool_label} actions={<OperationStatusBadge status={op.status} />} />
      <AutoRefresh active={op.status === "queued" || op.status === "running"} />
      {op.status === "denied" && <Alert tone="yellow">Refused: {op.denial_reason}</Alert>}
      {op.status === "failed" && <Alert>Failed: {op.error}</Alert>}
      <div className="mt-4 grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <Panel title="Provenance">
          <dl className="space-y-2 text-sm">
            {rows.map(([k, v]) => <div key={k} className="flex justify-between gap-4"><dt className="text-muted">{k}</dt><dd className="text-right font-mono text-xs tabular">{v}</dd></div>)}
          </dl>
        </Panel>
        <Panel title="Result">
          {op.status === "succeeded" ? (
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
