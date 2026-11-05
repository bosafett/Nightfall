import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Replay } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { Alert, DataTable, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Replay against current rules" };

type Row = Replay["unchanged"][number];

function Rows({ rows, empty }: { rows: Row[]; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <DataTable head={["Finding", "Asset", "Severity", "Rule"]}>
      {rows.map((r) => (
        <tr key={`${r.asset}-${r.check_id ?? r.title}`}>
          <td className="px-4 py-2.5 text-sm">{r.title}</td>
          <td className="px-4 py-2.5 font-mono text-xs">{r.asset ?? "—"}</td>
          <td className="px-4 py-2.5 text-sm">{r.severity}</td>
          <td className="px-4 py-2.5 font-mono text-xs text-muted">{r.rule_id}</td>
        </tr>
      ))}
    </DataTable>
  );
}

/** BLACK ICE replay: what today's rules would conclude from this report's evidence. */
export default async function ReplayPage({ params }: { params: Promise<{ ws: string; reportId: string }> }) {
  const { ws, reportId } = await params;
  const d = await apiGet<Replay>(`/workspaces/${ws}/reports/${reportId}/replay`);
  const differs = d.changed.length + d.new.length + d.gone.length > 0;
  return (
    <>
      <nav className="mb-2 text-sm text-muted"><Link href={`/w/${ws}/reports/${reportId}`} className="hover:text-text">← Report</Link></nav>
      <PageHeader title="Replay against current rules" subtitle={`Evidence as of ${formatDateTime(d.as_of)} · ${d.evidence_considered} evidence records`} />
      <div className="space-y-6">
        <Alert tone="blue">
          Read-only. The current finding rules (<span className="font-mono">{d.current_ruleset}</span>) were re-run over the evidence that existed when the
          report was made (rules then: <span className="font-mono">{d.snapshot_ruleset}</span>). Nothing in the report or the findings changes.
        </Alert>
        <Alert tone={differs ? "yellow" : "green"}>
          {differs
            ? `Today's rules would conclude differently: ${d.changed.length} changed, ${d.new.length} new, ${d.gone.length} no longer found.`
            : "Today's rules reach the same rule-based findings as the report."}
        </Alert>
        {d.changed.length > 0 && (
          <Panel title={`Changed · ${d.changed.length}`}>
            <DataTable head={["Finding", "Asset", "In the report", "Today"]}>
              {d.changed.map((c) => (
                <tr key={`${c.then.asset}-${c.then.check_id ?? c.then.title}`}>
                  <td className="px-4 py-2.5 text-sm">{c.now.title}</td>
                  <td className="px-4 py-2.5 font-mono text-xs">{c.now.asset ?? "—"}</td>
                  <td className="px-4 py-2.5 text-sm">{c.then.severity}{c.then.title !== c.now.title && <span className="block text-xs text-muted">{c.then.title}</span>}</td>
                  <td className="px-4 py-2.5 text-sm">{c.now.severity}</td>
                </tr>
              ))}
            </DataTable>
          </Panel>
        )}
        <Panel title={`New with today's rules · ${d.new.length}`}><Rows rows={d.new} empty="None." /></Panel>
        <Panel title={`No longer found · ${d.gone.length}`}><Rows rows={d.gone} empty="None." /></Panel>
        <Panel title={`Unchanged · ${d.unchanged.length}`}><Rows rows={d.unchanged} empty="No rule-based findings in this report." /></Panel>
      </div>
    </>
  );
}
