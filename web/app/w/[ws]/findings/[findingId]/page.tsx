import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { EvidenceSummary, FindingDetail } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { GuardianVerdictBadge } from "@/components/agents/AgentBadges";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { EvidenceList } from "@/components/assets/EvidenceList";
import { SeverityBadge, StatusBadge } from "@/components/findings/Badges";
import { EditFinding, LinkEvidence, StatusDecision } from "@/components/findings/FindingForms";
import { Alert, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Finding" };

export default async function FindingPage({ params }: { params: Promise<{ ws: string; findingId: string }> }) {
  const { ws, findingId } = await params;
  const [f, me] = await Promise.all([apiGet<FindingDetail>(`/workspaces/${ws}/findings/${findingId}`), membership(ws)]);
  const options = can.editFindings(me.role) ? await apiGet<EvidenceSummary[]>(`/workspaces/${ws}/projects/${f.project_id}/evidence`) : [];
  const facts: [string, React.ReactNode][] = [
    ["Project", <Link key="p" href={`/w/${ws}/targets/${f.organization_id}/projects/${f.project_id}`} className="hover:text-crimson-text">{f.organization_name} — {f.project_name}</Link>],
    ["Affected asset", f.asset_id ? <Link key="a" href={`/w/${ws}/targets/${f.organization_id}/assets/${f.asset_id}`} className="font-mono hover:text-crimson-text">{f.asset_value}</Link> : "—"],
    ["Confidence", <span key="c" className="capitalize">{f.confidence}</span>],
    ["Origin", f.origin === "deterministic_check" ? "Rule check" : f.origin === "human" ? "Recorded by a person" : "Agent"],
    ["Discovery source", f.discovery_source || "—"],
    ["Rule", f.rule_id ? <span key="r" className="font-mono text-xs">{f.rule_id}</span> : "—"],
    ["First observed", formatDateTime(f.first_observed_at)],
    ["Last observed", formatDateTime(f.last_observed_at)],
    ["Recorded by", f.created_by ?? (f.origin === "deterministic_check" ? "Worker (rule)" : "—")],
  ];
  return (
    <>
      <nav className="mb-2 text-sm text-muted"><Link href={`/w/${ws}/findings`} className="hover:text-text">Findings</Link> / <span className="font-mono">{f.ref}</span></nav>
      <PageHeader title={f.title} actions={<><SeverityBadge severity={f.severity} /><StatusBadge status={f.validation_status} /></>} />
      {f.validation_status === "hypothesis" && <Alert tone="yellow">Hypothesis: plausible, but not shown by evidence. Don&apos;t treat it as a confirmed vulnerability.</Alert>}
      {f.validated_by && <Alert tone={f.validation_status === "validated" ? "green" : "blue"}>Marked {f.validation_status.replace("_", " ")} by {f.validated_by} on {formatDateTime(f.validated_at)}{f.status_note && `: ${f.status_note}`}</Alert>}
      {!f.validated_by && f.status_note && <Alert tone="yellow">{f.status_note}</Alert>}
      <div className="mt-4 grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-6">
          <Panel title="Details">
            <div className="space-y-4 text-sm">
              <section><h3 className="font-medium">Description</h3><p className="mt-1 whitespace-pre-wrap text-muted">{f.description || "—"}</p></section>
              <section><h3 className="font-medium">Potential impact</h3><p className="mt-1 whitespace-pre-wrap text-muted">{f.impact || "—"}</p></section>
              <section><h3 className="font-medium">Recommended remediation</h3><p className="mt-1 whitespace-pre-wrap text-muted">{f.remediation || "—"}</p></section>
            </div>
          </Panel>
          <Panel title={`Supporting evidence (${f.evidence.length})`}>
            {f.evidence.length === 0 && <p className="mb-3 text-sm text-muted">No evidence linked. A finding can&apos;t be validated without it.</p>}
            <EvidenceList ws={ws} items={f.evidence} />
            {f.evidence.length > 0 && <p className="mt-2 text-xs text-muted">Linked by: {f.evidence.map((e) => e.linked_by.startsWith("rule:") ? `rule ${e.linked_by.slice(5)}` : "a person").join(", ")}</p>}
            {can.editFindings(me.role) && <div className="mt-4"><LinkEvidence ws={ws} finding={f} options={options} /></div>}
          </Panel>
          {f.attack_paths.length > 0 && (
            <Panel title="Attack paths using this finding">
              <ul className="space-y-1 text-sm">{f.attack_paths.map((p) => <li key={p.id}><Link href={`/w/${ws}/attack-graph?project=${f.project_id}&path=${p.id}`} className="hover:text-crimson-text">{p.title}</Link> <span className="text-muted">({p.status})</span></li>)}</ul>
            </Panel>
          )}
        </div>
        <div className="space-y-6">
          {f.origin === "agent" && (
            <Panel title="AI provenance">
              <div className="space-y-3 text-sm">
                <p className="text-muted">Proposed by the Hunter agent. It stays a hypothesis until a person reviews the evidence and decides.</p>
                {f.proposed_by_task_id && <Link className="hover:text-crimson-text" href={`/w/${ws}/agents/${f.proposed_by_task_id}`}>Open the agent task</Link>}
                {f.guardian_review ? (
                  <div className="space-y-2 rounded-md border border-dashed border-border-strong p-3">
                    <GuardianVerdictBadge value={f.guardian_review.verdict} />
                    <p>{f.guardian_review.rationale}</p>
                    <p className="text-xs text-muted">
                      Severity: {f.guardian_review.severity_assessment.replace("_", " ")} · {f.guardian_review.model} · {formatDateTime(f.guardian_review.reviewed_at)}.
                      Advice only; it doesn&apos;t change the status.
                    </p>
                  </div>
                ) : <p className="text-muted">Guardian review pending.</p>}
              </div>
            </Panel>
          )}
          <Panel title="Facts"><dl className="space-y-2 text-sm">{facts.map(([k, v]) => <div key={k} className="flex justify-between gap-4"><dt className="text-muted">{k}</dt><dd className="text-right">{v}</dd></div>)}</dl></Panel>
          {can.editFindings(me.role) && <Panel title="Decision"><StatusDecision ws={ws} finding={f} /></Panel>}
          {can.editFindings(me.role) && <Panel title="Edit"><EditFinding ws={ws} finding={f} /></Panel>}
        </div>
      </div>
    </>
  );
}
