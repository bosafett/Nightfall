import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Report, Severity, ValidationStatus } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { SEVERITIES, assessmentTypeLabel, severityLabel } from "@/lib/labels";
import { SeverityBadge, StatusBadge } from "@/components/findings/Badges";
import { PrintButton } from "@/components/reports/ReportActions";
import { Alert } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Report" };

type F = { ref: string; title: string; severity: Severity; confidence: string; status: ValidationStatus; origin: string; asset: string | null;
  description: string; impact: string; remediation: string; first_observed_at: string; last_observed_at: string; decided_by: string | null;
  decision_note: string; rule_id: string | null; evidence: { id: string; sha256: string; tool: string; source: string; collected_at: string }[] };
type P = { title: string; status: string; narrative: string; reviewed_by: string | null; review_note: string;
  steps: { ordinal: number; description: string; finding_ref: string | null; finding_title: string | null; asset_value: string | null }[] };

function H2({ n, children }: { n: number; children: React.ReactNode }) {
  return <h2 className="mt-10 mb-3 border-b border-border pb-1 text-xl font-semibold break-after-avoid"><span className="mr-2 font-mono text-muted">{n}.</span>{children}</h2>;
}

export default async function ReportPage({ params }: { params: Promise<{ ws: string; reportId: string }> }) {
  const { ws, reportId } = await params;
  const r = await apiGet<Report>(`/workspaces/${ws}/reports/${reportId}`);
  const c = r.content as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  const findings = c.findings as F[];
  const paths = c.attack_paths as P[];
  const open = c.severity_breakdown.open as Record<Severity, number>;
  const confirmed = findings.filter((f) => f.status === "validated" || f.status === "unverified");
  const hypotheses = findings.filter((f) => f.status === "hypothesis");
  const closed = findings.filter((f) => f.status === "false_positive" || f.status === "remediated");

  const FindingBlock = ({ f }: { f: F }) => (
    <article className="break-inside-avoid rounded-md border border-border p-4 print:border-gray">
      <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs text-muted">{f.ref}</span><SeverityBadge severity={f.severity} /><StatusBadge status={f.status} /></div>
      <h3 className="mt-2 font-semibold">{f.title}</h3>
      <p className="text-xs text-muted">Asset: <span className="font-mono">{f.asset ?? "—"}</span> · confidence {f.confidence} · {f.origin === "deterministic_check" ? `rule ${f.rule_id}` : "recorded by a person"} · first seen {formatDateTime(f.first_observed_at)}</p>
      {f.description && <p className="mt-2 text-sm whitespace-pre-wrap">{f.description}</p>}
      {f.impact && <p className="mt-2 text-sm"><span className="font-medium">Impact: </span>{f.impact}</p>}
      {f.remediation && <p className="mt-1 text-sm"><span className="font-medium">Remediation: </span>{f.remediation}</p>}
      {f.decided_by && <p className="mt-2 text-xs text-muted">Decision by {f.decided_by}: {f.decision_note}</p>}
      <p className="mt-2 text-xs text-muted">Evidence: {f.evidence.length === 0 ? "none linked" : f.evidence.map((e) => `${e.tool} ${formatDateTime(e.collected_at)} (sha256 ${e.sha256.slice(0, 12)}…)`).join("; ")}</p>
    </article>
  );

  let n = 0;
  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 print:hidden">
        <Link href={`/w/${ws}/reports?project=${r.project_id}`} className="text-sm text-muted hover:text-text">← Reports</Link>
        <span className="flex items-center gap-3">
          <Link href={`/w/${ws}/reports/${r.id}/replay`} className="text-sm text-crimson-text hover:underline">Check against current rules</Link>
          <PrintButton />
        </span>
      </div>
      {!r.integrity_ok && <Alert>Integrity check failed: this snapshot no longer matches its SHA-256. Don&apos;t rely on it.</Alert>}
      <header className="border-b border-border pb-4">
        <p className="text-xs font-semibold tracking-[0.3em] text-crimson-text">DRE · NIGHTFALL · ASSESSMENT REPORT</p>
        <h1 className="mt-2 text-3xl font-semibold">{c.organization.name} — {c.project.name}</h1>
        <p className="mt-1 text-muted">{assessmentTypeLabel[c.project.assessment_type as keyof typeof assessmentTypeLabel]} · generated {formatDateTime(c.generated_at)} by {r.taken_by}</p>
        <p className="mt-1 font-mono text-xs text-muted break-all">Snapshot {r.id} · SHA-256 {r.sha256} · rulesets {Object.values(c.rulesets).join(", ")}</p>
      </header>

      <H2 n={++n}>Executive summary</H2>
      <div className="space-y-2">{(c.executive_summary as string[]).map((s, i) => <p key={i}>{s}</p>)}</div>

      <H2 n={++n}>Assessment scope</H2>
      {c.scope ? (
        <div className="text-sm">
          {c.scope.is_lab && (
            <p className="mb-2 rounded-md border border-blue/50 px-3 py-2 text-sm"><span className="font-semibold">LAB · ISOLATED.</span> These results come from the isolated lab
              against practice targets, not from real systems.</p>
          )}
          <p>Scope v{c.scope.version}, authorization <span className="font-medium">{c.scope.reference}</span>, authorized by {c.scope.authorized_by} on {formatDateTime(c.scope.authorized_at)}.</p>
          <p className="mt-2">In scope: <span className="font-mono">{c.scope.targets.map((t: { value: string }) => t.value).join(", ")}</span></p>
          <p className="mt-1">Excluded: <span className="font-mono">{c.scope.exclusions.map((t: { value: string; reason: string }) => `${t.value}${t.reason ? ` (${t.reason})` : ""}`).join(", ") || "none"}</span></p>
        </div>
      ) : <p className="text-sm">No authorized scope.</p>}

      <H2 n={++n}>Methodology</H2>
      <ul className="list-disc space-y-1 pl-5 text-sm">
        {(c.methodology.collectors as { label: string; risk_class: string; runs: number; succeeded: number; denied_or_rejected: number }[]).map((m) => (
          <li key={m.label}>{m.label} ({m.risk_class} risk): {m.runs} runs, {m.succeeded} completed, {m.denied_or_rejected} refused or rejected.</li>
        ))}
        <li>Every collection request was checked against the authorized scope. Anything above passive required approval by a second person.</li>
        <li>Findings from rule checks start unverified; only a person can validate, dismiss or close one.</li>
      </ul>

      <H2 n={++n}>Severity breakdown (open findings)</H2>
      <table className="text-sm"><tbody>{SEVERITIES.map((s) => <tr key={s}><td className="py-1 pr-4"><SeverityBadge severity={s} /></td><td className="font-mono tabular">{open[s] ?? 0}</td></tr>)}</tbody></table>
      <p className="mt-2 text-xs text-muted">{severityLabel.critical} to {severityLabel.info.toLowerCase()}; counts include unverified findings and hypotheses, listed separately below. No overall risk score is calculated.</p>

      <H2 n={++n}>Findings</H2>
      {confirmed.length === 0 ? <p className="text-sm">No validated or unverified findings.</p> : <div className="space-y-3">{confirmed.map((f) => <FindingBlock key={f.ref} f={f} />)}</div>}

      <H2 n={++n}>Potential attack paths</H2>
      {paths.length === 0 ? <p className="text-sm">None proposed.</p> : paths.map((p) => (
        <article key={p.title} className="mb-3 break-inside-avoid rounded-md border border-border p-4 print:border-gray">
          <p className="font-semibold">{p.title} <span className="text-sm font-normal text-muted">— {p.status === "validated" ? `validated by ${p.reviewed_by}` : p.status === "rejected" ? "rejected" : "hypothesis, not demonstrated"}</span></p>
          {p.narrative && <p className="mt-1 text-sm">{p.narrative}</p>}
          <ol className="mt-2 list-decimal pl-5 text-sm">{p.steps.map((s) => <li key={s.ordinal}>{s.finding_ref ? `${s.finding_ref} ${s.finding_title}` : s.asset_value} — {s.description}</li>)}</ol>
        </article>
      ))}

      <H2 n={++n}>Assets discovered ({c.assets.length})</H2>
      <table className="w-full text-left text-sm"><thead className="text-xs uppercase text-muted"><tr><th className="py-1">Asset</th><th>Type</th><th>Source</th><th>Last seen</th></tr></thead>
        <tbody>{(c.assets as { kind: string; value: string; source: string; last_seen_at: string }[]).map((a) => <tr key={`${a.kind}${a.value}`} className="border-t border-border"><td className="py-1 font-mono">{a.value}</td><td>{a.kind.replace("_", " ")}</td><td>{a.source}</td><td className="font-mono text-xs">{formatDateTime(a.last_seen_at)}</td></tr>)}</tbody>
      </table>

      <H2 n={++n}>Limitations and unverified hypotheses</H2>
      <ul className="list-disc space-y-1 pl-5 text-sm">{(c.limitations as string[]).map((l, i) => <li key={i}>{l}</li>)}</ul>
      {hypotheses.length > 0 && <div className="mt-4 space-y-3"><p className="text-sm font-medium">Hypotheses (not confirmed)</p>{hypotheses.map((f) => <FindingBlock key={f.ref} f={f} />)}</div>}
      {closed.length > 0 && <div className="mt-4 space-y-3"><p className="text-sm font-medium">Dismissed or remediated</p>{closed.map((f) => <FindingBlock key={f.ref} f={f} />)}</div>}
      <p className="mt-10 border-t border-border pt-3 text-xs text-muted">Generated by NIGHTFALL from snapshot {r.id}. Authorized use only.</p>
    </div>
  );
}
