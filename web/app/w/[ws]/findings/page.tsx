import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Asset, Finding, Organization, Project, Severity, ValidationStatus } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { SEVERITIES, STATUSES, can, severityLabel, statusLabel } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { SeverityBadge, StatusBadge } from "@/components/findings/Badges";
import { NewFinding } from "@/components/findings/FindingForms";
import { Button, DataTable, EmptyState, PageHeader, Panel, Select } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Findings" };

type SP = { severity?: string | string[]; status?: string | string[]; org?: string; sort?: string };
const arr = (v: string | string[] | undefined) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

export default async function FindingsPage({ params, searchParams }: { params: Promise<{ ws: string }>; searchParams: Promise<SP> }) {
  const { ws } = await params;
  const sp = await searchParams;
  const sev = arr(sp.severity).filter((v): v is Severity => (SEVERITIES as string[]).includes(v));
  const st = arr(sp.status).filter((v): v is ValidationStatus => (STATUSES as string[]).includes(v));
  const sort = ["severity", "discovered", "last_seen"].includes(sp.sort ?? "") ? sp.sort! : "severity";
  const q = new URLSearchParams({ sort });
  sev.forEach((v) => q.append("severity", v));
  st.forEach((v) => q.append("status", v));
  if (sp.org && /^[0-9a-f-]{36}$/.test(sp.org)) q.set("organization_id", sp.org);
  const [findings, orgs, projects, assets, me] = await Promise.all([
    apiGet<Finding[]>(`/workspaces/${ws}/findings?${q}`),
    apiGet<Organization[]>(`/workspaces/${ws}/organizations`),
    apiGet<Project[]>(`/workspaces/${ws}/projects`),
    apiGet<Asset[]>(`/workspaces/${ws}/assets`),
    membership(ws),
  ]);
  const filtered = sev.length > 0 || st.length > 0 || !!sp.org;

  return (
    <>
      <PageHeader title="Findings" subtitle="Every finding traces to its evidence. Hypotheses are marked with a dashed border and never count as confirmed." />
      {can.editFindings(me.role) && <div className="mb-6"><NewFinding ws={ws} projects={projects} assets={assets} /></div>}
      <Panel title="Filter">
        <form method="get" className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_1fr_14rem_12rem_auto] lg:items-end">
          <fieldset><legend className="mb-1 text-sm font-medium">Severity</legend>
            <div className="flex flex-wrap gap-3">{SEVERITIES.map((v) => (
              <label key={v} className="flex items-center gap-1.5 text-sm"><input type="checkbox" name="severity" value={v} defaultChecked={sev.includes(v)} className="accent-[#CC1426]" />{severityLabel[v]}</label>
            ))}</div>
          </fieldset>
          <fieldset><legend className="mb-1 text-sm font-medium">Status</legend>
            <div className="flex flex-wrap gap-3">{STATUSES.map((v) => (
              <label key={v} className="flex items-center gap-1.5 text-sm"><input type="checkbox" name="status" value={v} defaultChecked={st.includes(v)} className="accent-[#CC1426]" />{statusLabel[v]}</label>
            ))}</div>
          </fieldset>
          <label className="block"><span className="mb-1 block text-sm font-medium">Organization</span>
            <Select name="org" defaultValue={sp.org ?? ""}><option value="">All</option>{orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</Select>
          </label>
          <label className="block"><span className="mb-1 block text-sm font-medium">Sort by</span>
            <Select name="sort" defaultValue={sort}><option value="severity">Severity</option><option value="discovered">Discovered (newest)</option><option value="last_seen">Last seen (newest)</option></Select>
          </label>
          <div className="flex gap-2"><Button type="submit">Apply</Button>{filtered && <Link href={`/w/${ws}/findings`} className="self-center text-sm text-muted hover:text-text">Clear</Link>}</div>
        </form>
      </Panel>
      <div className="mt-6">
        {findings.length === 0 ? (
          <EmptyState title={filtered ? "No findings match" : "No findings yet"}
            body={filtered ? "Try fewer filters." : "Findings come from rule checks on collected evidence (for example technology identification), or record one yourself."} />
        ) : (
          <Panel title={`${findings.length} ${findings.length === 1 ? "finding" : "findings"}`}>
            <DataTable head={["Ref", "Severity", "Finding", "Asset", "Status", "Evidence", "Discovered"]}>
              {findings.map((f) => (
                <tr key={f.id} className="hover:bg-surface-2">
                  <td className="px-4 py-3 font-mono text-xs text-muted">{f.ref}</td>
                  <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-3">
                    <Link href={`/w/${ws}/findings/${f.id}`} className="font-medium hover:text-crimson-text">{f.title}</Link>
                    <span className="block text-xs text-muted">{f.organization_name} — {f.project_name}{f.origin === "deterministic_check" && " · rule check"}</span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{f.asset_value ?? "—"}</td>
                  <td className="px-4 py-3"><StatusBadge status={f.validation_status} /></td>
                  <td className="px-4 py-3 font-mono text-sm tabular">{f.evidence_count}</td>
                  <td className="px-4 py-3 font-mono text-xs text-muted tabular">{formatDateTime(f.first_observed_at)}</td>
                </tr>
              ))}
            </DataTable>
          </Panel>
        )}
      </div>
    </>
  );
}
