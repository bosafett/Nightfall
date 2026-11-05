import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Project, ReportSummary } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { GenerateReport } from "@/components/reports/ReportActions";
import { Button, DataTable, EmptyState, PageHeader, Panel, Select } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Reports" };

export default async function ReportsPage({ params, searchParams }: { params: Promise<{ ws: string }>; searchParams: Promise<{ project?: string }> }) {
  const { ws } = await params;
  const sp = await searchParams;
  const [projects, me] = await Promise.all([apiGet<Project[]>(`/workspaces/${ws}/projects`), membership(ws)]);
  const project = projects.find((p) => p.id === sp.project) ?? projects[0];
  if (!project) return (<><PageHeader title="Reports" subtitle="Assessment reports from stored data" /><EmptyState title="No projects yet" body="Create a project first." /></>);
  const reports = await apiGet<ReportSummary[]>(`/workspaces/${ws}/projects/${project.id}/reports`);
  return (
    <>
      <PageHeader title="Reports" subtitle="A report freezes the project's current state into a hashed snapshot. It never changes afterwards."
        actions={<form method="get" className="flex gap-2"><Select name="project" defaultValue={project.id} aria-label="Project" className="w-auto">{projects.map((p) => <option key={p.id} value={p.id}>{p.organization_name} — {p.name}</option>)}</Select><Button type="submit">Show</Button></form>} />
      <Panel title={`${project.organization_name} — ${project.name}`}>
        {can.editFindings(me.role) && <div className="mb-4"><GenerateReport ws={ws} projectId={project.id} /></div>}
        {reports.length === 0 ? <p className="text-sm text-muted">No reports for this project yet.</p> : (
          <DataTable head={["Generated", "By", "Open findings", "SHA-256"]}>
            {reports.map((r) => (
              <tr key={r.id} className="hover:bg-surface-2">
                <td className="px-4 py-3"><Link href={`/w/${ws}/reports/${r.id}`} className="font-mono text-sm hover:text-crimson-text">{formatDateTime(r.taken_at)}</Link></td>
                <td className="px-4 py-3">{r.taken_by}</td>
                <td className="px-4 py-3 font-mono tabular">{r.findings_open}</td>
                <td className="px-4 py-3 font-mono text-xs text-muted" title={r.sha256}>{r.sha256.slice(0, 16)}…</td>
              </tr>
            ))}
          </DataTable>
        )}
      </Panel>
    </>
  );
}
