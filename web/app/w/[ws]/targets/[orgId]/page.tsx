import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Organization, Project } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { assessmentTypeLabel, can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { EditOrganization, NewProject } from "@/components/registry/Forms";
import { ProjectStatusBadge } from "@/components/registry/StatusBadge";
import { DataTable, EmptyState, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Organization" };

export default async function OrganizationPage({ params }: { params: Promise<{ ws: string; orgId: string }> }) {
  const { ws, orgId } = await params;
  const [org, projects, me] = await Promise.all([
    apiGet<Organization>(`/workspaces/${ws}/organizations/${orgId}`),
    apiGet<Project[]>(`/workspaces/${ws}/projects?organization_id=${encodeURIComponent(orgId)}`),
    membership(ws),
  ]);
  const writable = can.writeRegistry(me.role);

  return (
    <>
      <nav className="mb-2 text-sm text-muted"><Link href={`/w/${ws}/targets`} className="hover:text-text">Target Registry</Link> /</nav>
      <PageHeader title={org.name} subtitle={org.notes || "No notes."} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          {writable && <NewProject ws={ws} orgId={org.id} />}
          {projects.length === 0 ? (
            <EmptyState title="No projects yet" body="Each assessment is a project with its own type and status. Scope is defined per project in phase 3." />
          ) : (
            <Panel title="Projects">
              <DataTable head={["Project", "Type", "Status", "Started"]}>
                {projects.map((p) => (
                  <tr key={p.id} className="hover:bg-surface-2">
                    <td className="px-4 py-3">
                      <Link href={`/w/${ws}/targets/${org.id}/projects/${p.id}`} className="font-medium hover:text-crimson-text">{p.name}</Link>
                    </td>
                    <td className="px-4 py-3 text-muted">{assessmentTypeLabel[p.assessment_type]}</td>
                    <td className="px-4 py-3"><ProjectStatusBadge status={p.status} /></td>
                    <td className="px-4 py-3 font-mono text-xs text-muted tabular">{formatDateTime(p.started_at)}</td>
                  </tr>
                ))}
              </DataTable>
            </Panel>
          )}
        </div>
        {writable && <Panel title="Details"><EditOrganization ws={ws} org={org} /></Panel>}
      </div>
    </>
  );
}
