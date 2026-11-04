import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Asset, Organization, Project } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { assessmentTypeLabel, assetKindLabel, can, ownershipLabel } from "@/lib/labels";
import { NewAsset } from "@/components/assets/AssetForms";
import { membership } from "@/lib/workspace";
import { EditOrganization, NewProject } from "@/components/registry/Forms";
import { ProjectStatusBadge } from "@/components/registry/StatusBadge";
import { DataTable, EmptyState, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Organization" };

export default async function OrganizationPage({ params }: { params: Promise<{ ws: string; orgId: string }> }) {
  const { ws, orgId } = await params;
  const q = `organization_id=${encodeURIComponent(orgId)}`;
  const [org, projects, assets, me] = await Promise.all([
    apiGet<Organization>(`/workspaces/${ws}/organizations/${orgId}`),
    apiGet<Project[]>(`/workspaces/${ws}/projects?${q}`),
    apiGet<Asset[]>(`/workspaces/${ws}/assets?${q}`),
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
          <Panel title={`Assets (${assets.length})`}>
            {writable && <div className="mb-4"><NewAsset ws={ws} orgId={org.id} /></div>}
            {assets.length === 0 ? (
              <p className="text-sm text-muted">No assets yet. Register them here, or run passive collection from a project with an authorized scope.</p>
            ) : (
              <DataTable head={["Asset", "Type", "Ownership", "Source", "Last seen"]}>
                {assets.map((a) => (
                  <tr key={a.id} className="hover:bg-surface-2">
                    <td className="px-4 py-2.5"><Link href={`/w/${ws}/targets/${org.id}/assets/${a.id}`} className="font-mono text-sm hover:text-crimson-text">{a.value}</Link></td>
                    <td className="px-4 py-2.5 text-muted">{assetKindLabel[a.kind]}</td>
                    <td className="px-4 py-2.5 text-muted">{ownershipLabel[a.ownership]}</td>
                    <td className="px-4 py-2.5 text-xs text-muted">{a.source}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted tabular">{formatDateTime(a.last_seen_at)}</td>
                  </tr>
                ))}
              </DataTable>
            )}
          </Panel>
        </div>
        {writable && <Panel title="Details"><EditOrganization ws={ws} org={org} /></Panel>}
      </div>
    </>
  );
}
