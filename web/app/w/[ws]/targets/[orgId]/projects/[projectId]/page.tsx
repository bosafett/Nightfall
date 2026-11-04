import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGet } from "@/lib/api/server";
import type { Operation, Project, ScopeVersion } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { assessmentTypeLabel, can } from "@/lib/labels";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { CollectionForm } from "@/components/recon/CollectionForm";
import { OperationsTable } from "@/components/recon/OperationsTable";
import { ScopePanel } from "@/components/scope/ScopePanel";
import { membership } from "@/lib/workspace";
import { EditProject } from "@/components/registry/Forms";
import { ProjectStatusBadge } from "@/components/registry/StatusBadge";
import { PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Project" };

export default async function ProjectPage({ params }: { params: Promise<{ ws: string; orgId: string; projectId: string }> }) {
  const { ws, orgId, projectId } = await params;
  const [project, scopes, ops, me] = await Promise.all([
    apiGet<Project>(`/workspaces/${ws}/projects/${projectId}`),
    apiGet<ScopeVersion[]>(`/workspaces/${ws}/projects/${projectId}/scopes`),
    apiGet<Operation[]>(`/workspaces/${ws}/operations?project_id=${encodeURIComponent(projectId)}&limit=20`),
    membership(ws),
  ]);
  const active = scopes.find((v) => v.status === "active");
  const suggestions = active ? active.targets.filter((t) => t.kind === "host" || t.kind === "domain_tree").map((t) => t.value) : [];
  const writable = can.writeRegistry(me.role);
  const pending = ops.some((o) => o.status === "queued" || o.status === "running");
  if (project.organization_id !== orgId) notFound();

  return (
    <>
      <nav className="mb-2 text-sm text-muted">
        <Link href={`/w/${ws}/targets`} className="hover:text-text">Target Registry</Link> /{" "}
        <Link href={`/w/${ws}/targets/${orgId}`} className="hover:text-text">{project.organization_name}</Link> /
      </nav>
      <PageHeader title={project.name} subtitle={assessmentTypeLabel[project.assessment_type]} actions={<ProjectStatusBadge status={project.status} />} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Project"><EditProject ws={ws} project={project} canWrite={writable} /></Panel>
        <Panel title="Timeline">
          <dl className="space-y-3 text-sm">
            {([["Created", project.created_at], ["Started", project.started_at], ["Last updated", project.updated_at]] as const).map(([k, v]) => (
              <div key={k}><dt className="text-muted">{k}</dt><dd className="font-mono tabular">{formatDateTime(v)}</dd></div>
            ))}
          </dl>
        </Panel>
      </div>
      <div className="mt-6 space-y-6">
        <Panel title="Authorized scope">
          <ScopePanel ws={ws} projectId={projectId} versions={scopes} canEdit={writable} canAuthorize={can.authorizeScope(me.role)} />
        </Panel>
        <Panel title="Passive collection">
          {active && writable ? <CollectionForm ws={ws} projectId={projectId} suggestions={suggestions} />
            : <p className="text-sm text-muted">{active ? "Your role can view collection results but not request collection." : "Authorize a scope first."}</p>}
          <div className="mt-6">
            <AutoRefresh active={pending} />
            {ops.length > 0 ? <OperationsTable ws={ws} ops={ops} showProject={false} /> : <p className="text-sm text-muted">No collection has run for this project yet.</p>}
          </div>
        </Panel>
      </div>
    </>
  );
}
