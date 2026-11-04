import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGet } from "@/lib/api/server";
import type { Project } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { assessmentTypeLabel, can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { EditProject } from "@/components/registry/Forms";
import { ProjectStatusBadge } from "@/components/registry/StatusBadge";
import { PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Project" };

export default async function ProjectPage({ params }: { params: Promise<{ ws: string; orgId: string; projectId: string }> }) {
  const { ws, orgId, projectId } = await params;
  const [project, me] = await Promise.all([apiGet<Project>(`/workspaces/${ws}/projects/${projectId}`), membership(ws)]);
  if (project.organization_id !== orgId) notFound();

  return (
    <>
      <nav className="mb-2 text-sm text-muted">
        <Link href={`/w/${ws}/targets`} className="hover:text-text">Target Registry</Link> /{" "}
        <Link href={`/w/${ws}/targets/${orgId}`} className="hover:text-text">{project.organization_name}</Link> /
      </nav>
      <PageHeader title={project.name} subtitle={assessmentTypeLabel[project.assessment_type]} actions={<ProjectStatusBadge status={project.status} />} />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Project"><EditProject ws={ws} project={project} canWrite={can.writeRegistry(me.role)} /></Panel>
        <Panel title="Timeline">
          <dl className="space-y-3 text-sm">
            {([["Created", project.created_at], ["Started", project.started_at], ["Last updated", project.updated_at]] as const).map(([k, v]) => (
              <div key={k}><dt className="text-muted">{k}</dt><dd className="font-mono tabular">{formatDateTime(v)}</dd></div>
            ))}
          </dl>
          <p className="mt-4 text-xs text-muted">Scope, assets and findings attach to this project from phase 3.</p>
        </Panel>
      </div>
    </>
  );
}
