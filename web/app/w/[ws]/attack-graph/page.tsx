import type { Metadata } from "next";
import { apiGet } from "@/lib/api/server";
import type { Asset, AttackPath, Finding, Project, ProjectGraph } from "@/lib/api/types";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { AttackGraph } from "@/components/graph/AttackGraph";
import { NewPath, PathCard } from "@/components/graph/PathEditor";
import { Button, EmptyState, PageHeader, Panel, Select } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Attack Graph" };

export default async function AttackGraphPage({ params, searchParams }: { params: Promise<{ ws: string }>; searchParams: Promise<{ project?: string; path?: string }> }) {
  const { ws } = await params;
  const sp = await searchParams;
  const [projects, me] = await Promise.all([apiGet<Project[]>(`/workspaces/${ws}/projects`), membership(ws)]);
  const project = projects.find((p) => p.id === sp.project) ?? projects[0];
  if (!project) {
    return (<><PageHeader title="Attack Graph" subtitle="Relationships between assets, findings and potential attack paths" />
      <EmptyState title="No projects yet" body="Create a project in the Target Registry first." /></>);
  }
  const [graph, paths, findings, assets] = await Promise.all([
    apiGet<ProjectGraph>(`/workspaces/${ws}/projects/${project.id}/graph`),
    apiGet<AttackPath[]>(`/workspaces/${ws}/projects/${project.id}/attack-paths`),
    apiGet<Finding[]>(`/workspaces/${ws}/findings?project_id=${project.id}`),
    apiGet<Asset[]>(`/workspaces/${ws}/assets?organization_id=${project.organization_id}`),
  ]);
  const editable = can.editFindings(me.role);
  return (
    <>
      <PageHeader title="Attack Graph" subtitle="Recorded relationships are solid; hypotheses are dashed and never shown as compromises."
        actions={
          <form method="get" className="flex gap-2">
            <Select name="project" defaultValue={project.id} aria-label="Project" className="w-auto">{projects.map((p) => <option key={p.id} value={p.id}>{p.organization_name} — {p.name}</option>)}</Select>
            <Button type="submit">Show</Button>
          </form>
        } />
      <div className="space-y-6">
        <Panel title={`${project.organization_name} — ${project.name}`}>
          {graph.nodes.length === 0 ? <p className="py-10 text-center text-sm text-muted">Nothing recorded yet for this project. Run collection or record findings first.</p>
            : <AttackGraph ws={ws} orgId={project.organization_id} graph={graph} highlightPath={sp.path} />}
        </Panel>
        <Panel title={`Attack paths (${paths.length})`}>
          <div className="space-y-4">
            {editable && <NewPath ws={ws} projectId={project.id} findings={findings.filter((f) => f.validation_status !== "false_positive")} assets={assets} />}
            {paths.length === 0 && <p className="text-sm text-muted">No attack paths proposed yet.</p>}
            {paths.map((p) => <PathCard key={p.id} ws={ws} path={p} canReview={editable} selected={p.id === sp.path} />)}
          </div>
        </Panel>
      </div>
    </>
  );
}
