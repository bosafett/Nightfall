import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGet } from "@/lib/api/server";
import type { AgentsInfo, AgentTask, AgentTaskDetail, Asset, Operation, Project, ScopeVersion } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { assessmentTypeLabel, can } from "@/lib/labels";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { AgentTasksTable } from "@/components/agents/AgentTasksTable";
import { RunAgent } from "@/components/agents/RunAgent";
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
  const [project, scopes, ops, me, ai, tasks, assets] = await Promise.all([
    apiGet<Project>(`/workspaces/${ws}/projects/${projectId}`),
    apiGet<ScopeVersion[]>(`/workspaces/${ws}/projects/${projectId}/scopes`),
    apiGet<Operation[]>(`/workspaces/${ws}/operations?project_id=${encodeURIComponent(projectId)}&limit=20`),
    membership(ws),
    apiGet<AgentsInfo>(`/workspaces/${ws}/agents`),
    apiGet<AgentTask[]>(`/workspaces/${ws}/projects/${projectId}/agent-tasks`),
    apiGet<Asset[]>(`/workspaces/${ws}/assets?organization_id=${encodeURIComponent(orgId)}`),
  ]);
  const lastSummary = tasks.find((t) => t.agent === "analyst" && t.status === "succeeded");
  const summary = lastSummary ? await apiGet<AgentTaskDetail>(`/workspaces/${ws}/agent-tasks/${lastSummary.id}`) : null;
  const active = scopes.find((v) => v.status === "active");
  const suggestions = active ? active.targets.filter((t) => t.kind === "host" || t.kind === "domain_tree").map((t) => t.value) : [];
  const writable = can.writeRegistry(me.role);
  const pending = ops.some((o) => o.status === "queued" || o.status === "running")
    || tasks.some((t) => t.status === "queued" || t.status === "running");
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
            <AutoRefresh ws={ws} active={pending} />
            {ops.length > 0 ? <OperationsTable ws={ws} ops={ops} showProject={false} /> : <p className="text-sm text-muted">No collection has run for this project yet.</p>}
          </div>
        </Panel>
        <Panel title="AI agents">
          {!ai.ai_enabled ? (
            <p className="text-sm text-muted">AI is off on this deployment. Everything else works without it; an owner can turn it on by configuring a model provider.</p>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-muted">
                Agents only propose. Collections they suggest are checked against the scope, and anything that contacts a target still needs
                an explicit approval. Findings, relationships and attack paths they suggest are recorded as hypotheses
                (findings each reviewed by Guardian) until a person decides.
                Model: <span className="font-mono">{ai.model}</span>. Project data is sent to the model provider.
              </p>
              {summary && typeof summary.result.summary === "string" && (
                <div className="rounded-md border border-dashed border-border-strong p-3" data-testid="analyst-summary">
                  <p className="text-xs font-medium text-muted">
                    Latest assessment summary by Analyst (AI-written, not verified) · <span className="font-mono tabular">{formatDateTime(summary.finished_at)}</span> ·{" "}
                    <Link href={`/w/${ws}/agents/${summary.id}`} className="text-crimson-text hover:underline">details</Link>
                  </p>
                  <p className="mt-1 whitespace-pre-wrap text-sm">{summary.result.summary}</p>
                </div>
              )}
              {writable ? <RunAgent ws={ws} projectId={projectId} assets={assets.map((a) => ({ id: a.id, value: a.value }))} /> : <p className="text-sm text-muted">Your role can view agent results but not start agents.</p>}
              {tasks.length > 0 ? <AgentTasksTable ws={ws} tasks={tasks} /> : <p className="text-sm text-muted">No agent has run for this project yet.</p>}
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
