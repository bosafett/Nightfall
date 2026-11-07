import type { Metadata } from "next";
import { apiGet } from "@/lib/api/server";
import type { WorkflowRun, Workflows } from "@/lib/api/types";
import { kindLabel } from "@/components/nexus/labels";
import { RunsTable } from "@/components/nexus/RunsTable";
import { Badge, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "NEXUS" };

export default async function NexusPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [defs, runs] = await Promise.all([
    apiGet<Workflows>(`/workspaces/${ws}/nexus/workflows`),
    apiGet<WorkflowRun[]>(`/workspaces/${ws}/workflow-runs`),
  ]);
  return (
    <>
      <PageHeader title="NEXUS" subtitle="Workflows of ordinary steps: each one checked, and approved where it needs to be, when it starts" />
      <div className="space-y-6">
        <Panel title="Runs">
          {runs.length === 0
            ? <p className="text-sm text-muted">No workflow has run yet. Start one from a project, or reassess a remediated finding.</p>
            : <RunsTable ws={ws} runs={runs} />}
        </Panel>
        <Panel title="Available workflows">
          <div className="space-y-5">
            {defs.workflows.map((w) => (
              <section key={w.id} aria-label={w.name}>
                <h3 className="font-medium">{w.name} <span className="font-mono text-xs text-muted">v{w.version} · {w.sha256.slice(0, 12)}</span></h3>
                <p className="text-sm text-muted">{w.summary} Starts from {w.starts_from === "target" ? "a scope target (on a project)" : "a remediated finding"}; ends after {w.deadline_days} days at most.</p>
                <ol className="mt-2 space-y-1 text-sm">
                  {w.steps.map((s, i) => (
                    <li key={s.key} className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-muted tabular">{i + 1}.</span>
                      <span>{s.label}</span>
                      <Badge tone="gray">{kindLabel[s.kind] ?? s.kind}</Badge>
                      {s.starts === "person" && <Badge tone="yellow">A person starts it</Badge>}
                      {s.when !== "always" && <span className="text-xs text-muted">only if {s.when.replace(/_/g, " ")}</span>}
                    </li>
                  ))}
                </ol>
              </section>
            ))}
            <p className="text-xs text-muted">
              Not available yet: {defs.unavailable_step_kinds.join(", ")}. They need SHIELD and integrations, which aren&apos;t built.
              Starting a workflow approves nothing: every step that contacts a target is started by a person and approved through the
              normal flow when it&apos;s due.
            </p>
          </div>
        </Panel>
      </div>
    </>
  );
}
