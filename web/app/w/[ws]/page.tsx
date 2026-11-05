import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { AgentsInfo, AgentTask, Finding, Operation, Overview, OverviewWindow } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { IntelligenceGraph } from "@/components/command/IntelligenceGraph";
import { AgentActivity } from "@/components/command/AgentActivity";
import { ActiveAssessments, KpiRow, RecentFindings, RiskOverview, SecondaryMetrics, WINDOWS, WindowPicker } from "@/components/command/Panels";
import { RecentOperations } from "@/components/command/RecentOperations";
import { LinkButton, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Command Center" };

export default async function CommandCenter({ params, searchParams }: {
  params: Promise<{ ws: string }>; searchParams: Promise<{ window?: string }>;
}) {
  const { ws } = await params;
  const requested = (await searchParams).window;
  const window: OverviewWindow = WINDOWS.includes(requested as OverviewWindow) ? (requested as OverviewWindow) : "24h";
  // The overview is required; the rest enrich panels and degrade to an "unavailable" state on failure.
  const optional = <T,>(path: string) => apiGet<T>(path).catch(() => null);
  const [overview, findings, ops, agents, tasks] = await Promise.all([
    apiGet<Overview>(`/workspaces/${ws}/overview?window=${window}`),
    optional<Finding[]>(`/workspaces/${ws}/findings?sort=discovered&descending=true`),
    optional<Operation[]>(`/workspaces/${ws}/operations?limit=8`),
    optional<AgentsInfo>(`/workspaces/${ws}/agents`),
    optional<AgentTask[]>(`/workspaces/${ws}/agent-tasks`),
  ]);
  const now = new Date(overview.generated_at);

  return (
    <>
      <PageHeader title="Command Center" subtitle="Your adversarial intelligence overview"
        actions={<><WindowPicker ws={ws} current={overview.window} /><LinkButton href={`/w/${ws}/targets`} variant="primary">New project</LinkButton></>} />
      <div className="space-y-6">
        <KpiRow overview={overview} />
        <SecondaryMetrics overview={overview} />

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
          <ActiveAssessments ws={ws} items={overview.assessments} now={now} />
          <Panel title="Intelligence graph" actions={
            <span className="flex items-center gap-3 text-xs text-muted">
              <span className="flex items-center gap-1.5"><svg width="22" height="4" aria-hidden="true"><line x1="0" y1="2" x2="22" y2="2" stroke="currentColor" strokeWidth="2" /></svg>Recorded</span>
              <span className="flex items-center gap-1.5"><svg width="22" height="4" aria-hidden="true"><line x1="0" y1="2" x2="22" y2="2" stroke="currentColor" strokeWidth="2" strokeDasharray="5 3" /></svg>Hypothesis</span>
            </span>
          }>
            {overview.graph.nodes.length === 0 ? (
              <div className="grid h-[22rem] place-items-center rounded-md border border-dashed border-border-strong text-center">
                <div>
                  <p className="font-medium">No relationships yet</p>
                  <p className="mt-1 text-sm text-muted">Organizations and projects appear here. Assets, findings and evidence for each project are in its Attack Graph.</p>
                </div>
              </div>
            ) : (
              <>
                <IntelligenceGraph ws={ws} graph={overview.graph} />
                <p className="mt-2 text-xs text-muted">
                  Click a node to open its record.{overview.graph.truncated && <> Showing the first {overview.graph.nodes.length} nodes; <Link href={`/w/${ws}/targets`} className="underline">see all</Link>.</>}
                </p>
              </>
            )}
          </Panel>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <RecentFindings ws={ws} overview={overview} findings={findings} now={now} />
          <RiskOverview ws={ws} overview={overview} findings={findings} />
          <AgentActivity ws={ws} overview={overview} info={agents} tasks={tasks} now={now} />
        </div>
        <RecentOperations ws={ws} ops={ops} now={now} />
        <p className="font-mono text-xs text-muted tabular">Updated {formatDateTime(overview.generated_at)}</p>
      </div>
    </>
  );
}
