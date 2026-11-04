import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Overview, OverviewWindow } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { IntelligenceGraph } from "@/components/command/IntelligenceGraph";
import { ActiveAssessments, ComingPanel, KpiRow, WINDOWS, WindowPicker } from "@/components/command/Panels";
import { LinkButton, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Command Center" };

export default async function CommandCenter({ params, searchParams }: {
  params: Promise<{ ws: string }>; searchParams: Promise<{ window?: string }>;
}) {
  const { ws } = await params;
  const requested = (await searchParams).window;
  const window: OverviewWindow = WINDOWS.includes(requested as OverviewWindow) ? (requested as OverviewWindow) : "24h";
  const overview = await apiGet<Overview>(`/workspaces/${ws}/overview?window=${window}`);
  const now = new Date(overview.generated_at);

  return (
    <>
      <PageHeader title="Command Center" subtitle="Your adversarial intelligence overview"
        actions={<><WindowPicker ws={ws} current={overview.window} /><LinkButton href={`/w/${ws}/targets`} variant="primary">New project</LinkButton></>} />
      <div className="space-y-6">
        <KpiRow overview={overview} />

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
                  <p className="mt-1 text-sm text-muted">Organizations and projects appear here. Assets and findings join in phases 3–4.</p>
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
          <ComingPanel title="Recent findings" phase={overview.recent_findings.phase} body="Severity, affected asset and validation status, each traceable to evidence." />
          <ComingPanel title="Agent activity" phase={overview.agent_activity.phase} body="What each agent is working on and which operations wait for approval." />
          <ComingPanel title="Risk overview" phase={overview.risk.phase} body="Severity breakdown of open findings. No blended risk score." />
        </div>
        <p className="font-mono text-xs text-muted tabular">Updated {formatDateTime(overview.generated_at)}</p>
      </div>
    </>
  );
}
