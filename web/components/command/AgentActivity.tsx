import Link from "next/link";
import type { AgentsInfo, AgentTask, Overview } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { Badge, Panel } from "@/components/ui/primitives";
import { AgentTaskStatusBadge } from "@/components/agents/AgentBadges";

const OPEN = new Set(["queued", "running"]);

/**
 * Command Center: every agent from the registry, with its latest real task.
 * Nothing is simulated: an agent with no task row reads "No runs yet".
 */
export function AgentActivity({ ws, overview, info, tasks, now }: {
  ws: string; overview: Overview; info: AgentsInfo | null; tasks: AgentTask[] | null; now: Date;
}) {
  const a = overview.agent_activity;
  const latest = new Map<string, AgentTask>();
  for (const t of [...(tasks ?? [])].sort((x, y) => y.queued_at.localeCompare(x.queued_at))) {
    if (!latest.has(t.agent)) latest.set(t.agent, t);
  }
  return (
    <Panel title="Agent activity" actions={<Link href={`/w/${ws}/agents`} className="text-sm text-crimson-text hover:underline">All agents</Link>}>
      <div data-testid="agent-activity">
        {!a.ai_enabled && (
          <p className="mb-3 rounded-md border border-border-strong bg-surface-2 px-3 py-2 text-xs text-muted">
            <span className="font-medium text-text">AI is off on this deployment.</span> Agents can&apos;t run; everything else works without them.
          </p>
        )}
        <dl className="mb-3 grid grid-cols-3 gap-2 text-center">
          {([["Working", a.open], ["Finished", a.finished_in_window], ["Awaiting you", a.agent_proposals_awaiting_approval]] as const).map(([k, v]) => (
            <div key={k} className={`rounded-md border px-2 py-2 ${k === "Awaiting you" && v > 0 ? "border-yellow/60" : "border-border"}`}>
              <dd className="font-mono text-lg tabular">{v}</dd>
              <dt className="text-xs text-muted">{k}</dt>
            </div>
          ))}
        </dl>
        {info === null ? (
          <p className="text-sm text-muted">Agent roster unavailable: the API didn&apos;t answer. Counts above are from the overview.</p>
        ) : (
          <ul className="-my-1.5 divide-y divide-border">
            {info.agents.map((agent) => {
              const t = latest.get(agent.key);
              const working = t && OPEN.has(t.status);
              return (
                <li key={agent.key} className="py-1.5" data-testid={`agent-${agent.key}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium">{agent.label}</span>
                    {!info.ai_enabled ? <Badge tone="gray">AI off</Badge>
                      : working ? <AgentTaskStatusBadge value={t.status} />
                      : t ? <span className="flex items-center gap-1.5 text-xs text-muted">Idle · last <AgentTaskStatusBadge value={t.status} /></span>
                      : <span className="text-xs text-muted">No runs yet</span>}
                  </div>
                  {t && (
                    <p className="truncate text-xs text-muted">
                      <Link href={`/w/${ws}/agents/${t.id}`} className="hover:text-crimson-text">{t.objective}</Link>
                      {" · "}<span className="font-mono tabular">{formatRelative(t.finished_at ?? t.queued_at, now)}</span>
                      {t.status === "failed" && <span className="text-crimson-text"> · needs review</span>}
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Panel>
  );
}
