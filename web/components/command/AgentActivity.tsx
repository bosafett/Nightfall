import Link from "next/link";
import type { Overview } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { Panel } from "@/components/ui/primitives";
import { AgentTaskStatusBadge } from "@/components/agents/AgentBadges";

/** Command Center: what the agents are doing, counted from agent_tasks. */
export function AgentActivity({ ws, overview, now }: { ws: string; overview: Overview; now: Date }) {
  const a = overview.agent_activity;
  return (
    <Panel title="Agent activity" actions={<Link href={`/w/${ws}/agents`} className="text-sm text-crimson-text hover:underline">All agents</Link>}>
      {!a.ai_enabled && a.recent.length === 0 ? (
        <p className="py-6 text-center text-sm text-muted">AI is off on this deployment. Everything else works without it.</p>
      ) : (
        <>
          <dl className="mb-3 grid grid-cols-3 gap-2 text-center">
            {([["Working", a.open], ["Finished", a.finished_in_window], ["Awaiting you", a.agent_proposals_awaiting_approval]] as const).map(([k, v]) => (
              <div key={k} className="rounded-md border border-border px-2 py-2">
                <dd className="font-mono text-lg tabular">{v}</dd>
                <dt className="text-xs text-muted">{k}</dt>
              </div>
            ))}
          </dl>
          {a.recent.length === 0 ? <p className="text-sm text-muted">No agent has run yet.</p> : (
            <ul className="-my-2 divide-y divide-border">
              {a.recent.map((t) => (
                <li key={t.id} className="flex items-center gap-3 py-2.5">
                  <div className="min-w-0 flex-1">
                    <Link href={`/w/${ws}/agents/${t.id}`} className="block truncate text-sm hover:text-crimson-text">{t.objective}</Link>
                    <p className="text-xs text-muted">{t.agent_label} · <span className="font-mono tabular">{formatRelative(t.queued_at, now)}</span></p>
                  </div>
                  <AgentTaskStatusBadge value={t.status} />
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Panel>
  );
}
