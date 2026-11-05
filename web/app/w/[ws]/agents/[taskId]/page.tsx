import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { AgentTaskDetail } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { AgentTaskStatusBadge, AiBadge } from "@/components/agents/AgentBadges";
import { AgentTasksTable } from "@/components/agents/AgentTasksTable";
import { CancelAgentTask } from "@/components/agents/CancelAgentTask";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { Alert, DataTable, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Agent task" };

type Item = { [k: string]: unknown };

function itemLink(ws: string, it: Item) {
  if (typeof it.operation_id === "string") return <Link className="hover:text-crimson-text" href={`/w/${ws}/recon/${it.operation_id}`}>Open collection</Link>;
  if (typeof it.finding_id === "string") return <Link className="hover:text-crimson-text" href={`/w/${ws}/findings/${it.finding_id}`}>Open finding</Link>;
  return "—";
}

function itemLabel(it: Item) {
  if (typeof it.title === "string") return it.title;
  if (typeof it.target === "string") return `${String(it.tool ?? "")} · ${it.target}`;
  if (typeof it.verdict === "string") return `Verdict: ${it.verdict.replace("_", " ")}`;
  return "—";
}

export default async function AgentTaskPage({ params }: { params: Promise<{ ws: string; taskId: string }> }) {
  const { ws, taskId } = await params;
  const task = await apiGet<AgentTaskDetail>(`/workspaces/${ws}/agent-tasks/${taskId}`);
  const accepted = (task.result.accepted ?? []) as Item[];
  const refused = (task.result.refused ?? []) as Item[];
  const notes = typeof task.result.notes === "string" ? task.result.notes : "";
  const open = task.status === "queued" || task.status === "running";
  const rows: [string, string][] = [
    ["Agent", task.agent_label],
    ["Requested by", task.requested_by ?? "—"],
    ["Queued", formatDateTime(task.queued_at)],
    ["Finished", task.finished_at ? formatDateTime(task.finished_at) : "—"],
    ["Model", task.model ?? "—"],
    ["Prompt version", task.prompt_version ?? "—"],
    ["Tokens in / out", task.input_tokens != null ? `${task.input_tokens} / ${task.output_tokens}` : "—"],
    ["Model time", task.latency_ms != null ? `${(task.latency_ms / 1000).toFixed(1)} s` : "—"],
  ];
  return (
    <>
      <nav className="mb-2 text-sm text-muted"><Link href={`/w/${ws}/targets`} className="hover:text-text">Target Registry</Link> / agent task</nav>
      <PageHeader title={task.objective} subtitle={`${task.agent_label} · AI agent`} actions={<div className="flex items-center gap-2"><AiBadge /><AgentTaskStatusBadge value={task.status} /></div>} />
      <AutoRefresh ws={ws} active={open} />
      {open && <div className="mb-4"><CancelAgentTask ws={ws} taskId={task.id} /></div>}
      {task.error && <Alert>{task.error}</Alert>}
      <div className="mt-4 grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <Panel title="Provenance">
          <dl className="space-y-2 text-sm">
            {rows.map(([k, v]) => <div key={k} className="flex justify-between gap-4"><dt className="text-muted">{k}</dt><dd className="text-right font-mono text-xs tabular">{v}</dd></div>)}
          </dl>
        </Panel>
        <Panel title="What the gateway did">
          {task.status !== "succeeded" ? <p className="text-sm text-muted">{open ? "Waiting for the agent…" : "Nothing was applied."}</p> : (
            <div className="space-y-4">
              <div>
                <p className="mb-2 text-sm font-medium">Accepted <span className="font-mono text-muted tabular">{accepted.length}</span></p>
                {accepted.length === 0 ? <p className="text-sm text-muted">Nothing.</p> : (
                  <DataTable head={["Proposal", "Outcome", ""]}>
                    {accepted.map((it, i) => (
                      <tr key={i}>
                        <td className="px-4 py-2.5 text-sm">{itemLabel(it)}</td>
                        <td className="px-4 py-2.5 text-xs text-muted">{String(it.status ?? it.note ?? (it.evidence ? `${String(it.evidence)} evidence linked, hypothesis` : "recorded"))}</td>
                        <td className="px-4 py-2.5 text-sm">{itemLink(ws, it)}</td>
                      </tr>
                    ))}
                  </DataTable>
                )}
              </div>
              <div>
                <p className="mb-2 text-sm font-medium">Refused <span className="font-mono text-muted tabular">{refused.length}</span></p>
                {refused.length === 0 ? <p className="text-sm text-muted">Nothing.</p> : (
                  <DataTable head={["Proposal", "Why it was refused"]}>
                    {refused.map((it, i) => (
                      <tr key={i}><td className="px-4 py-2.5 text-sm">{itemLabel(it)}</td><td className="px-4 py-2.5 text-xs text-muted">{String(it.reason ?? "")}</td></tr>
                    ))}
                  </DataTable>
                )}
              </div>
              {notes && (
                <div className="rounded-md border border-dashed border-border-strong p-3">
                  <p className="text-xs font-medium text-muted">Agent&apos;s notes (AI-written, not verified)</p>
                  <p className="mt-1 whitespace-pre-wrap text-sm">{notes}</p>
                </div>
              )}
            </div>
          )}
        </Panel>
      </div>
      {task.children.length > 0 && (
        <div className="mt-6"><Panel title="Follow-up tasks"><AgentTasksTable ws={ws} tasks={task.children} /></Panel></div>
      )}
    </>
  );
}
