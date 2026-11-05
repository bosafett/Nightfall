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
  if (typeof it.task_id === "string") return <Link className="hover:text-crimson-text" href={`/w/${ws}/agents/${it.task_id}`}>Open the task</Link>;
  if (typeof it.attack_path_id === "string") return <Link className="hover:text-crimson-text" href={`/w/${ws}/attack-graph`}>Open the attack graph</Link>;
  if (typeof it.operation_id === "string") return <Link className="hover:text-crimson-text" href={`/w/${ws}/recon/${it.operation_id}`}>Open collection</Link>;
  if (typeof it.finding_id === "string") return <Link className="hover:text-crimson-text" href={`/w/${ws}/findings/${it.finding_id}`}>Open finding</Link>;
  return "—";
}

const relText: Record<string, string> = { subdomain_of: "subdomain of", resolves_to: "resolves to", cname_to: "CNAME to" };

function itemLabel(it: Item) {
  if (typeof it.title === "string") return it.title;
  if (typeof it.agent === "string" && typeof it.objective === "string") return `${it.agent}${typeof it.asset === "string" ? ` · ${it.asset}` : ""}: ${it.objective}`;
  if (typeof it.to_asset === "string") return `${relText[String(it.rel_type)] ?? String(it.rel_type)} ${it.to_asset}`;
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
  const summary = typeof task.result.summary === "string" ? task.result.summary : "";
  const list = (k: string) => (Array.isArray(task.result[k]) ? (task.result[k] as unknown[]).map(String) : []);
  const keyRisks = (Array.isArray(task.result.key_risks) ? task.result.key_risks : []) as Item[];
  const counts = (task.result.counts ?? null) as Record<string, number | Record<string, number>> | null;
  const open = task.status === "queued" || task.status === "running";
  const rows: [string, string][] = [
    ["Agent", task.agent_label],
    ...(task.subject_asset ? [["Asset", task.subject_asset] as [string, string]] : []),
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
                        <td className="px-4 py-2.5 text-xs text-muted">{String(it.status ?? it.note ?? (it.evidence ? `${String(it.evidence)} evidence linked, hypothesis` : it.steps ? `${String(it.steps)} steps, hypothesis` : it.task_id ? "queued" : "recorded"))}</td>
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
      {(summary || keyRisks.length > 0 || list("next_steps").length > 0 || list("open_questions").length > 0) && (
        <div className="mt-6">
          <Panel title={`${task.agent_label}'s write-up (AI-written, not verified)`}>
            <div className="space-y-4 rounded-md border border-dashed border-border-strong p-4" data-testid="ai-writeup">
              {summary && <p className="whitespace-pre-wrap text-sm">{summary}</p>}
              {keyRisks.length > 0 && (
                <div>
                  <p className="mb-1 text-xs font-medium text-muted">Key risks it picked (status from the records)</p>
                  <ul className="space-y-1 text-sm">
                    {keyRisks.map((k) => (
                      <li key={String(k.finding_id)}>
                        <Link href={`/w/${ws}/findings/${String(k.finding_id)}`} className="font-medium hover:text-crimson-text">{String(k.title)}</Link>{" "}
                        <span className="text-xs text-muted">({String(k.severity)}, {String(k.status).replace("_", " ")})</span> — {String(k.why)}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {([["open_questions", "Open questions"], ["next_steps", "Suggested next steps"]] as const).map(([k, label]) => list(k).length > 0 && (
                <div key={k}>
                  <p className="mb-1 text-xs font-medium text-muted">{label}</p>
                  <ul className="list-disc space-y-1 pl-5 text-sm">{list(k).map((x, i) => <li key={i}>{x}</li>)}</ul>
                </div>
              ))}
            </div>
            {counts && (
              <div className="mt-4">
                <p className="mb-2 text-xs font-medium text-muted">Counts from the records when it ran (not from the model)</p>
                <dl className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
                  {Object.entries(counts).map(([k, v]) => (
                    <div key={k} className="rounded-md border border-border px-3 py-2">
                      <dt className="text-xs text-muted">{k.replaceAll("_", " ")}</dt>
                      <dd className="font-mono text-xs tabular">{typeof v === "number" ? v : Object.entries(v).map(([a, b]) => `${a.replace("_", " ")} ${b}`).join(" · ") || "none"}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            )}
          </Panel>
        </div>
      )}
      {task.children.length > 0 && (
        <div className="mt-6"><Panel title="Follow-up tasks"><AgentTasksTable ws={ws} tasks={task.children} /></Panel></div>
      )}
    </>
  );
}
