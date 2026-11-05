import type { Metadata } from "next";
import { apiGet } from "@/lib/api/server";
import type { AgentsInfo, AgentTask } from "@/lib/api/types";
import { AgentTasksTable } from "@/components/agents/AgentTasksTable";
import { AutoRefresh } from "@/components/recon/AutoRefresh";
import { Alert, Badge, DataTable, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "AI agents" };

const fmt = new Intl.NumberFormat("en-US");

/** Who the agents are, what they cost, what they did. Every number comes from agent_tasks. */
export default async function AgentsPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [info, tasks] = await Promise.all([
    apiGet<AgentsInfo>(`/workspaces/${ws}/agents`),
    apiGet<AgentTask[]>(`/workspaces/${ws}/agent-tasks`),
  ]);
  const open = tasks.some((t) => t.status === "queued" || t.status === "running");
  return (
    <>
      <PageHeader
        title="AI agents"
        subtitle={info.ai_enabled ? `Model: ${info.model}` : "AI is off on this deployment"}
        actions={<Badge tone={info.ai_enabled ? "green" : "gray"}>{info.ai_enabled ? "AI on" : "AI off"}</Badge>}
      />
      <AutoRefresh ws={ws} active={open} />
      <div className="space-y-6">
        <Alert tone="blue">
          Agents only propose. Deterministic code checks every proposal against the scope, the agent&apos;s allowlist and the risk class,
          and refuses the rest with a recorded reason. What they write is labelled as AI output and enters as a hypothesis; only a person
          can validate a finding or an attack path. Agents are started from a project page.
        </Alert>
        <Panel title={`Agents · last ${info.usage_days} days`}>
          <DataTable head={["Agent", "What it does", "Runs", "Done", "Failed", "Tokens in / out"]}>
            {info.agents.map((a) => (
              <tr key={a.key}>
                <td className="px-4 py-3 font-medium">
                  {a.label}
                  {a.status === "automatic" && <span className="block text-xs font-normal text-muted">Runs automatically</span>}
                </td>
                <td className="max-w-md px-4 py-3 text-sm text-muted">{a.role}</td>
                <td className="px-4 py-3 font-mono tabular">{fmt.format(a.usage.runs)}</td>
                <td className="px-4 py-3 font-mono tabular">{fmt.format(a.usage.succeeded)}</td>
                <td className="px-4 py-3 font-mono tabular">{fmt.format(a.usage.failed)}</td>
                <td className="px-4 py-3 font-mono text-xs tabular">{fmt.format(a.usage.input_tokens)} / {fmt.format(a.usage.output_tokens)}</td>
              </tr>
            ))}
          </DataTable>
        </Panel>
        <Panel title="Recent tasks">
          {tasks.length === 0 ? <p className="text-sm text-muted">No agent has run in this workspace yet.</p> : <AgentTasksTable ws={ws} tasks={tasks} />}
        </Panel>
      </div>
    </>
  );
}
