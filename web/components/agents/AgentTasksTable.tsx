import Link from "next/link";
import type { AgentTask } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { DataTable } from "@/components/ui/primitives";
import { AgentTaskStatusBadge } from "./AgentBadges";

export function AgentTasksTable({ ws, tasks }: { ws: string; tasks: AgentTask[] }) {
  return (
    <DataTable head={["Agent", "Task", "Status", "Requested"]}>
      {tasks.map((t) => (
        <tr key={t.id} className="hover:bg-surface-2">
          <td className="px-4 py-3 font-medium">{t.agent_label}</td>
          <td className="max-w-md px-4 py-3">
            <Link href={`/w/${ws}/agents/${t.id}`} className="hover:text-crimson-text">{t.objective}</Link>
            {t.error && <span className="block text-xs text-crimson-text">{t.error}</span>}
          </td>
          <td className="px-4 py-3"><AgentTaskStatusBadge value={t.status} /></td>
          <td className="px-4 py-3 font-mono text-xs text-muted tabular">
            {formatDateTime(t.queued_at)}
            {t.requested_by && <span className="block font-sans">{t.requested_by}</span>}
          </td>
        </tr>
      ))}
    </DataTable>
  );
}
