import Link from "next/link";
import type { WorkflowRun } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { Badge, DataTable } from "@/components/ui/primitives";
import { runStateLabel } from "@/components/nexus/labels";

export function RunsTable({ ws, runs, showProject = true }: { ws: string; runs: WorkflowRun[]; showProject?: boolean }) {
  return (
    <DataTable head={["Workflow", ...(showProject ? ["Project"] : []), "Subject", "State", "Now", "Started"]}>
      {runs.map((r) => {
        const [label, tone] = runStateLabel[r.state] ?? [r.state, "gray"];
        return (
          <tr key={r.id}>
            <td className="px-4 py-2.5"><Link className="font-medium hover:text-crimson-text" href={`/w/${ws}/nexus/runs/${r.id}`}>{r.workflow_name}</Link></td>
            {showProject && <td className="px-4 py-2.5 text-sm">{r.project_name}</td>}
            <td className="max-w-xs truncate px-4 py-2.5 font-mono text-xs">{r.subject}</td>
            <td className="px-4 py-2.5"><Badge tone={tone}>{label}</Badge></td>
            <td className="px-4 py-2.5 text-sm text-muted">{r.current ?? "—"}</td>
            <td className="px-4 py-2.5 font-mono text-xs text-muted tabular">{formatDateTime(r.started_at)}<span className="block">{r.started_by}</span></td>
          </tr>
        );
      })}
    </DataTable>
  );
}
