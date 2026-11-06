import Link from "next/link";
import type { PlaybookRun } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { profileLabel, runStatusLabel, runStatusTone } from "@/lib/blackops";
import { Badge, DataTable, EmptyState } from "@/components/ui/primitives";

export function RunsTable({ ws, runs }: { ws: string; runs: PlaybookRun[] }) {
  if (runs.length === 0) return <EmptyState title="No runs yet" body="Launched playbooks appear here with their steps and results." />;
  return (
    <DataTable head={["Started", "Playbook", "Target", "Profile", "Steps", "Status"]}>
      {runs.map((r) => (
        <tr key={r.id}>
          <td className="px-4 py-2.5 font-mono text-xs text-muted tabular">{formatDateTime(r.created_at)}</td>
          <td className="px-4 py-2.5">
            <Link href={`/w/${ws}/blacksite/ops/runs/${r.id}`} className="font-medium hover:underline">{r.playbook_name}</Link>
            <span className="block font-mono text-xs text-muted">v{r.playbook_version} · {r.project_name}</span>
          </td>
          <td className="px-4 py-2.5 font-mono text-sm">{r.target}</td>
          <td className="px-4 py-2.5"><Badge tone={r.profile === "lab" ? "orange" : "blue"}>{profileLabel[r.profile]}</Badge></td>
          <td className="px-4 py-2.5 font-mono text-xs tabular">{r.steps.filter((s) => s.status === "succeeded").length}/{r.steps.length}</td>
          <td className="px-4 py-2.5"><Badge tone={runStatusTone[r.status]}>{runStatusLabel[r.status]}</Badge></td>
        </tr>
      ))}
    </DataTable>
  );
}
