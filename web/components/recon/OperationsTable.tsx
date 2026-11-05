import Link from "next/link";
import type { Operation } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { DataTable } from "@/components/ui/primitives";
import { OperationStatusBadge } from "./OperationStatusBadge";

function outcome(op: Operation): string {
  if (op.status === "denied") return op.denial_reason ?? "Denied";
  if (op.status === "awaiting_approval") return "Needs approval from someone other than the requester";
  if (op.status === "rejected") return "Rejected";
  if (op.status === "failed") return op.error ?? "Failed";
  if (op.status !== "succeeded") return "—";
  const s = op.result_summary as { assets_new?: number; assets_seen?: number; out_of_scope?: number; technologies?: { name: string }[] };
  if (op.tool === "http") return `${s.technologies?.length ?? 0} technologies identified`;
  if (op.tool === "nuclei") {
    const n = (op.result_summary as { checks?: unknown[] }).checks?.length ?? 0;
    return n === 1 ? "1 check matched" : `${n} checks matched`;
  }
  return `${s.assets_new ?? 0} new · ${s.assets_seen ?? 0} seen · ${s.out_of_scope ?? 0} outside scope`;
}

export function OperationsTable({ ws, ops, showProject = true }: { ws: string; ops: Operation[]; showProject?: boolean }) {
  return (
    <DataTable head={[...(showProject ? ["Project"] : []), "Collector", "Target", "Status", "Result", "Requested"]}>
      {ops.map((op) => (
        <tr key={op.id} className="hover:bg-surface-2">
          {showProject && <td className="px-4 py-3"><span className="block">{op.project_name}</span><span className="block text-xs text-muted">{op.organization_name}</span></td>}
          <td className="px-4 py-3 text-muted">{op.tool_label}</td>
          <td className="px-4 py-3">
            <Link href={`/w/${ws}/recon/${op.id}`} className="font-mono text-sm hover:text-crimson-text">{op.target}</Link>
          </td>
          <td className="px-4 py-3"><OperationStatusBadge status={op.status} /></td>
          <td className="max-w-xs px-4 py-3 text-xs text-muted">{outcome(op)}</td>
          <td className="px-4 py-3 font-mono text-xs text-muted tabular">
            {formatDateTime(op.queued_at)}{op.requested_by && <span className="block font-sans">{op.requested_by}</span>}
          </td>
        </tr>
      ))}
    </DataTable>
  );
}
