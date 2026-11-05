import Link from "next/link";
import type { Operation } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { Panel } from "@/components/ui/primitives";
import { LabBadge } from "@/components/scope/LabBadge";
import { OperationStatusBadge } from "@/components/recon/OperationStatusBadge";

function approvalNote(op: Operation): string | null {
  if (op.status === "awaiting_approval") return "Awaiting approval";
  if (op.status === "rejected") return "Approval rejected";
  if (op.status === "denied") return op.denial_reason ?? "Denied by scope check";
  if (op.status === "failed") return op.error ?? "Failed";
  return null;
}

/** Latest collections from /operations, including failed, denied and rejected ones. */
export function RecentOperations({ ws, ops, now }: { ws: string; ops: Operation[] | null; now: Date }) {
  return (
    <Panel title="Recent operations" actions={<Link href={`/w/${ws}/recon`} className="text-sm text-crimson-text hover:underline">Reconnaissance</Link>}>
      <div data-testid="recent-operations">
        {ops === null ? (
          <p className="py-6 text-center text-sm text-muted">Operations are unavailable: the API didn&apos;t answer.</p>
        ) : ops.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted">No operations yet. Start a collection from a project.</p>
        ) : (
          <ul className="-my-2 divide-y divide-border">
            {ops.map((op) => {
              const note = approvalNote(op);
              return (
                <li key={op.id} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 py-2.5 sm:grid-cols-[minmax(0,2fr)_minmax(0,2fr)_auto]">
                  <div className="min-w-0">
                    <Link href={`/w/${ws}/recon/${op.id}`} className="block truncate text-sm hover:text-crimson-text">
                      {op.tool_label} <span className="font-mono text-muted">{op.target}</span>
                    </Link>
                    <p className="truncate text-xs text-muted">{op.organization_name} — {op.project_name}{op.is_lab && <span className="ml-2"><LabBadge /></span>}</p>
                  </div>
                  <p className="hidden min-w-0 truncate text-xs text-muted sm:block">
                    {op.requested_by ?? "System"} · <span className="font-mono tabular">{formatRelative(op.queued_at, now)}</span>
                    {note && <span className="block truncate">{note}</span>}
                  </p>
                  <OperationStatusBadge status={op.status} />
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Panel>
  );
}
