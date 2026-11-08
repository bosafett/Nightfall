"use client";

import Link from "next/link";
import { api } from "@/lib/api/client";
import type { ShieldAlert } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Input } from "@/components/ui/primitives";
import { kindLabel, severityTone } from "@/components/shield/labels";

/** SHIELD alerts: read by anyone; acknowledged and resolved by analysts and above. Nothing here
 * runs a countermeasure: the recommendation is advice for a person. */
export function AlertList({ ws, alerts, canAct }: { ws: string; alerts: ShieldAlert[]; canAct: boolean }) {
  const { busy, error, run } = useAction();
  if (alerts.length === 0) return <p className="text-sm text-muted">No alerts.</p>;
  return (
    <div className="space-y-3">
      {error && <Alert>{error}</Alert>}
      <ul className="space-y-3" data-testid="alert-list">
        {alerts.map((a) => (
          <li key={a.id} className="rounded-md border border-border bg-bg p-3" data-testid={`alert-${a.kind}`}>
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={severityTone[a.severity] ?? "gray"}>{a.severity}</Badge>
              <Badge tone="gray">{kindLabel[a.kind] ?? a.kind}</Badge>
              <span className="font-medium">{a.title}</span>
              <span className="ml-auto text-xs text-muted">{a.state === "open" ? "Open" : a.state === "acknowledged" ? `Acknowledged by ${a.acknowledged_by}` : `Resolved by ${a.resolved_by}`}</span>
            </div>
            <p className="mt-1 text-sm text-muted">{a.detail}</p>
            {a.recommendation && <p className="mt-1 text-sm"><span className="text-muted">Recommended:</span> {a.recommendation}</p>}
            <p className="mt-1 font-mono text-xs text-muted tabular">
              {a.project_name} · first seen {formatDateTime(a.first_seen_at)} · last seen {formatDateTime(a.last_seen_at)} · {a.rules}
              {a.finding_id && <> · <Link className="hover:text-crimson-text" href={`/w/${ws}/findings/${a.finding_id}`}>finding →</Link></>}
            </p>
            {a.note && <p className="mt-1 text-xs">Note: {a.note}</p>}
            {canAct && a.state !== "resolved" && (
              <form className="mt-2 flex flex-wrap gap-2" onSubmit={(e) => {
                e.preventDefault();
                const note = String(new FormData(e.currentTarget).get("note") ?? "");
                run(() => api(`/workspaces/${ws}/alerts/${a.id}/resolve`, { method: "POST", body: { note } }));
              }}>
                {a.state === "open" && (
                  <Button type="button" variant="secondary" disabled={busy}
                    onClick={() => run(() => api(`/workspaces/${ws}/alerts/${a.id}/acknowledge`, { method: "POST" }))}>Acknowledge</Button>
                )}
                <Input name="note" placeholder="What was done (optional)" aria-label={`Resolution note for ${a.title}`} maxLength={1000} className="min-w-0 flex-1" />
                <Button type="submit" disabled={busy}>Resolve</Button>
              </form>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
