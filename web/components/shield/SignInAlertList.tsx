"use client";

import { api } from "@/lib/api/client";
import type { SignInAlert } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button } from "@/components/ui/primitives";
import { severityTone } from "@/components/shield/labels";

/** SHIELD v3 sign-in alerts. The lock itself is automatic (the sign-in throttle); these say it
 * happened. Only the account's own user acknowledges (`own`); admins see their members' alerts. */
export function SignInAlertList({ alerts, own }: { alerts: SignInAlert[]; own: boolean }) {
  const { busy, error, run } = useAction();
  if (alerts.length === 0) return <p className="text-sm text-muted">No sign-in alerts in the last 30 days.</p>;
  return (
    <div className="space-y-3">
      {error && <Alert>{error}</Alert>}
      <ul className="space-y-3" data-testid="sign-in-alerts">
        {alerts.map((a) => (
          <li key={a.id} className="rounded-md border border-border bg-bg p-3" data-testid={`sign-in-alert-${a.kind}`}>
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={severityTone[a.severity] ?? "gray"}>{a.severity}</Badge>
              <span className="font-medium">{a.title}</span>
              <span className="ml-auto text-xs text-muted">{a.state === "open" ? "Open" : "Acknowledged"}</span>
            </div>
            {!own && <p className="mt-1 text-sm">{a.email}</p>}
            <p className="mt-1 text-sm text-muted">{a.detail}</p>
            <p className="mt-1 font-mono text-xs text-muted tabular">
              {a.count} {a.count === 1 ? "time" : "times"} · first {formatDateTime(a.first_seen_at)} · last {formatDateTime(a.last_seen_at)}
              {a.addresses.length > 0 && <> · from {a.addresses.join(", ")}</>}
            </p>
            {own && a.state === "open" && (
              <Button className="mt-2" variant="secondary" disabled={busy}
                onClick={() => run(() => api(`/auth/sign-in-alerts/${a.id}/acknowledge`, { method: "POST" }))}>
                This was me, or I&apos;ve dealt with it
              </Button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
