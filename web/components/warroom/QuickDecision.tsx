"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Input } from "@/components/ui/primitives";

/** Approve or reject from the War Room. The API re-checks role, self-approval and scope. */
export function QuickDecision({ ws, opId, target, scopeVersion }: { ws: string; opId: string; target: string; scopeVersion: number }) {
  const { error, run } = useAction();
  const [reason, setReason] = useState("");
  const base = `/workspaces/${ws}/operations/${opId}`;
  return (
    <div className="space-y-2">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <Input aria-label="Reason (recorded with your decision)" placeholder="Reason (recorded)" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} />
        <div className="flex gap-2">
          <ConfirmButton variant="secondary" label="Approve" title="Approve this operation?"
            body={`${target} will be contacted directly. Your name, the reason and scope v${scopeVersion} are recorded.`}
            confirmLabel="Approve and queue"
            onConfirm={async () => { await run(() => api(`${base}/approve`, { method: "POST", body: { reason } })); }} />
          <ConfirmButton label="Reject" title="Reject this operation?" body="It won't run. Rejection is final; it can be requested again."
            confirmLabel="Reject operation"
            onConfirm={async () => { await run(() => api(`${base}/reject`, { method: "POST", body: { reason } })); }} />
        </div>
      </div>
      {error && <Alert>{error}</Alert>}
    </div>
  );
}
