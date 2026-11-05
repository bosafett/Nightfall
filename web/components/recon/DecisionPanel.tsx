"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { OperationDetail } from "@/lib/api/types";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Field, Input } from "@/components/ui/primitives";

/** Approve or reject an operation. The API also enforces role, scope and "not your own". */
export function DecisionPanel({ ws, op }: { ws: string; op: OperationDetail }) {
  const { error, run } = useAction();
  const [reason, setReason] = useState("");
  const base = `/workspaces/${ws}/operations/${op.id}`;
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">
        {op.tool === "nuclei"
          ? <>Approving runs NIGHTFALL&apos;s reviewed GET-only checks against <span className="font-mono text-text">{op.target}</span> through the scope proxy (ports 443 and 80).</>
          : <>Approving sends up to 3 GET requests to <span className="font-mono text-text">{op.target}</span> (ports 443 and 80).</>}
        {" "}It runs only if the target still resolves to a public address that the scope doesn&apos;t exclude. Approval is tied to scope v{op.scope_version}.
      </p>
      <Field label="Reason (recorded with your decision)"><Input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} /></Field>
      {error && <Alert>{error}</Alert>}
      <div className="flex flex-wrap gap-2">
        <ConfirmButton variant="secondary" label="Approve" title={`Approve ${op.tool_label}?`}
          body={`${op.target} will be contacted directly. Your name, the reason and scope v${op.scope_version} are recorded.`}
          confirmLabel="Approve and queue"
          onConfirm={async () => { await run(() => api(`${base}/approve`, { method: "POST", body: { reason } })); }} />
        <ConfirmButton label="Reject" title="Reject this operation?" body="It won't run. Rejection is final; it can be requested again."
          confirmLabel="Reject operation"
          onConfirm={async () => { await run(() => api(`${base}/reject`, { method: "POST", body: { reason } })); }} />
      </div>
    </div>
  );
}

export function CancelRequest({ ws, opId }: { ws: string; opId: string }) {
  const { run } = useAction();
  return (
    <ConfirmButton label="Cancel request" title="Cancel this request?" body="It won't run." confirmLabel="Cancel request"
      onConfirm={async () => { await run(() => api(`/workspaces/${ws}/operations/${opId}/cancel`, { method: "POST" })); }} />
  );
}
