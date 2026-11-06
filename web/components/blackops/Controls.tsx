"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { PlaybookRunDetail } from "@/lib/api/types";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Field, Input } from "@/components/ui/primitives";

export function EnableToggle({ ws, playbookId, enabled }: { ws: string; playbookId: string; enabled: boolean }) {
  const { run } = useAction();
  return (
    <ConfirmButton variant={enabled ? "danger" : "secondary"} label={enabled ? "Disable" : "Enable"}
      title={`${enabled ? "Disable" : "Enable"} this playbook?`}
      body={enabled ? "Nobody in this workspace can launch it until it is enabled again. Runs already queued are not affected." : "Owners can launch it again. Each launch still needs preflight and, above passive, approval."}
      confirmLabel={enabled ? "Disable" : "Enable"}
      onConfirm={async () => { await run(() => api(`/workspaces/${ws}/blackops/playbooks/${playbookId}/setting`, { method: "PUT", body: { enabled: !enabled } })); }} />
  );
}

/** Approve or reject every waiting step of a run. The API enforces role, scope and "not your own". */
export function RunDecision({ ws, run: r }: { ws: string; run: PlaybookRunDetail }) {
  const { error, run } = useAction();
  const [reason, setReason] = useState("");
  const base = `/workspaces/${ws}/blackops/runs/${r.id}`;
  const waiting = r.steps.filter((s) => s.status === "awaiting_approval").length;
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">
        Approving queues {waiting} step(s) of {r.playbook_name} against <span className="font-mono text-text">{r.target}</span>
        {r.profile === "lab" ? ", run by the isolated lab machine inside the lab network only. Lab approvals expire after 24 hours." : ". Each step runs only if the target still resolves to a public address the scope doesn't exclude."}
        {" "}Approval is tied to scope v{r.scope_version}.
      </p>
      <Field label="Reason (recorded with your decision)"><Input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} /></Field>
      {error && <Alert>{error}</Alert>}
      <div className="flex flex-wrap gap-2">
        <ConfirmButton variant="secondary" label="Approve run" title={`Approve ${r.playbook_name}?`}
          body={`${r.target} will be contacted. Your name, the reason and scope v${r.scope_version} are recorded with every step.`}
          confirmLabel="Approve and queue"
          onConfirm={async () => { await run(() => api(`${base}/approve`, { method: "POST", body: { reason } })); }} />
        <ConfirmButton label="Reject run" title="Reject this run?" body="None of its waiting steps will run. It can be launched again."
          confirmLabel="Reject run"
          onConfirm={async () => { await run(() => api(`${base}/reject`, { method: "POST", body: { reason } })); }} />
      </div>
    </div>
  );
}

export function CancelRun({ ws, runId }: { ws: string; runId: string }) {
  const { run } = useAction();
  return (
    <ConfirmButton label="Cancel run" title="Cancel this run?" body="Steps that haven't started won't run." confirmLabel="Cancel run"
      onConfirm={async () => { await run(() => api(`/workspaces/${ws}/blackops/runs/${runId}/cancel`, { method: "POST" })); }} />
  );
}
