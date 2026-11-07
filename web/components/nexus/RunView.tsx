"use client";

import Link from "next/link";
import { api } from "@/lib/api/client";
import type { Role, WorkflowRunDetail, WorkflowStep } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can } from "@/lib/labels";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Input } from "@/components/ui/primitives";
import { kindLabel, stepStateLabel } from "@/components/nexus/labels";

function Step({ ws, run, step, role, busy, act }: {
  ws: string; run: WorkflowRunDetail; step: WorkflowStep; role: Role; busy: boolean;
  act: (path: string, body?: unknown) => Promise<unknown>;
}) {
  const [label, tone] = stepStateLabel[step.state] ?? [step.state, "gray"];
  const live = run.state === "running";
  const ops = (step.outputs.operation_ids as string[] | undefined) ?? [];
  const playbookRuns = (step.outputs.playbook_run_ids as string[] | undefined) ?? [];
  const executing = step.kind === "playbook" || step.kind === "rerun";
  return (
    <li className="rounded-md border border-border bg-bg p-3" data-testid={`step-${step.key}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{step.label}</span>
          <Badge tone="gray">{kindLabel[step.kind] ?? step.kind}</Badge>
          <Badge tone={tone}>{label}</Badge>
          {step.attempt > 1 && <span className="text-xs text-muted">attempt {step.attempt}</span>}
        </span>
        {live && (
          <span className="flex flex-wrap gap-2">
            {executing && (step.state === "ready" || step.state === "blocked") && can.launchPlaybooks(role) && (
              <Button disabled={busy} onClick={() => act(`steps/${step.key}/start`)}>Start step</Button>
            )}
            {step.can_retry && can.writeRegistry(role) && (
              <Button variant="secondary" disabled={busy} onClick={() => act(`steps/${step.key}/retry`)}>Retry</Button>
            )}
            {step.kind === "review" && step.state === "running" && can.editFindings(role) && (
              <form className="flex gap-2" onSubmit={(e) => {
                e.preventDefault();
                act(`steps/${step.key}/complete`, { note: String(new FormData(e.currentTarget).get("note") ?? "") });
              }}>
                <Input name="note" placeholder="Note (optional)" aria-label={`Note for ${step.label}`} maxLength={1000} />
                <Button type="submit" disabled={busy}>Mark done</Button>
              </form>
            )}
            {step.kind === "checkpoint" && step.state === "running" && can.approveOperations(role) && (
              <>
                <Button disabled={busy} onClick={() => act(`steps/${step.key}/answer`, { answer: "continue" })}>Continue</Button>
                <Button variant="secondary" disabled={busy} onClick={() => act(`steps/${step.key}/answer`, { answer: "stop" })}>Stop here</Button>
              </>
            )}
          </span>
        )}
      </div>
      <p className="mt-1 text-sm text-muted">{step.description}</p>
      {step.detail && <p className="mt-1 text-sm">{step.detail}</p>}
      <p className="mt-1 font-mono text-xs text-muted tabular">
        {step.started_at && <>started {formatDateTime(step.started_at)}{step.started_by && ` by ${step.started_by}`}</>}
        {step.deadline && !step.finished_at && <> · due by {formatDateTime(step.deadline)}</>}
        {step.finished_at && <> · ended {formatDateTime(step.finished_at)}</>}
      </p>
      {(ops.length > 0 || playbookRuns.length > 0) && (
        <p className="mt-1 flex flex-wrap gap-3 text-xs">
          {playbookRuns.map((id) => <Link key={id} className="text-muted hover:text-crimson-text" href={`/w/${ws}/blacksite/ops/runs/${id}`}>Playbook run {id.slice(0, 8)} →</Link>)}
          {ops.map((id) => <Link key={id} className="text-muted hover:text-crimson-text" href={`/w/${ws}/recon/${id}`}>Operation {id.slice(0, 8)} →</Link>)}
        </p>
      )}
    </li>
  );
}

export function RunView({ ws, run, role }: { ws: string; run: WorkflowRunDetail; role: Role }) {
  const { busy, error, run: go } = useAction();
  const act = (path: string, body?: unknown) =>
    go(() => api(`/workspaces/${ws}/workflow-runs/${run.id}/${path}`, { method: "POST", body: body ?? {} }));
  return (
    <div className="space-y-4">
      {error && <Alert>{error}</Alert>}
      <ol className="space-y-3">
        {run.steps.map((s) => <Step key={s.key} ws={ws} run={run} step={s} role={role} busy={busy} act={act} />)}
      </ol>
      {run.state === "running" && can.writeRegistry(role) && (
        <ConfirmButton label="Cancel workflow" title="Cancel this workflow?" confirmLabel="Cancel workflow"
          body="Steps that haven't finished are cancelled, and so are operations still waiting to run or for approval. Running operations finish and their evidence is kept."
          onConfirm={async () => { await act("cancel", { reason: "Cancelled from the run page" }); }} />
      )}
    </div>
  );
}
