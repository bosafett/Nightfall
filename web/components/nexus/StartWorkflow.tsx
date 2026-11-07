"use client";

import { useRouter } from "next/navigation";
import { api } from "@/lib/api/client";
import type { WorkflowRunDetail, Workflows } from "@/lib/api/types";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Select } from "@/components/ui/primitives";

/** Starts a workflow that begins from a scope target. Starting approves nothing. */
export function StartWorkflow({ ws, projectId, workflows, targets }: {
  ws: string; projectId: string; workflows: Workflows["workflows"]; targets: string[];
}) {
  const router = useRouter();
  const { busy, error, run } = useAction();
  const fromTarget = workflows.filter((w) => w.starts_from === "target");
  if (fromTarget.length === 0) return null;
  if (targets.length === 0) return <p className="text-sm text-muted">Authorize a scope with a hostname or domain first.</p>;
  return (
    <form className="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end" onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      const res = await run(() => api<WorkflowRunDetail>(`/workspaces/${ws}/projects/${projectId}/workflows`, {
        method: "POST", body: { workflow_id: String(f.get("workflow")), target: String(f.get("target")) },
      }), { refresh: false });
      if (res) router.push(`/w/${ws}/nexus/runs/${res.id}`);
    }}>
      {error && <div className="sm:col-span-3"><Alert>{error}</Alert></div>}
      <Field label="Workflow">
        <Select name="workflow">{fromTarget.map((w) => <option key={w.id} value={w.id}>{w.name} (v{w.version})</option>)}</Select>
      </Field>
      <Field label="Workflow target">
        <Select name="target">{targets.map((t) => <option key={t} value={t}>{t}</option>)}</Select>
      </Field>
      <Button type="submit" disabled={busy}>Start workflow</Button>
    </form>
  );
}

/** "Reassess" on a remediated finding: starts the remediation-reassessment workflow. */
export function ReassessFinding({ ws, projectId, findingId }: { ws: string; projectId: string; findingId: string }) {
  const router = useRouter();
  const { busy, error, run } = useAction();
  return (
    <div className="space-y-2">
      {error && <Alert>{error}</Alert>}
      <Button variant="secondary" disabled={busy} onClick={async () => {
        const res = await run(() => api<WorkflowRunDetail>(`/workspaces/${ws}/projects/${projectId}/workflows`, {
          method: "POST", body: { workflow_id: "remediation-reassessment", finding_id: findingId },
        }), { refresh: false });
        if (res) router.push(`/w/${ws}/nexus/runs/${res.id}`);
      }}>Reassess with NEXUS</Button>
    </div>
  );
}
