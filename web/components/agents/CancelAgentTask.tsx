"use client";

import { api } from "@/lib/api/client";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert } from "@/components/ui/primitives";

export function CancelAgentTask({ ws, taskId }: { ws: string; taskId: string }) {
  const { error, run } = useAction();
  return (
    <div className="space-y-2">
      <ConfirmButton label="Cancel task" title="Cancel this agent task?" body="If the model is already working, its answer is discarded and nothing is applied."
        confirmLabel="Cancel task" onConfirm={async () => { await run(() => api(`/workspaces/${ws}/agent-tasks/${taskId}/cancel`, { method: "POST" })); }} />
      {error && <Alert>{error}</Alert>}
    </div>
  );
}
