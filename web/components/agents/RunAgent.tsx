"use client";

import { useRouter } from "next/navigation";
import { api } from "@/lib/api/client";
import type { AgentTask } from "@/lib/api/types";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button } from "@/components/ui/primitives";

/** Starts an agent run. The API checks role, scope and limits; the agent only proposes. */
export function RunAgent({ ws, projectId }: { ws: string; projectId: string }) {
  const router = useRouter();
  const { busy, error, run } = useAction();
  const start = async (agent: "scout" | "hunter") => {
    const task = await run(() => api<AgentTask>(`/workspaces/${ws}/projects/${projectId}/agent-runs`, { method: "POST", body: { agent } }), { refresh: false });
    if (task) router.push(`/w/${ws}/agents/${task.id}`);
  };
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <Button disabled={busy} onClick={() => start("scout")}>Suggest collections (Scout)</Button>
        <Button disabled={busy} onClick={() => start("hunter")}>Look for findings (Hunter)</Button>
      </div>
      {error && <Alert>{error}</Alert>}
    </div>
  );
}
