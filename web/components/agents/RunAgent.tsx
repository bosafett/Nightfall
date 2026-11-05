"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api/client";
import type { AgentTask } from "@/lib/api/types";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Input, Select } from "@/components/ui/primitives";

type Agent = "director" | "scout" | "investigator" | "hunter" | "adversary" | "analyst";

/** Starts an agent run. The API checks role, scope and limits; the agent only proposes. */
export function RunAgent({ ws, projectId, assets }: { ws: string; projectId: string; assets: { id: string; value: string }[] }) {
  const router = useRouter();
  const { busy, error, run } = useAction();
  const [objective, setObjective] = useState("");
  const [assetId, setAssetId] = useState("");
  const start = async (agent: Agent, extra: Record<string, string> = {}) => {
    const task = await run(() => api<AgentTask>(`/workspaces/${ws}/projects/${projectId}/agent-runs`, { method: "POST", body: { agent, ...extra } }), { refresh: false });
    if (task) router.push(`/w/${ws}/agents/${task.id}`);
  };
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <Button disabled={busy} onClick={() => start("scout")}>Suggest collections (Scout)</Button>
        <Button disabled={busy} onClick={() => start("hunter")}>Look for findings (Hunter)</Button>
        <Button disabled={busy} onClick={() => start("adversary")}>Propose attack paths (Adversary)</Button>
        <Button disabled={busy} onClick={() => start("analyst")}>Summarise the assessment (Analyst)</Button>
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <form className="flex flex-col gap-2 sm:flex-row sm:items-end" onSubmit={(e) => { e.preventDefault(); void start("director", { objective }); }}>
          <div className="flex-1">
            <Field label="Objective for the Director" hint="It splits this into tasks for the other agents.">
              <Input value={objective} onChange={(e) => setObjective(e.target.value)} maxLength={500} placeholder="e.g. Map the external attack surface" />
            </Field>
          </div>
          <Button type="submit" disabled={busy || !objective.trim()}>Plan it (Director)</Button>
        </form>
        <form className="flex flex-col gap-2 sm:flex-row sm:items-end" onSubmit={(e) => { e.preventDefault(); void start("investigator", { asset_id: assetId }); }}>
          <div className="flex-1">
            <Field label="Asset to explain" hint={assets.length ? "What it is, what it runs, how it connects." : "No assets recorded for this organization yet."}>
              <Select value={assetId} onChange={(e) => setAssetId(e.target.value)} disabled={!assets.length}>
                <option value="">Choose an asset…</option>
                {assets.map((a) => <option key={a.id} value={a.id}>{a.value}</option>)}
              </Select>
            </Field>
          </div>
          <Button type="submit" disabled={busy || !assetId}>Explain it (Investigator)</Button>
        </form>
      </div>
      {error && <Alert>{error}</Alert>}
    </div>
  );
}
