"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { Operation } from "@/lib/api/types";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Input, Select } from "@/components/ui/primitives";

/** Collection request (passive, or low risk with approval). The server checks scope; this form can't widen it. */
export function CollectionForm({ ws, projectId, suggestions }: { ws: string; projectId: string; suggestions: string[] }) {
  const { busy, error, run } = useAction();
  const [queued, setQueued] = useState<Operation | null>(null);
  return (
    <form className="space-y-3" onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      setQueued(null);
      const op = await run(() => api<Operation>(`/workspaces/${ws}/projects/${projectId}/collections`, {
        method: "POST", body: { tool: String(f.get("tool")), target: String(f.get("target")) },
      }));
      if (op) setQueued(op);
    }}>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-[14rem_minmax(0,1fr)]">
        <Field label="Collector">
          <Select name="tool" defaultValue="ct">
            <option value="ct">Certificate transparency</option>
            <option value="dns">DNS records</option>
            <option value="http">Technology identification (low risk · needs approval)</option>
            <option value="nuclei">Web exposure checks (low risk · needs approval)</option>
          </Select>
        </Field>
        <Field label="Target" hint="Must be inside the authorized scope. CT and DNS are passive. Technology identification sends up to 3 GET requests. Web exposure checks run 4 reviewed GET-only checks through the scope proxy. Both need a second person to approve.">
          <Input name="target" list={`scope-suggestions-${projectId}`} required maxLength={300} className="font-mono" placeholder="example.com" />
          <datalist id={`scope-suggestions-${projectId}`}>{suggestions.map((s) => <option key={s} value={s} />)}</datalist>
        </Field>
      </div>
      {error && <Alert>{error}</Alert>}
      {queued && <Alert tone="green">{queued.status === "awaiting_approval" ? `Requested ${queued.tool_label} for ${queued.target}. It runs once it is explicitly approved.` : `Queued ${queued.tool_label} for ${queued.target}.`}</Alert>}
      <Button type="submit" variant="primary" disabled={busy}>{busy ? "Checking scope…" : "Request collection"}</Button>
    </form>
  );
}
