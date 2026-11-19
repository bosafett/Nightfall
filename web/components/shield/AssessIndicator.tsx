"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Input, Select } from "@/components/ui/primitives";

/** A person's assessment of an indicator, with a reason. History and audit are kept by the API. */
export function AssessIndicator({ ws, id, current }: { ws: string; id: string; current: string }) {
  const { busy, error, run } = useAction();
  const [assessment, setAssessment] = useState(current === "unreviewed" ? "malicious" : "unreviewed");
  const [reason, setReason] = useState("");
  return (
    <form className="flex flex-wrap items-end gap-2" onSubmit={async (e) => {
      e.preventDefault();
      if (await run(() => api(`/workspaces/${ws}/sentinel/indicators/${id}/assess`, { method: "POST", body: { assessment, reason } }))) setReason("");
    }}>
      {error && <Alert>{error}</Alert>}
      <Field label="Assessment">
        <Select value={assessment} onChange={(e) => setAssessment(e.target.value)}>
          <option value="malicious">Malicious</option>
          <option value="benign">Benign</option>
          <option value="false_positive">False positive</option>
          <option value="unreviewed">Unreviewed (undo)</option>
        </Select>
      </Field>
      <Field label="Reason"><Input value={reason} onChange={(e) => setReason(e.target.value)} required /></Field>
      <Button type="submit" variant="primary" disabled={busy || !reason.trim() || assessment === current}>Record assessment</Button>
    </form>
  );
}
