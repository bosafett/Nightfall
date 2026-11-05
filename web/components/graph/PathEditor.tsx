"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { Asset, AttackPath, Finding } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Field, Input, Select, Textarea } from "@/components/ui/primitives";
import { SeverityBadge, StatusBadge } from "@/components/findings/Badges";

type Step = { ref: string; description: string };

export function NewPath({ ws, projectId, findings, assets }: { ws: string; projectId: string; findings: Finding[]; assets: Asset[] }) {
  const [open, setOpen] = useState(false);
  const [steps, setSteps] = useState<Step[]>([{ ref: "", description: "" }, { ref: "", description: "" }]);
  const { busy, error, run } = useAction();
  if (!open) return <Button onClick={() => setOpen(true)}>Propose an attack path</Button>;
  const set = (i: number, patch: Partial<Step>) => setSteps((s) => s.map((x, j) => (j === i ? { ...x, ...patch } : x)));
  return (
    <form className="space-y-3 rounded-md border border-border-strong p-4" onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      const ok = await run(() => api(`/workspaces/${ws}/projects/${projectId}/attack-paths`, { method: "POST", body: {
        title: String(f.get("title")), narrative: String(f.get("narrative")), confidence: String(f.get("confidence")),
        steps: steps.map((s) => ({ description: s.description, ...(s.ref.startsWith("f:") ? { finding_id: s.ref.slice(2) } : { asset_id: s.ref.slice(2) }) })),
      } }));
      if (ok) { setOpen(false); setSteps([{ ref: "", description: "" }, { ref: "", description: "" }]); }
    }}>
      <p className="text-sm text-muted">A proposed path is a hypothesis. It can only be marked validated once every finding in it is validated.</p>
      {error && <Alert>{error}</Alert>}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-[minmax(0,1fr)_12rem]">
        <Field label="Path title"><Input name="title" required maxLength={300} /></Field>
        <Field label="Confidence"><Select name="confidence" defaultValue="low"><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></Select></Field>
      </div>
      <Field label="Narrative"><Textarea name="narrative" maxLength={20000} /></Field>
      <ol className="space-y-2">
        {steps.map((s, i) => (
          <li key={i} className="grid grid-cols-1 gap-2 md:grid-cols-[2rem_minmax(0,1fr)_minmax(0,1fr)] md:items-end">
            <span className="font-mono text-sm text-muted">{i + 1}.</span>
            <Field label={`Step ${i + 1}: finding or asset`}>
              <Select value={s.ref} onChange={(e) => set(i, { ref: e.target.value })} required>
                <option value="">Choose…</option>
                <optgroup label="Findings">{findings.map((f) => <option key={f.id} value={`f:${f.id}`}>{f.ref} {f.title}</option>)}</optgroup>
                <optgroup label="Assets">{assets.map((a) => <option key={a.id} value={`a:${a.id}`}>{a.value}</option>)}</optgroup>
              </Select>
            </Field>
            <Field label={`Step ${i + 1}: what happens`}><Input value={s.description} onChange={(e) => set(i, { description: e.target.value })} required maxLength={2000} /></Field>
          </li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-2">
        <Button onClick={() => setSteps((s) => [...s, { ref: "", description: "" }])} disabled={steps.length >= 50}>Add step</Button>
        {steps.length > 2 && <Button variant="ghost" onClick={() => setSteps((s) => s.slice(0, -1))}>Remove last step</Button>}
        <Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Save as hypothesis"}</Button>
        <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
      </div>
    </form>
  );
}

export function PathCard({ ws, path, canReview, selected }: { ws: string; path: AttackPath; canReview: boolean; selected: boolean }) {
  const [note, setNote] = useState("");
  const { error, run } = useAction();
  const review = (status: string) => run(() => api(`/workspaces/${ws}/attack-paths/${path.id}/review`, { method: "POST", body: { status, note } }));
  return (
    <article className={`rounded-md border p-4 ${selected ? "border-crimson" : "border-border"}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-medium">{path.title}</h3>
        <Badge tone={path.status === "validated" ? "green" : path.status === "rejected" ? "gray" : "yellow"}>
          {path.status === "validated" ? "Validated" : path.status === "rejected" ? "Rejected" : "Hypothesis — not demonstrated"}
        </Badge>
      </div>
      {path.narrative && <p className="mt-1 text-sm text-muted">{path.narrative}</p>}
      <ol className="mt-3 space-y-1.5 text-sm">
        {path.steps.map((s) => (
          <li key={s.ordinal} className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-muted">{s.ordinal}.</span>
            {s.finding_ref ? <>{s.finding_severity && <SeverityBadge severity={s.finding_severity} />}<span className="font-mono text-xs">{s.finding_ref}</span> {s.finding_title}{s.finding_status && <StatusBadge status={s.finding_status} />}</>
              : <span className="font-mono text-xs">{s.asset_value}</span>}
            <span className="text-muted">— {s.description}</span>
          </li>
        ))}
      </ol>
      {path.reviewed_by && <p className="mt-2 text-xs text-muted">Reviewed by {path.reviewed_by} on {formatDateTime(path.reviewed_at)}{path.review_note && `: ${path.review_note}`}</p>}
      {canReview && (
        <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-end">
          <div className="flex-1"><Field label="Review note"><Input value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} /></Field></div>
          {path.status !== "validated" && <ConfirmButton variant="secondary" label="Mark validated" title="Mark this path validated?" body="Only allowed when every finding in it is validated. Your name and note are recorded." confirmLabel="Mark validated" onConfirm={async () => { await review("validated"); }} />}
          {path.status !== "rejected" && <ConfirmButton label="Reject" title="Reject this path?" body="It stays on record as rejected." confirmLabel="Reject path" onConfirm={async () => { await review("rejected"); }} />}
          {path.status !== "hypothesis" && <Button onClick={() => review("hypothesis")}>Reopen as hypothesis</Button>}
        </div>
      )}
      {error && <div className="mt-2"><Alert>{error}</Alert></div>}
    </article>
  );
}
