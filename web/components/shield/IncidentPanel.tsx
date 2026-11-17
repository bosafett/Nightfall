"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { IncidentDetail, IncidentVerify } from "@/lib/api/types";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Input, Panel, Select, Textarea } from "@/components/ui/primitives";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const NEXT: Record<string, "contained" | "recovering" | null> = { open: "contained", contained: "recovering", recovering: null };

/** Everything a person does on an incident. JANUS records it; the only thing it runs is
 * "Verify now", which queues the monitor's own check under its existing authorization. */
export function IncidentPanel({ ws, incident: inc, addable, findings, canWork, canManage, mfaHint }: {
  ws: string; incident: IncidentDetail; addable: { id: string; title: string }[]; findings: { id: string; title: string }[]; canWork: boolean; canManage: boolean; mfaHint: boolean;
}) {
  const { busy, error, run } = useAction();
  const [verify, setVerify] = useState<IncidentVerify | null>(null);
  const base = `/workspaces/${ws}/incidents/${inc.id}`;
  const post = (path: string, body?: unknown) => run(() => api(`${base}/${path}`, { method: "POST", body }));
  const text = (form: HTMLFormElement, name: string) => String(new FormData(form).get(name) ?? "").trim();
  const next = NEXT[inc.state];
  const inProgress = inc.state in NEXT;

  if (!canWork && !canManage) return null;
  return (
    <>
      {error && <Alert>{error}</Alert>}
      {canWork && (
        <Panel title="Work the incident">
          <form className="space-y-2" data-testid="incident-entry" onSubmit={async (e) => {
            e.preventDefault();
            const form = e.currentTarget;
            const kind = text(form, "kind"), body = text(form, "body");
            if (body && (await post("entries", { kind, body }))) form.reset();
          }}>
            <div className="flex flex-wrap gap-2">
              <Select name="kind" aria-label="Entry type" defaultValue="note">
                <option value="note">Note: something observed or decided</option>
                <option value="action">Action: something you did outside JANUS</option>
              </Select>
              <Input name="body" required maxLength={4000} placeholder="What happened, or what was done" aria-label="Entry text" className="min-w-0 flex-1" />
              <Button type="submit" disabled={busy}>Add to timeline</Button>
            </div>
          </form>

          <p className="mt-4 text-xs text-muted">Checklist: recommendations for people. Nothing here is run by JANUS.</p>
          <div className="mt-1 space-y-1" data-testid="incident-checklist">
            {inc.checklist.map((c) => (
              <label key={c.key} className="flex items-start gap-2 text-sm">
                <input type="checkbox" className="mt-1" checked={c.done} disabled={busy} onChange={(e) => post("checklist", { key: c.key, done: e.target.checked })} />
                <span>{c.text}</span>
              </label>
            ))}
            <form className="flex gap-2 pt-1" onSubmit={async (e) => {
              e.preventDefault();
              const form = e.currentTarget;
              const t = text(form, "text");
              if (t && (await post("checklist", { text: t }))) form.reset();
            }}>
              <Input name="text" maxLength={500} placeholder="Add a checklist item" aria-label="New checklist item" className="min-w-0 flex-1" />
              <Button type="submit" disabled={busy}>Add</Button>
            </form>
          </div>

          <div className="mt-4 flex flex-wrap items-end gap-2">
            {inc.verification.length > 0 && (
              <Button variant="primary" disabled={busy} data-testid="verify-now" onClick={async () => {
                setVerify((await run(() => api<IncidentVerify>(`${base}/verify`, { method: "POST" }))) ?? null);
              }}>Verify now</Button>
            )}
            {next && (
              <form className="flex min-w-0 flex-1 gap-2" onSubmit={(e) => {
                e.preventDefault();
                const note = text(e.currentTarget, "note");
                if (note) post("state", { state: next, note });
              }}>
                <Input name="note" required maxLength={4000} aria-label={`Note for marking ${next}`} className="min-w-0 flex-1"
                  placeholder={next === "contained" ? "How the immediate exposure was stopped" : "What fix is in place"} />
                <Button type="submit" disabled={busy} data-testid="incident-next">Mark {next}</Button>
              </form>
            )}
          </div>
          {verify && (
            <div className="mt-2 text-sm" data-testid="verify-result">
              {verify.queued.map((q) => <p key={q.operation_id}>Queued: {q.tool} check of {q.target}. It runs under the monitor&apos;s authorization; refresh in a moment.</p>)}
              {verify.skipped.map((s) => <p key={s.alert_id} className="text-muted">{s.title}: {s.reason}</p>)}
              {verify.queued.length === 0 && verify.skipped.length === 0 && <p className="text-muted">Nothing new to check: the checks are already waiting.</p>}
            </div>
          )}

          {addable.length > 0 && (
            <form className="mt-4 flex gap-2" onSubmit={(e) => {
              e.preventDefault();
              const id = text(e.currentTarget, "alert");
              if (id) post("items", { kind: "alert", item_id: id });
            }}>
              <Select name="alert" aria-label="Alert to add" defaultValue="" className="min-w-0 flex-1">
                <option value="" disabled>Add another alert of this project…</option>
                {addable.map((a) => <option key={a.id} value={a.id}>{a.title}</option>)}
              </Select>
              <Button type="submit" disabled={busy}>Link</Button>
            </form>
          )}
          {findings.length > 0 && (
            <form className="mt-2 flex gap-2" data-testid="incident-link-finding" onSubmit={(e) => {
              e.preventDefault();
              const id = text(e.currentTarget, "finding");
              if (id) post("items", { kind: "finding", item_id: id });
            }}>
              <Select name="finding" aria-label="Finding to add" defaultValue="" className="min-w-0 flex-1">
                <option value="" disabled>Link a finding of this project…</option>
                {findings.map((f) => <option key={f.id} value={f.id}>{f.title}</option>)}
              </Select>
              <Button type="submit" disabled={busy}>Link</Button>
            </form>
          )}
        </Panel>
      )}

      {canManage && inProgress && (
        <Panel title="Close (admin or owner)">
          {inc.close_blockers.length > 0 ? (
            <Alert tone="yellow">
              Not verified: {inc.close_blockers.join(" ")} Verify again, or give an override reason below.
              {mfaHint && " An override asks for your authenticator code."}
            </Alert>
          ) : <p className="mb-2 text-sm text-muted">Every check that can look for these alerts again no longer sees them.</p>}
          <form className="space-y-3" data-testid="incident-close" onSubmit={(e) => {
            e.preventDefault();
            const f = e.currentTarget;
            post("close", {
              review: { what_happened: text(f, "what_happened"), cause: text(f, "cause"), what_was_done: text(f, "what_was_done"), lessons: text(f, "lessons") },
              override_reason: text(f, "override_reason"),
            });
          }}>
            <Field label="What happened"><Textarea name="what_happened" rows={2} required maxLength={4000} /></Field>
            <Field label="Cause, if known"><Textarea name="cause" rows={2} maxLength={4000} /></Field>
            <Field label="What was done"><Textarea name="what_was_done" rows={2} required maxLength={4000} /></Field>
            <Field label="What would catch it sooner next time"><Textarea name="lessons" rows={2} maxLength={4000} /></Field>
            {inc.close_blockers.length > 0 && (
              <Field label="Override reason" hint="Why this closes without verification, e.g. the host was decommissioned. Shown on the incident as an override.">
                <Input name="override_reason" maxLength={2000} />
              </Field>
            )}
            <Button type="submit" variant="primary" disabled={busy}>Close incident</Button>
          </form>

          <div className="mt-6 grid gap-3 border-t border-border pt-4 md:grid-cols-2">
            <form className="flex flex-wrap gap-2" onSubmit={(e) => {
              e.preventDefault();
              const reason = text(e.currentTarget, "reason");
              if (reason) post("severity", { severity: text(e.currentTarget, "severity"), reason });
            }}>
              <Select name="severity" aria-label="Severity" defaultValue={inc.severity}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</Select>
              <Input name="reason" required maxLength={1000} placeholder="Why" aria-label="Reason for the severity" className="min-w-0 flex-1" />
              <Button type="submit" disabled={busy}>Set severity</Button>
            </form>
            <form className="flex flex-wrap gap-2" onSubmit={(e) => {
              e.preventDefault();
              const reason = text(e.currentTarget, "reason");
              if (reason) post("cancel", { reason });
            }}>
              <Input name="reason" required maxLength={1000} placeholder="Opened by mistake because…" aria-label="Reason for cancelling" className="min-w-0 flex-1" />
              <Button type="submit" disabled={busy}>Cancel incident</Button>
            </form>
          </div>
        </Panel>
      )}

      {canManage && inc.state === "closed" && (
        <Panel title="Reopen (admin or owner)">
          <form className="flex gap-2" onSubmit={(e) => {
            e.preventDefault();
            const reason = text(e.currentTarget, "reason");
            if (reason) post("reopen", { reason });
          }}>
            <Input name="reason" required maxLength={1000} placeholder="Why it's being reopened" aria-label="Reason for reopening" className="min-w-0 flex-1" />
            <Button type="submit" disabled={busy}>Reopen</Button>
          </form>
        </Panel>
      )}
    </>
  );
}
