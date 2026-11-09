"use client";

import { api } from "@/lib/api/client";
import type { ScopeEntryKind, ScopeVersion } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { scopeKindHint, scopeKindLabel } from "@/lib/labels";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Field, Input, Select } from "@/components/ui/primitives";
import { LabBadge } from "@/components/scope/LabBadge";

const KINDS: ScopeEntryKind[] = ["domain_tree", "host", "cidr", "ip"];
const toInput = (iso: string | null) => (iso ? iso.slice(0, 16) : "");
const fromInput = (v: FormDataEntryValue | null) => (v ? new Date(`${String(v)}Z`).toISOString() : null);

function Entries({ title, entries, onRemove, empty }: {
  title: string; entries: ScopeVersion["targets"]; onRemove?: (id: string) => void; empty: string;
}) {
  return (
    <div>
      <h3 className="text-sm font-medium">{title}</h3>
      {entries.length === 0 ? <p className="mt-1 text-sm text-muted">{empty}</p> : (
        <ul className="mt-2 space-y-1.5">
          {entries.map((e) => (
            <li key={e.id} className="flex items-center justify-between gap-2 rounded border border-border bg-bg px-3 py-1.5">
              <span className="min-w-0">
                <span className="block truncate font-mono text-sm">{e.value}</span>
                <span className="block text-xs text-muted">{scopeKindLabel[e.kind]}{e.note && ` · ${e.note}`}</span>
              </span>
              {e.control?.proven && (
                <span data-testid="control-proven" title={`Proven by ${e.control.method === "dns" ? "DNS record" : "file"} on ${e.control.claim_name}, checked ${formatDateTime(e.control.checked_at ?? null)}`}>
                  <Badge tone="green">Control proven</Badge>
                </span>
              )}
              {onRemove && <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => onRemove(e.id)} aria-label={`Remove ${e.value}`}>Remove</Button>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function AddEntry({ label, onAdd, noteLabel }: { label: string; noteLabel: string; onAdd: (kind: string, value: string, note: string) => Promise<unknown> }) {
  return (
    <form className="grid grid-cols-1 gap-2 sm:grid-cols-[13rem_minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end" onSubmit={async (e) => {
      e.preventDefault();
      const form = e.currentTarget;
      const f = new FormData(form);
      const ok = await onAdd(String(f.get("kind")), String(f.get("value")), String(f.get("note")));
      if (ok) form.reset();
    }}>
      <Field label={`${label} type`}>
        <Select name="kind" defaultValue="domain_tree">
          {KINDS.map((k) => <option key={k} value={k} title={scopeKindHint[k]}>{scopeKindLabel[k]}</option>)}
        </Select>
      </Field>
      <Field label={`${label} value`}><Input name="value" required maxLength={300} className="font-mono" /></Field>
      <Field label={noteLabel}><Input name="note" maxLength={500} /></Field>
      <Button type="submit">Add</Button>
    </form>
  );
}

export function ScopePanel({ ws, projectId, versions, canEdit, canAuthorize }: {
  ws: string; projectId: string; versions: ScopeVersion[]; canEdit: boolean; canAuthorize: boolean;
}) {
  const { busy, error, run } = useAction();
  const active = versions.find((v) => v.status === "active");
  const draft = versions.find((v) => v.status === "draft");
  const history = versions.filter((v) => v.status === "superseded");
  const base = `/workspaces/${ws}`;

  return (
    <div className="space-y-6">
      {error && <Alert>{error}</Alert>}

      {active ? (
        <section aria-label="Active scope" className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="green">Authorized · v{active.version}</Badge>
            {active.is_lab && <LabBadge />}
            <span className="text-sm text-muted">Ref: <span className="text-text">{active.authorization_reference}</span></span>
          </div>
          <p className="font-mono text-xs text-muted tabular">
            Authorized by {active.authorized_by} on {formatDateTime(active.authorized_at)}
            {(active.valid_from || active.valid_until) && <> · valid {formatDateTime(active.valid_from)} → {formatDateTime(active.valid_until)}</>}
          </p>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Entries title="In scope" entries={active.targets} empty="No targets." />
            <Entries title="Excluded (always wins)" entries={active.exclusions} empty="No exclusions." />
          </div>
        </section>
      ) : (
        <Alert tone="yellow">No authorized scope. Nothing can be collected for this project until one is authorized.</Alert>
      )}

      {draft ? (
        <section aria-label="Draft scope" className="space-y-4 rounded-md border border-yellow/40 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex flex-wrap items-center gap-2">
              <Badge tone="yellow">Draft · v{draft.version}</Badge>
              {draft.is_lab && <LabBadge />}
            </span>
            {canEdit && (
              <ConfirmButton label="Discard draft" title="Discard this draft?" body="The authorized scope (if any) stays as it is." confirmLabel="Discard draft"
                onConfirm={async () => { await run(() => api(`${base}/scopes/${draft.id}`, { method: "DELETE" })); }} />
            )}
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Entries title="In scope" entries={draft.targets} empty="Add at least one target."
              onRemove={canEdit ? (id) => run(() => api(`${base}/scopes/${draft.id}/targets/${id}`, { method: "DELETE" })) : undefined} />
            <Entries title="Excluded" entries={draft.exclusions} empty="No exclusions."
              onRemove={canEdit ? (id) => run(() => api(`${base}/scopes/${draft.id}/exclusions/${id}`, { method: "DELETE" })) : undefined} />
          </div>
          {canEdit && (
            <label className="flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-1" checked={draft.is_lab} disabled={busy}
                onChange={(e) => run(() => api(`${base}/scopes/${draft.id}`, { method: "PATCH", body: { is_lab: e.target.checked } }))} />
              <span>
                <span className="font-medium">Lab scope (isolated lab machine)</span>
                <span className="block text-xs text-muted">
                  Targets must be IP addresses inside the lab network, e.g. <span className="font-mono">172.30.99.10</span>. Lab runs are carried out
                  only by your lab machine, are launched and approved only in BLACKSITE (with a fresh two-factor code), and are recorded as lab results.
                </span>
              </span>
            </label>
          )}
          {canEdit && (
            <>
              <AddEntry label="Target" noteLabel="Note (optional)" onAdd={(kind, value, note) =>
                run(() => api(`${base}/scopes/${draft.id}/targets`, { method: "POST", body: { kind, value, note } }))} />
              <AddEntry label="Exclusion" noteLabel="Reason (optional)" onAdd={(kind, value, note) =>
                run(() => api(`${base}/scopes/${draft.id}/exclusions`, { method: "POST", body: { kind, value, note } }))} />
              <form className="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end" onSubmit={async (e) => {
                e.preventDefault();
                const f = new FormData(e.currentTarget);
                await run(() => api(`${base}/scopes/${draft.id}`, { method: "PATCH", body: {
                  authorization_reference: String(f.get("reference")), valid_from: fromInput(f.get("from")), valid_until: fromInput(f.get("until")),
                } }));
              }}>
                <Field label="Authorization reference" hint="e.g. the signed engagement letter or SOW number">
                  <Input name="reference" defaultValue={draft.authorization_reference} maxLength={500} />
                </Field>
                <Field label="Valid from (UTC)"><Input name="from" type="datetime-local" defaultValue={toInput(draft.valid_from)} /></Field>
                <Field label="Valid until (UTC)"><Input name="until" type="datetime-local" defaultValue={toInput(draft.valid_until)} /></Field>
                <Button type="submit" disabled={busy}>Save details</Button>
              </form>
            </>
          )}
          {canAuthorize ? (
            <ConfirmButton variant="secondary" label={`Authorize v${draft.version}`} title={`Authorize scope v${draft.version}?`}
              body={`This becomes the only scope collection can use${active ? `, replacing v${active.version}. Queued jobs from v${active.version} will be refused` : ""}. An authorized version can't be edited.`}
              confirmLabel="Authorize scope"
              onConfirm={async () => { await run(() => api(`${base}/scopes/${draft.id}/authorize`, { method: "POST" })); }} />
          ) : (
            <p className="text-xs text-muted">An admin or owner authorizes the draft.</p>
          )}
        </section>
      ) : canEdit && (
        <Button disabled={busy} onClick={() => run(() => api(`${base}/projects/${projectId}/scopes`, { method: "POST" }))}>
          {active ? `Start draft v${active.version + 1}` : "Draft a scope"}
        </Button>
      )}

      {history.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted">Scope history ({history.length} earlier {history.length === 1 ? "version" : "versions"})</summary>
          <ul className="mt-2 space-y-2">
            {history.map((v) => (
              <li key={v.id} className="rounded border border-border p-3">
                <p className="font-medium">v{v.version} · {v.authorization_reference}</p>
                <p className="font-mono text-xs text-muted tabular">Authorized {formatDateTime(v.authorized_at)} by {v.authorized_by} · replaced {formatDateTime(v.superseded_at)}</p>
                <p className="mt-1 font-mono text-xs">{v.targets.map((t) => t.value).join(", ")}{v.exclusions.length > 0 && <span className="text-muted"> · excluding {v.exclusions.map((t) => t.value).join(", ")}</span>}</p>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
