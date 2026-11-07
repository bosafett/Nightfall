"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { OwnershipClaim, OwnershipClaimCreated } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Field, Input, Select } from "@/components/ui/primitives";

/** Proof of control over targets (Profile B design, gate G1). Profile B itself stays off. */
export function OwnershipPanel({ ws, scopeId, claims, canManage, canCheck }: {
  ws: string; scopeId: string | null; claims: OwnershipClaim[]; canManage: boolean; canCheck: boolean;
}) {
  const { busy, error, run } = useAction();
  const [created, setCreated] = useState<OwnershipClaimCreated | null>(null);
  const base = `/workspaces/${ws}`;
  const active = claims.filter((c) => !c.retired_at);
  const retired = claims.filter((c) => c.retired_at);

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        An authorization reference shows intent; this shows control. Publish a one-time token in DNS or on the web server,
        then check it. Proof lasts 24 hours and belongs to the scope version it was checked against. IP-address targets
        can&apos;t be proven this way.
      </p>
      {error && <Alert>{error}</Alert>}
      {created && (
        <div data-testid="claim-token" className="space-y-2 rounded-md border border-yellow/40 p-3 text-sm">
          <p className="font-medium">Token for {created.name}. Copy it now: it won&apos;t be shown again.</p>
          <p className="break-all rounded bg-bg px-2 py-1 font-mono text-xs">{created.token}</p>
          <p className="text-muted">
            {created.method === "dns"
              ? <>Add it as a <span className="font-mono">TXT</span> record named <span className="font-mono">_janus-verify.{created.name}</span>. It covers {created.name} and every name under it.</>
              : <>Serve it as the only line of <span className="font-mono">{created.where}</span> over HTTPS with a valid certificate. It covers this host only.</>}
          </p>
          <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => setCreated(null)}>I&apos;ve copied it</Button>
        </div>
      )}
      {active.length === 0 ? <p className="text-sm text-muted">No ownership claims yet.</p> : (
        <ul className="space-y-2" data-testid="ownership-claims">
          {active.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-border bg-bg px-3 py-2">
              <span className="min-w-0">
                <span className="block font-mono text-sm">{c.name}</span>
                <span className="block text-xs text-muted">{c.method === "dns" ? "DNS record" : "File on web server"} · {c.where}</span>
                {c.last_check ? (
                  <span className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                    <Badge tone={c.last_check.ok ? "green" : "crimson"}>{c.last_check.ok ? "Found" : "Not found"}</Badge>
                    <span className="text-muted">{c.last_check.detail} · {formatDateTime(c.last_check.checked_at)} by {c.last_check.checked_by}</span>
                  </span>
                ) : <span className="mt-1 block text-xs text-muted">Not checked yet.</span>}
              </span>
              <span className="flex gap-2">
                {canCheck && scopeId && (
                  <Button variant="secondary" className="px-2 py-1 text-xs" disabled={busy}
                    onClick={() => run(() => api(`${base}/scopes/${scopeId}/ownership/${c.id}/check`, { method: "POST" }))}>
                    Check now
                  </Button>
                )}
                {canManage && (
                  <ConfirmButton label="Retire" title={`Retire the claim for ${c.name}?`}
                    body="Its proof stops counting at once. You can issue a new token afterwards." confirmLabel="Retire claim"
                    onConfirm={async () => { await run(() => api(`${base}/ownership/claims/${c.id}/retire`, { method: "POST" })); }} />
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
      {!scopeId && active.length > 0 && <p className="text-xs text-muted">Checks run against the active, non-lab scope. Authorize one first.</p>}
      {canManage ? (
        <form className="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_13rem_auto] sm:items-end" onSubmit={async (e) => {
          e.preventDefault();
          const form = e.currentTarget;
          const f = new FormData(form);
          const res = await run(() => api<OwnershipClaimCreated>(`${base}/ownership/claims`, {
            method: "POST", body: { name: String(f.get("name")), method: String(f.get("method")) },
          }));
          if (res) { setCreated(res); form.reset(); }
        }}>
          <Field label="Hostname or domain"><Input name="name" required maxLength={253} className="font-mono" placeholder="example.com" /></Field>
          <Field label="Proof method">
            <Select name="method" defaultValue="dns">
              <option value="dns">DNS TXT record</option>
              <option value="file">File on web server</option>
            </Select>
          </Field>
          <Button type="submit" disabled={busy}>Issue token</Button>
        </form>
      ) : <p className="text-xs text-muted">Only an owner issues or retires tokens.</p>}
      {retired.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted">Retired claims ({retired.length})</summary>
          <ul className="mt-2 space-y-1 font-mono text-xs text-muted">
            {retired.map((c) => <li key={c.id}>{c.name} · {c.method} · retired {formatDateTime(c.retired_at)}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
}
