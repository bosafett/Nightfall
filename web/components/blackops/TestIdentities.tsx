"use client";

import { api } from "@/lib/api/client";
import type { TestIdentities as Data } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Field, Input, Select, Textarea } from "@/components/ui/primitives";

/** Profile B designated test identities (G2). The credential is sealed to the self-hosted
 * worker's key on arrival and never shown again; this page only says it's set. */
export function TestIdentities({ ws, data }: { ws: string; data: Data }) {
  const { busy, error, run } = useAction();
  const active = data.identities.filter((i) => !i.retired_at);
  const retired = data.identities.filter((i) => i.retired_at);
  return (
    <div className="space-y-4" data-testid="test-identities">
      <p className="text-sm text-muted">
        Accounts that exist only for testing, each bound to one HTTPS origin. Profile B may log in only as these. The
        password is sealed to your self-hosted worker&apos;s key: this deployment can store it but can&apos;t read it back, and
        it never appears in evidence, logs, the audit trail or AI prompts.
      </p>
      {data.unavailable_reason && <Alert tone="yellow">Profile B can&apos;t run here yet: {data.unavailable_reason}</Alert>}
      {error && <Alert>{error}</Alert>}
      {active.length === 0 ? <p className="text-sm text-muted">No test identities.</p> : (
        <ul className="space-y-2">
          {active.map((i) => (
            <li key={i.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-border bg-bg px-3 py-2">
              <span className="min-w-0 text-sm">
                <span className="font-medium">{i.label}</span> <span className="font-mono text-xs text-muted">{i.origin}{i.login_path}</span>
                <span className="block text-xs text-muted">
                  {i.role_description || "No role description"} · {i.login_method === "form" ? "Login form" : "HTTP basic"} · attested by {i.attested_by} on {formatDateTime(i.attested_at)}
                </span>
              </span>
              <span className="flex items-center gap-2">
                <Badge tone="green">Credential sealed</Badge>
                <ConfirmButton label="Retire" title={`Retire ${i.label}?`} confirmLabel="Retire identity"
                  body="It can't be used again and can't be revived. Register a new one if needed."
                  onConfirm={async () => { await run(() => api(`/workspaces/${ws}/test-identities/${i.id}/retire`, { method: "POST" })); }} />
              </span>
            </li>
          ))}
        </ul>
      )}
      {data.can_register ? (
        <form className="grid grid-cols-1 gap-3 md:grid-cols-2" autoComplete="off" onSubmit={async (e) => {
          e.preventDefault();
          const form = e.currentTarget;
          const f = new FormData(form);
          const ok = await run(() => api(`/workspaces/${ws}/test-identities`, { method: "POST", body: {
            origin: String(f.get("origin")), label: String(f.get("label")), role_description: String(f.get("role")),
            login_method: String(f.get("method")), login_path: String(f.get("path") || "/"),
            username: String(f.get("username")), password: String(f.get("password")),
            attestation: String(f.get("attestation")), attest: f.get("attest") === "on",
          } }));
          if (ok) form.reset();
        }}>
          <Field label="Origin" hint="https://app.example.com"><Input name="origin" required maxLength={300} className="font-mono" /></Field>
          <Field label="Label"><Input name="label" required maxLength={100} placeholder="low-privilege customer" /></Field>
          <Field label="Role description"><Input name="role" maxLength={500} /></Field>
          <Field label="Login method">
            <Select name="method" defaultValue="form"><option value="form">Login form</option><option value="basic">HTTP basic</option></Select>
          </Field>
          <Field label="Login path"><Input name="path" defaultValue="/login" maxLength={500} className="font-mono" /></Field>
          <Field label="Username"><Input name="username" required maxLength={300} autoComplete="off" /></Field>
          <Field label="Password"><Input name="password" type="password" required maxLength={1000} autoComplete="new-password" /></Field>
          <Field label="Attestation" hint="Who created this account, and that it holds no real person's data">
            <Textarea name="attestation" required minLength={10} maxLength={1000} rows={2} />
          </Field>
          <label className="flex items-start gap-2 text-sm md:col-span-2">
            <input type="checkbox" name="attest" className="mt-1" required />
            <span>I confirm this account exists for testing only and holds no real person&apos;s data. Lockout testing is not used in v1.</span>
          </label>
          <div className="md:col-span-2"><Button type="submit" disabled={busy}>Register test identity</Button></div>
        </form>
      ) : <p className="text-xs text-muted">Registration needs the worker key (NIGHTFALL_PROFILE_B_PUBLIC_KEY) on this deployment.</p>}
      {retired.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted">Retired ({retired.length})</summary>
          <ul className="mt-2 space-y-1 text-xs text-muted">{retired.map((i) => <li key={i.id}>{i.label} · {i.origin} · retired {formatDateTime(i.retired_at)}</li>)}</ul>
        </details>
      )}
    </div>
  );
}
