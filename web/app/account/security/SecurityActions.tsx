"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api/client";
import type { MfaSetup as Setup } from "@/lib/api/types";
import { groupSecret } from "@/lib/format";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Input } from "@/components/ui/primitives";

export function MfaSetup() {
  const [setup, setSetup] = useState<Setup | null>(null);
  const { busy, error, run } = useAction();

  if (!setup) {
    return (
      <div className="mt-2 space-y-3">
        <p className="text-sm text-muted">Off. Use an authenticator app (TOTP) to add a second step at sign-in.</p>
        {error && <Alert>{error}</Alert>}
        <Button variant="primary" disabled={busy}
          onClick={() => run(() => api<Setup>("/auth/mfa/setup", { method: "POST" }).then(setSetup), { refresh: false })}>
          {busy ? "Starting…" : "Set up two-factor"}
        </Button>
      </div>
    );
  }

  async function confirm(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const code = String(new FormData(e.currentTarget).get("code")).replace(/\s/g, "");
    await run(() => api("/auth/mfa/confirm", { method: "POST", body: { code } }));
  }

  return (
    <form onSubmit={confirm} className="mt-3 space-y-4">
      <ol className="list-decimal space-y-2 pl-5 text-sm text-muted">
        <li>In your authenticator app, add an account by entering this key manually (time-based):</li>
      </ol>
      <p data-testid="totp-secret" data-secret={setup.secret}
        className="select-all rounded-md border border-border-strong bg-bg px-3 py-2 font-mono text-sm tracking-wider break-all">
        {groupSecret(setup.secret)}
      </p>
      <details className="text-xs text-muted">
        <summary className="cursor-pointer">Setup URI (for apps that accept one)</summary>
        <p className="mt-2 select-all break-all font-mono">{setup.otpauth_uri}</p>
      </details>
      <ol start={2} className="list-decimal pl-5 text-sm text-muted"><li>Enter the 6-digit code it shows.</li></ol>
      {error && <Alert>{error}</Alert>}
      <Field label="Authentication code">
        <Input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required className="font-mono tracking-[0.3em]" />
      </Field>
      <Button type="submit" variant="primary" disabled={busy}>{busy ? "Checking…" : "Turn on two-factor"}</Button>
    </form>
  );
}

export function SignOutEverywhere() {
  const router = useRouter();
  const { busy, error, run } = useAction();
  return (
    <>
      {error && <Alert>{error}</Alert>}
      <Button variant="danger" disabled={busy} onClick={async () => {
        await run(() => api("/auth/logout-all", { method: "POST" }), { refresh: false });
        router.replace("/login");
      }}>
        {busy ? "Signing out…" : "Sign out everywhere"}
      </Button>
    </>
  );
}
