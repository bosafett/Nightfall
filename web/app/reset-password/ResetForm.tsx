"use client";

import Link from "next/link";
import { useState, useSyncExternalStore } from "react";
import { api } from "@/lib/api/client";
import { readHashToken } from "@/lib/hashToken";
import { Alert, Button, Field, Input } from "@/components/ui/primitives";

const noop = () => () => {};

export function ResetForm() {
  const token = useSyncExternalStore(noop, readHashToken, () => null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const pw = String(f.get("password"));
    if (pw !== String(f.get("confirm"))) return setError("Passwords don't match.");
    setBusy(true);
    setError(null);
    try {
      await api("/auth/password-reset", { method: "POST", body: { token, new_password: pw } });
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reset failed.");
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="space-y-4">
        <Alert tone="green">Password changed. Every other session was signed out.</Alert>
        <Link href="/login" className="text-sm text-crimson-text underline">Sign in</Link>
      </div>
    );
  }
  if (!token) return <Alert>This reset link is incomplete. Ask your admin for a new one.</Alert>;

  return (
    <form onSubmit={submit} className="space-y-4">
      {error && <Alert>{error}</Alert>}
      <Field label="New password" hint="At least 12 characters.">
        <Input name="password" type="password" autoComplete="new-password" minLength={12} required />
      </Field>
      <Field label="Repeat new password">
        <Input name="confirm" type="password" autoComplete="new-password" minLength={12} required />
      </Field>
      <Button type="submit" variant="primary" className="w-full" disabled={busy}>
        {busy ? "Saving…" : "Set new password"}
      </Button>
    </form>
  );
}
