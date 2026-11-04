"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api/client";
import { ApiError } from "@/lib/api/errors";
import { Alert, Button, Field, Input } from "@/components/ui/primitives";

export function LoginForm() {
  const router = useRouter();
  const [needsCode, setNeedsCode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await api("/auth/login", {
        method: "POST",
        body: {
          email: String(f.get("email")),
          password: String(f.get("password")),
          ...(needsCode ? { totp_code: String(f.get("code")).replace(/\s/g, "") } : {}),
        },
      });
      router.replace("/");
      router.refresh();
    } catch (err) {
      if (err instanceof ApiError && err.code === "mfa_required") {
        setNeedsCode(true);
      } else {
        setError(err instanceof Error ? err.message : "Sign-in failed.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      {error && <Alert>{error}</Alert>}
      <Field label="Email">
        <Input name="email" type="email" autoComplete="username" required readOnly={needsCode} />
      </Field>
      <Field label="Password">
        <Input name="password" type="password" autoComplete="current-password" required readOnly={needsCode} />
      </Field>
      {needsCode && (
        <Field label="Authentication code" hint="The 6-digit code from your authenticator app.">
          <Input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required autoFocus className="font-mono tracking-[0.3em]" />
        </Field>
      )}
      <Button type="submit" variant="primary" className="w-full" disabled={busy}>
        {busy ? "Signing in…" : needsCode ? "Verify and sign in" : "Sign in"}
      </Button>
      <p className="text-xs text-muted">Forgot your password? Ask a workspace admin for a reset link.</p>
    </form>
  );
}
