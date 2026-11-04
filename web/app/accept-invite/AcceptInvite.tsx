"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api/client";
import type { InviteInfo } from "@/lib/api/types";
import { readHashToken } from "@/lib/hashToken";
import { roleLabel } from "@/lib/labels";
import { Alert, Button, Field, Input, Skeleton } from "@/components/ui/primitives";

type State = { kind: "loading" } | { kind: "invalid"; message: string } | { kind: "ready"; token: string; info: InviteInfo } | { kind: "joined" };

export function AcceptInvite() {
  const router = useRouter();
  const [state, setState] = useState<State>({ kind: "loading" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = readHashToken();
    const load = token
      ? api<InviteInfo>("/auth/invites/lookup", { method: "POST", body: { token } }).then(
          (info): State => ({ kind: "ready", token, info }),
          (e: Error): State => ({ kind: "invalid", message: e.message }),
        )
      : Promise.resolve<State>({ kind: "invalid", message: "This invite link is incomplete." });
    let live = true;
    load.then((s) => live && setState(s));
    return () => { live = false; };
  }, []);

  if (state.kind === "loading") return <Skeleton className="h-32" />;
  if (state.kind === "invalid") return <Alert>{state.message} Ask whoever invited you for a new link.</Alert>;
  if (state.kind === "joined") {
    return (
      <div className="space-y-4">
        <Alert tone="green">You&apos;ve joined the workspace. Sign in to continue.</Alert>
        <Link href="/login" className="text-sm text-crimson-text underline">Sign in</Link>
      </div>
    );
  }

  const { info, token } = state;
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const password = String(f.get("password"));
    if (!info.existing_account && password !== String(f.get("confirm"))) return setError("Passwords don't match.");
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ signed_in: boolean }>("/auth/accept-invite", {
        method: "POST",
        body: { token, password, ...(info.existing_account ? {} : { display_name: String(f.get("name")) }) },
      });
      if (res.signed_in) {
        router.replace("/");
        router.refresh();
      } else {
        setState({ kind: "joined" });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't accept the invite.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <p className="text-sm text-muted">
        You&apos;re invited to <span className="text-text">{info.workspace_name}</span> as{" "}
        <span className="text-text">{roleLabel[info.role as keyof typeof roleLabel] ?? info.role}</span>.
      </p>
      {error && <Alert>{error}</Alert>}
      <Field label="Email"><Input value={info.email} readOnly /></Field>
      {info.existing_account ? (
        <Field label="Your current password" hint="You already have an account. Confirm it's you.">
          <Input name="password" type="password" autoComplete="current-password" required />
        </Field>
      ) : (
        <>
          <Field label="Your name"><Input name="name" autoComplete="name" maxLength={120} required /></Field>
          <Field label="Password" hint="At least 12 characters.">
            <Input name="password" type="password" autoComplete="new-password" minLength={12} required />
          </Field>
          <Field label="Repeat password">
            <Input name="confirm" type="password" autoComplete="new-password" minLength={12} required />
          </Field>
        </>
      )}
      <Button type="submit" variant="primary" className="w-full" disabled={busy}>
        {busy ? "Joining…" : "Join workspace"}
      </Button>
    </form>
  );
}
