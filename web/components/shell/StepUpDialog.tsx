"use client";

import { useEffect, useRef, useState } from "react";
import { api, setStepUpHandler } from "@/lib/api/client";
import { Button, Field, Input } from "@/components/ui/primitives";

/** Prompts for a fresh authenticator code when a sensitive action needs one (D1). */
export function StepUpDialog() {
  const ref = useRef<HTMLDialogElement>(null);
  const resolver = useRef<((ok: boolean) => void) | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setStepUpHandler(() => new Promise<boolean>((resolve) => {
      resolver.current = resolve;
      setCode("");
      setError(null);
      ref.current?.showModal();
    }));
    return () => setStepUpHandler(null);
  }, []);

  function finish(ok: boolean) {
    ref.current?.close();
    resolver.current?.(ok);
    resolver.current = null;
  }

  async function verify() {
    setBusy(true);
    setError(null);
    try {
      await api("/auth/mfa/verify", { method: "POST", body: { code } });
      finish(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "That code didn't work.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <dialog ref={ref} onCancel={() => finish(false)} data-testid="step-up"
      className="m-auto w-[min(24rem,calc(100%-2rem))] rounded-lg border border-border-strong bg-surface p-5 text-text backdrop:bg-black/70">
      <h2 className="text-lg font-semibold">Confirm it&apos;s you</h2>
      <p className="mt-2 text-sm text-muted">Sensitive actions need a two-factor code from the last 15 minutes.</p>
      <form className="mt-4 space-y-3" onSubmit={(e) => { e.preventDefault(); void verify(); }}>
        <Field label="Authenticator code">
          <Input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" autoFocus />
        </Field>
        {error && <p role="alert" className="text-sm text-crimson-text">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={() => finish(false)} disabled={busy}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || code.length !== 6}>{busy ? "Checking…" : "Confirm"}</Button>
        </div>
      </form>
    </dialog>
  );
}
