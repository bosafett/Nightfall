"use client";

import { useRef, useState } from "react";
import { Button } from "./primitives";

/** Button that asks for confirmation in a native modal dialog before running onConfirm. */
export function ConfirmButton({
  label, title, body, confirmLabel, onConfirm, variant = "danger",
}: {
  label: string; title: string; body: string; confirmLabel: string;
  onConfirm: () => Promise<void>; variant?: "danger" | "secondary";
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
      ref.current?.close();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Button variant={variant} className="px-2.5 py-1 text-xs" onClick={() => ref.current?.showModal()}>{label}</Button>
      <dialog ref={ref} className="m-auto w-[min(28rem,calc(100%-2rem))] rounded-lg border border-border-strong bg-surface p-5 text-text backdrop:bg-black/70">
        <h2 className="text-lg font-semibold">{title}</h2>
        <p className="mt-2 text-sm text-muted">{body}</p>
        {error && <p role="alert" className="mt-3 text-sm text-crimson-text">{error}</p>}
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="ghost" onClick={() => ref.current?.close()} disabled={busy}>Cancel</Button>
          <Button variant={variant === "danger" ? "primary" : "secondary"} onClick={run} disabled={busy}>
            {busy ? "Working…" : confirmLabel}
          </Button>
        </div>
      </dialog>
    </>
  );
}
