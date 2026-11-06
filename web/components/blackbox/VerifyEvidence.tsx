"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { BlackBoxVerify } from "@/lib/api/types";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button } from "@/components/ui/primitives";

const problemText = { missing: "Content missing", hash_mismatch: "Hash mismatch", size_mismatch: "Size mismatch" } as const;

/** Runs a verification in server-sized batches until the whole workspace has been checked. */
export function VerifyEvidence({ ws }: { ws: string }) {
  const { busy, error, run } = useAction();
  const [progress, setProgress] = useState<number | null>(null);
  const [result, setResult] = useState<{ checked: number; failures: BlackBoxVerify["failures"] } | null>(null);

  async function verify() {
    setResult(null);
    const failures: BlackBoxVerify["failures"] = [];
    await run(async () => {
      let q = "";
      for (;;) {
        const r = await api<BlackBoxVerify>(`/workspaces/${ws}/blackbox/verify${q}`, { method: "POST" });
        failures.push(...r.failures);
        setProgress(r.total_checked);
        if (!r.next_after) {
          setResult({ checked: r.total_checked, failures });
          return;
        }
        q = `?${new URLSearchParams({ after: r.next_after, run_id: r.run_id })}`;
      }
    });
    setProgress(null);
  }

  return (
    <div className="space-y-3">
      {error && <Alert>{error}</Alert>}
      {result && (result.failures.length === 0
        ? <Alert tone="green">All {result.checked} evidence records match their SHA-256.</Alert>
        : (
          <Alert>
            {result.failures.length} of {result.checked} records failed:
            <ul className="mt-2 space-y-1 font-mono text-xs">
              {result.failures.slice(0, 50).map((f) => <li key={f.evidence_id}>{problemText[f.problem]} · {f.evidence_id}</li>)}
            </ul>
          </Alert>
        ))}
      <Button onClick={verify} disabled={busy}>{busy ? `Verifying… ${progress ?? 0} checked` : "Verify all evidence"}</Button>
      <p className="text-xs text-muted">Re-reads every stored item and recomputes its hash. Runs only when you press the button; each run is recorded in the audit log.</p>
    </div>
  );
}
