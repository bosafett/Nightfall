"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

/**
 * Re-fetches server data every few seconds while something is still queued or running.
 * With `ws` set it also nudges the job queue first: on serverless hosting there is no
 * worker loop, so open operation pages keep it moving. Elsewhere the API answers 404 and
 * the nudge is ignored.
 */
export function AutoRefresh({ active, ws, intervalMs = 3000 }: { active: boolean; ws?: string; intervalMs?: number }) {
  const router = useRouter();
  useEffect(() => {
    if (!active) return;
    let busy = false;
    let nudge = Boolean(ws);
    const t = setInterval(async () => {
      if (busy) return;
      busy = true;
      try {
        if (nudge) {
          const res = await fetch(`/api/workspaces/${ws}/worker/run`, { method: "POST", credentials: "same-origin" }).catch(() => null);
          if (res?.status === 404) nudge = false;
        }
        router.refresh();
      } finally {
        busy = false;
      }
    }, intervalMs);
    return () => clearInterval(t);
  }, [active, ws, intervalMs, router]);
  return active ? <p className="text-xs text-muted" aria-live="polite">Updating while collection runs…</p> : null;
}
