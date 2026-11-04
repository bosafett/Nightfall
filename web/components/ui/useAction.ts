"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

/** Runs an async action with busy/error state, then refreshes server data. */
export function useAction() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run<T>(fn: () => Promise<T>, opts: { refresh?: boolean } = {}): Promise<T | undefined> {
    setBusy(true);
    setError(null);
    try {
      const result = await fn();
      if (opts.refresh !== false) router.refresh();
      return result;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong.");
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  return { busy, error, setError, run };
}
