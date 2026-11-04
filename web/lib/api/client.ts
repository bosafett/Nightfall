"use client";

import { parseError } from "./errors";

/** Browser-side calls go to same-origin /api/*, proxied to the API by Next rewrites. */
export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: init.method ?? "GET",
    headers: init.body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    credentials: "same-origin",
    cache: "no-store",
  });
  const data: unknown = await res.json().catch(() => null);
  if (!res.ok) throw parseError(res.status, data);
  return data as T;
}
