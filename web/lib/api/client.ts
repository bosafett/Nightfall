"use client";

import { ApiError, parseError } from "./errors";

type StepUp = () => Promise<boolean>;
let stepUpHandler: StepUp | null = null;

/** Registered by <StepUpDialog/>: asks for a fresh authenticator code (D1, 15-minute window). */
export function setStepUpHandler(h: StepUp | null) {
  stepUpHandler = h;
}

/**
 * Browser-side calls go to same-origin /api/*, proxied to the API by Next rewrites.
 * When the API answers step_up_required, the operator confirms a fresh two-factor code and
 * the call is retried once. The server alone decides whether the verification is fresh.
 */
export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  try {
    return await call<T>(path, init);
  } catch (e) {
    if (e instanceof ApiError && e.code === "step_up_required" && stepUpHandler && (await stepUpHandler())) {
      return call<T>(path, init);
    }
    throw e;
  }
}

async function call<T>(path: string, init: { method?: string; body?: unknown }): Promise<T> {
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
