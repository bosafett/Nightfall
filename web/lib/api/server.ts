import { cookies } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { ApiError, parseError } from "./errors";

// Self-hosted: the API on loopback. Vercel: the backend service's private binding URL.
const API = (process.env.API_INTERNAL_URL ?? "http://127.0.0.1:8000").replace(/\/+$/, "");
export const SESSION_COOKIE = "nf_session";

async function call(path: string): Promise<Response> {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  return fetch(`${API}/api${path}`, {
    headers: token ? { cookie: `${SESSION_COOKIE}=${token}` } : {},
    cache: "no-store",
  });
}

/**
 * Server-side GET with the caller's session. Handles the common outcomes:
 * 401 → sign-in, MFA required → account security, 404 → not-found page.
 */
export async function apiGet<T>(path: string): Promise<T> {
  const res = await call(path);
  const data: unknown = await res.json().catch(() => null);
  if (res.ok) return data as T;
  const err = parseError(res.status, data);
  if (res.status === 401) redirect("/login");
  if (err.code === "mfa_required") redirect("/account/security");
  if (res.status === 404) notFound();
  throw err;
}

/** Like apiGet but returns null instead of redirecting when signed out. */
export async function apiGetOptional<T>(path: string): Promise<T | null> {
  const res = await call(path);
  if (res.status === 401) return null;
  const data: unknown = await res.json().catch(() => null);
  if (!res.ok) throw parseError(res.status, data);
  return data as T;
}

export async function healthOrNull<T>(): Promise<T | null> {
  try {
    const res = await fetch(`${API}/api/health`, { cache: "no-store", signal: AbortSignal.timeout(3000) });
    return res.ok ? ((await res.json()) as T) : null;
  } catch {
    return null;
  }
}

export { ApiError };
