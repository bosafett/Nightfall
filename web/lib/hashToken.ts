/** Reads `#token=...` from the URL fragment (never sent to servers or in Referer). */
export function readHashToken(): string | null {
  if (typeof window === "undefined") return null;
  const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
  return token && /^[A-Za-z0-9_-]{20,128}$/.test(token) ? token : null;
}
