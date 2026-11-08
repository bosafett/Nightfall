import type { Tone } from "@/components/ui/primitives";

export const severityTone: Record<string, Tone> = { critical: "crimson", high: "orange", medium: "yellow", low: "blue", info: "gray" };
export const kindLabel: Record<string, string> = {
  "cert.expiring": "Certificate expiring", "cert.changed": "Certificate changed", "tls.weakened": "TLS weakened",
  "headers.regressed": "Headers got worse", "ct.new_names": "New names in certificate logs", "dns.changed": "DNS changed",
  "finding.reopened": "Finding came back", "monitor.failed": "Check didn't run", "monitor.expiring": "Authorization expiring",
  "monitor.ended": "Monitoring stopped",
};
export const checkLabel: Record<string, string> = {
  ct: "Certificate-transparency names (passive)", dns: "DNS records (passive)", tls: "TLS configuration (low)", headers: "Security headers (low)",
};
export const endedLabel: Record<string, string> = { revoked: "Revoked", expired: "Expired", renewed: "Renewed", scope_changed: "Scope changed" };
