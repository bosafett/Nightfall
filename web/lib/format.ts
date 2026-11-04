const dateTime = new Intl.DateTimeFormat("en-US", {
  year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "UTC",
});

/** Stable, timezone-explicit timestamps (server and client render the same string). */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return `${dateTime.format(new Date(iso))} UTC`;
}

const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ["day", 86400], ["hour", 3600], ["minute", 60],
];

export function formatRelative(iso: string, now: Date = new Date()): string {
  const seconds = Math.round((new Date(iso).getTime() - now.getTime()) / 1000);
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size) return rtf.format(Math.round(seconds / size), unit);
  }
  return "just now";
}

/** Groups a base32 TOTP secret for manual entry: "ABCD EFGH ...". */
export function groupSecret(secret: string): string {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}
