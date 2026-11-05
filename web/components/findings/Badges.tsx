import type { Severity, ValidationStatus } from "@/lib/api/types";
import { severityLabel, statusHelp, statusLabel } from "@/lib/labels";
import { cx } from "@/components/ui/primitives";

/** Severity: colour + distinct shape + text, so it reads without colour vision. */
const sev: Record<Severity, { cls: string; shape: React.ReactNode }> = {
  critical: { cls: "text-crimson-text border-crimson/60 bg-crimson/10", shape: <path d="M6 0l6 6-6 6-6-6z" /> },
  high: { cls: "text-orange border-orange/60 bg-orange/10", shape: <path d="M6 0l6 11H0z" /> },
  medium: { cls: "text-yellow border-yellow/60 bg-yellow/10", shape: <circle cx="6" cy="6" r="5.5" /> },
  low: { cls: "text-blue-text border-blue/60 bg-blue/10", shape: <path d="M0 1h12L6 12z" /> },
  info: { cls: "text-gray border-border-strong bg-surface-2", shape: <rect x="1" y="1" width="10" height="10" /> },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = sev[severity];
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-semibold", s.cls)}>
      <svg viewBox="0 0 12 12" className="size-2.5 fill-current" aria-hidden="true">{s.shape}</svg>
      {severityLabel[severity]}
    </span>
  );
}

/** Validation status. Hypotheses use a dashed border so they never look like confirmed findings. */
const st: Record<ValidationStatus, string> = {
  hypothesis: "border-dashed border-gray text-muted",
  unverified: "border-border-strong text-text",
  validated: "border-green bg-green/15 text-green",
  false_positive: "border-border-strong text-muted line-through",
  remediated: "border-green/60 text-green",
};

export function StatusBadge({ status }: { status: ValidationStatus }) {
  return (
    <span title={statusHelp[status]} className={cx("inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-medium", st[status])}>
      {status === "validated" && <svg viewBox="0 0 12 12" className="size-2.5 stroke-current" fill="none" strokeWidth="2" aria-hidden="true"><path d="M2 6l3 3 5-6" /></svg>}
      {statusLabel[status]}
    </span>
  );
}
