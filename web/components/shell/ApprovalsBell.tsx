import Link from "next/link";
import type { WarRoomSummary } from "@/lib/api/types";
import { cx } from "@/components/ui/primitives";

/** Header bell: operations waiting for a decision. The number is what *you* can decide. */
export function ApprovalsBell({ ws, summary }: { ws: string; summary: WarRoomSummary | null }) {
  const yours = summary?.awaiting_you ?? 0;
  const label = !summary
    ? "Approvals"
    : yours > 0
      ? `${yours} operation${yours === 1 ? "" : "s"} waiting for your decision`
      : summary.awaiting_total > 0
        ? `${summary.awaiting_total} waiting for someone else's decision`
        : "No operations waiting for approval";
  return (
    <Link href={`/w/${ws}/war-room`} aria-label={label} title={label}
      className={cx("relative inline-flex h-9 w-9 items-center justify-center rounded-md border",
        yours > 0 ? "border-crimson text-crimson-text" : "border-border-strong text-muted hover:text-text")}>
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
        <path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.94 1.94 0 0 0 3.4 0" />
      </svg>
      {yours > 0 && (
        <span className="absolute -right-1.5 -top-1.5 min-w-5 rounded-full bg-crimson-strong px-1 text-center font-mono text-xs leading-5 text-white tabular">
          {yours > 99 ? "99+" : yours}
        </span>
      )}
    </Link>
  );
}
