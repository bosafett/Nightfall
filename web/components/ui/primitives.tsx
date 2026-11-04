import Link from "next/link";
import type { ComponentProps, ReactNode } from "react";
import { Icon } from "./Icon";

const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");

type Variant = "primary" | "secondary" | "danger" | "ghost";
const variants: Record<Variant, string> = {
  primary: "bg-crimson-strong text-white hover:bg-crimson border-transparent",
  secondary: "bg-surface-2 text-text border-border-strong hover:border-gray",
  danger: "bg-transparent text-crimson-text border-crimson/60 hover:bg-crimson/10",
  ghost: "bg-transparent text-muted border-transparent hover:text-text",
};
const btnBase =
  "inline-flex items-center justify-center gap-2 rounded-md border px-3.5 py-2 text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";

export function Button({ variant = "secondary", className, ...props }: ComponentProps<"button"> & { variant?: Variant }) {
  return <button type="button" className={cx(btnBase, variants[variant], className)} {...props} />;
}

export function LinkButton({ variant = "secondary", className, ...props }: ComponentProps<typeof Link> & { variant?: Variant }) {
  return <Link className={cx(btnBase, variants[variant], className)} {...props} />;
}

export function Panel({ title, actions, children, className }: { title?: string; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cx("rounded-lg border border-border bg-surface", className)}>
      {title && (
        <header className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-border px-4 py-3">
          <h2 className="text-base font-semibold tracking-wide">{title}</h2>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-wide sm:text-3xl">{title}</h1>
        {subtitle && <p className="mt-1 text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center rounded-lg border border-dashed border-border-strong px-6 py-12 text-center">
      <p className="text-lg font-medium">{title}</p>
      <p className="mt-2 max-w-md text-sm text-muted">{body}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export type Tone = "crimson" | "orange" | "yellow" | "blue" | "green" | "gray";
const tones: Record<Tone, string> = {
  crimson: "text-crimson-text border-crimson/50 bg-crimson/10",
  orange: "text-orange border-orange/50 bg-orange/10",
  yellow: "text-yellow border-yellow/50 bg-yellow/10",
  blue: "text-blue-text border-blue/50 bg-blue/10",
  green: "text-green border-green/50 bg-green/10",
  gray: "text-gray border-border-strong bg-surface-2",
};

/** Always carries a text label: colour is never the only signal. */
export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={cx("inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium", tones[tone])}>{children}</span>;
}

export function StatusDot({ ok }: { ok: boolean }) {
  return <span aria-hidden="true" className={cx("inline-block size-2 rounded-full", ok ? "bg-green" : "bg-crimson")} />;
}

export function Alert({ tone = "crimson", children }: { tone?: "crimson" | "yellow" | "green" | "blue"; children: ReactNode }) {
  return (
    <div role={tone === "crimson" ? "alert" : "status"} className={cx("flex gap-2 rounded-md border px-3 py-2 text-sm", tones[tone])}>
      <Icon name={tone === "green" ? "check" : "alert"} className="mt-0.5 size-4 shrink-0" />
      <div>{children}</div>
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("animate-pulse rounded bg-surface-2", className)} />;
}

const fieldCls =
  "w-full rounded-md border border-border-strong bg-bg px-3 py-2 text-sm text-text placeholder:text-faint focus:border-crimson focus:outline-none";

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div>
      <label className="block">
        <span className="mb-1 block text-sm font-medium">{label}</span>
        {children}
      </label>
      {hint && <p className="mt-1 text-xs text-muted">{hint}</p>}
    </div>
  );
}

export function Input(props: ComponentProps<"input">) {
  return <input {...props} className={cx(fieldCls, props.className)} />;
}

export function Textarea(props: ComponentProps<"textarea">) {
  return <textarea rows={3} {...props} className={cx(fieldCls, props.className)} />;
}

export function Select(props: ComponentProps<"select">) {
  return <select {...props} className={cx(fieldCls, props.className)} />;
}

export function DataTable({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="-mx-4 overflow-x-auto">
      <table className="w-full min-w-[560px] text-left text-sm">
        <thead className="text-xs uppercase tracking-wider text-muted">
          <tr>{head.map((h) => <th key={h} scope="col" className="px-4 py-2 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-border">{children}</tbody>
      </table>
    </div>
  );
}

export { cx };
