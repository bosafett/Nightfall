import Link from "next/link";
import type { AssessmentItem, Overview, OverviewWindow } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { assessmentTypeLabel } from "@/lib/labels";
import { Icon } from "@/components/ui/Icon";
import { Panel, cx } from "@/components/ui/primitives";
import { ProjectStatusBadge } from "@/components/registry/StatusBadge";
import { SeverityBadge, StatusBadge } from "@/components/findings/Badges";
import { SEVERITIES } from "@/lib/labels";

export const WINDOWS: OverviewWindow[] = ["1h", "24h", "7d", "30d"];
const windowText: Record<OverviewWindow, string> = { "1h": "last hour", "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days" };

export function WindowPicker({ ws, current }: { ws: string; current: OverviewWindow }) {
  return (
    <nav aria-label="Time window" className="flex gap-1.5">
      {WINDOWS.map((w) => (
        <Link key={w} href={`/w/${ws}?window=${w}`} aria-current={w === current ? "true" : undefined}
          className={cx("rounded-md border px-3 py-1.5 font-mono text-sm tabular",
            w === current ? "border-crimson bg-crimson-strong text-white" : "border-border-strong text-muted hover:text-text")}>
          {w}
        </Link>
      ))}
    </nav>
  );
}

type KpiProps = { label: string; icon: Parameters<typeof Icon>[0]["name"]; tone: string } & (
  | { value: number; detail: string }
  | { unavailablePhase: number }
);

export function KpiCard(props: KpiProps) {
  const unavailable = "unavailablePhase" in props;
  return (
    <div className="flex items-center gap-4 rounded-lg border border-border bg-surface p-4" data-testid={`kpi-${props.label}`}>
      <span className={cx("grid size-12 shrink-0 place-items-center rounded-full border", unavailable ? "border-border-strong text-faint" : props.tone)}>
        <Icon name={props.icon} className="size-6" />
      </span>
      <div className="min-w-0">
        <p className="text-sm text-muted">{props.label}</p>
        {unavailable ? (
          <>
            <p className="font-mono text-3xl text-muted tabular" aria-label="Not tracked yet">—</p>
            <p className="text-xs text-muted">Tracked from phase {props.unavailablePhase}</p>
          </>
        ) : (
          <>
            <p className="font-mono text-3xl tabular">{props.value}</p>
            <p className="text-xs text-muted">{props.detail}</p>
          </>
        )}
      </div>
    </div>
  );
}

export function KpiRow({ overview }: { overview: Overview }) {
  const p = overview.projects;
  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard label="Active projects" icon="target" tone="border-crimson/60 text-crimson-text" value={p.active}
        detail={`${p.started_in_window} started in the ${windowText[overview.window]} · ${p.open} open`} />
      <KpiCard label="Critical findings" icon="findings" tone="border-crimson/60 text-crimson-text" value={overview.critical_findings.open_critical}
        detail={`open · ${overview.critical_findings.new_in_window} new in the ${windowText[overview.window]}`} />
      <KpiCard label="Assets discovered" icon="graph" tone="border-blue/60 text-blue-text" value={overview.assets.total}
        detail={`${overview.assets.new_in_window} new in the ${windowText[overview.window]}`} />
      <KpiCard label="Operations" icon="warroom" tone="border-green/60 text-green" value={overview.operations.in_window}
        detail={`in the ${windowText[overview.window]} · ${overview.operations.pending} pending${overview.operations.awaiting_approval ? ` · ${overview.operations.awaiting_approval} awaiting approval` : ""}${overview.operations.failed_in_window ? ` · ${overview.operations.failed_in_window} failed` : ""}`} />
    </div>
  );
}

export function ActiveAssessments({ ws, items, now }: { ws: string; items: AssessmentItem[]; now: Date }) {
  return (
    <Panel title="Active assessments" actions={<Link href={`/w/${ws}/targets`} className="text-sm text-crimson-text hover:underline">Target Registry</Link>}>
      {items.length === 0 ? (
        <div className="py-8 text-center">
          <p className="font-medium">No open assessments</p>
          <p className="mt-1 text-sm text-muted">Projects in planning, active or paused status show here.</p>
        </div>
      ) : (
        <ul className="-my-2 divide-y divide-border">
          {items.map((a) => (
            <li key={a.id} className="py-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <Link href={`/w/${ws}/targets/${a.organization_id}/projects/${a.id}`} className="block truncate font-medium hover:text-crimson-text">
                    {a.organization_name} — {a.name}
                  </Link>
                  <p className="text-sm text-muted">{assessmentTypeLabel[a.assessment_type]}</p>
                </div>
                <ProjectStatusBadge status={a.status} />
              </div>
              <p className="mt-1 font-mono text-xs text-muted tabular">
                {a.started_at ? `Started ${formatRelative(a.started_at, now)}` : "Not started"} · Last activity {formatRelative(a.last_activity_at, now)}
              </p>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function ComingPanel({ title, phase, body }: { title: string; phase: number; body: string }) {
  return (
    <Panel title={title}>
      <div className="py-6 text-center">
        <p className="font-medium text-muted">Arrives in phase {phase}</p>
        <p className="mx-auto mt-1 max-w-xs text-sm text-muted">{body}</p>
      </div>
    </Panel>
  );
}

export function RecentFindings({ ws, overview, now }: { ws: string; overview: Overview; now: Date }) {
  const items = overview.recent_findings.items;
  return (
    <Panel title="Recent findings" actions={<Link href={`/w/${ws}/findings`} className="text-sm text-crimson-text hover:underline">All findings</Link>}>
      {items.length === 0 ? <p className="py-6 text-center text-sm text-muted">No findings yet.</p> : (
        <ul className="-my-2 divide-y divide-border">
          {items.map((f) => (
            <li key={f.id} className="flex items-center gap-3 py-2.5">
              <SeverityBadge severity={f.severity} />
              <div className="min-w-0 flex-1">
                <Link href={`/w/${ws}/findings/${f.id}`} className="block truncate text-sm hover:text-crimson-text">{f.title}</Link>
                <span className="block truncate font-mono text-xs text-muted">{f.ref}{f.asset_value && ` · ${f.asset_value}`} · {formatRelative(f.first_observed_at, now)}</span>
              </div>
              <StatusBadge status={f.validation_status} />
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

const barColor: Record<string, string> = { critical: "bg-crimson", high: "bg-orange", medium: "bg-yellow", low: "bg-blue", info: "bg-gray" };

/** Severity breakdown of open findings. Deliberately no blended "risk score". */
export function RiskOverview({ ws, overview }: { ws: string; overview: Overview }) {
  const r = overview.risk;
  const max = Math.max(1, ...Object.values(r.open_by_severity));
  return (
    <Panel title="Risk overview">
      {r.open_total === 0 ? <p className="py-6 text-center text-sm text-muted">No open findings.</p> : (
        <>
          <ul className="space-y-2" aria-label="Open findings by severity">
            {SEVERITIES.map((s) => {
              const n = r.open_by_severity[s] ?? 0;
              return (
                <li key={s}>
                  <Link href={`/w/${ws}/findings?severity=${s}`} className="grid grid-cols-[6.5rem_1fr_2.5rem] items-center gap-3 text-sm hover:text-crimson-text">
                    <SeverityBadge severity={s} />
                    <span className="h-2 rounded bg-surface-2"><span className={cx("block h-2 rounded", barColor[s])} style={{ width: `${(n / max) * 100}%` }} /></span>
                    <span className="text-right font-mono tabular">{n}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
          <p className="mt-4 text-xs text-muted">
            <span className="font-mono tabular text-text">{r.open_total}</span> open: <span className="font-mono tabular">{r.validated}</span> validated,{" "}
            <span className="font-mono tabular">{r.unverified}</span> unverified, <span className="font-mono tabular">{r.hypotheses}</span> hypotheses.
          </p>
        </>
      )}
    </Panel>
  );
}
