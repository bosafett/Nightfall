import Link from "next/link";
import type { AssessmentItem, Overview, OverviewWindow } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { assessmentTypeLabel } from "@/lib/labels";
import { Icon } from "@/components/ui/Icon";
import { Panel, cx } from "@/components/ui/primitives";
import { ProjectStatusBadge } from "@/components/registry/StatusBadge";

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
      <KpiCard label="Critical findings" icon="findings" tone="" unavailablePhase={overview.critical_findings.phase} />
      <KpiCard label="Assets discovered" icon="graph" tone="" unavailablePhase={overview.assets.phase} />
      <KpiCard label="Operations" icon="warroom" tone="" unavailablePhase={overview.operations.phase} />
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
