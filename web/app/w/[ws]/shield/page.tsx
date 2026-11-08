import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { ShieldOverview } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { AlertList } from "@/components/shield/AlertList";
import { severityTone } from "@/components/shield/labels";
import { Alert, Badge, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "AEGIS Overview" };

export default async function AegisOverview({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [o, me] = await Promise.all([apiGet<ShieldOverview>(`/workspaces/${ws}/shield/overview`), membership(ws)]);
  const late = o.checks_waiting.filter((c) => c.hours_waiting >= 6);
  return (
    <>
      <PageHeader title="AEGIS Overview" subtitle="SHIELD: scheduled monitoring of your own assets. Alerts are advice; nothing is changed automatically." />
      {o.authorizations_live === 0 && (
        <Alert tone="yellow">Nothing is monitored. <Link className="underline" href={`/w/${ws}/shield/monitoring`}>Authorize monitoring</Link> to start daily checks.</Alert>
      )}
      <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-5" data-testid="open-alerts">
        {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
          <div key={s} className="rounded-lg border border-border bg-surface p-3">
            <Badge tone={severityTone[s] ?? "gray"}>{s}</Badge>
            <p className="mt-1 text-2xl font-semibold tabular">{o.open_alerts[s] ?? 0}</p>
            <p className="text-xs text-muted">open</p>
          </div>
        ))}
      </div>
      <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Needs attention">
          <AlertList ws={ws} alerts={o.alerts_needing_attention} canAct={can.editFindings(me.role)} />
          <p className="mt-3 text-sm"><Link className="text-muted hover:text-crimson-text" href={`/w/${ws}/shield/alerts`}>All alerts →</Link></p>
        </Panel>
        <Panel title="Monitoring health">
          <dl className="space-y-2 text-sm" data-testid="monitoring-health">
            <div className="flex justify-between"><dt className="text-muted">Live authorizations</dt><dd className="tabular">{o.authorizations_live}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Checks a day (limit)</dt><dd className="tabular">{o.checks_per_day_authorized} / {o.daily_cap}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Ran in the last 24 h</dt><dd className="tabular">{o.checks_ran_24h}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Failed or refused (24 h)</dt><dd className="tabular">{o.checks_failed_24h}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Waiting to run</dt><dd className="tabular">{o.checks_waiting.length}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">Last scheduled</dt><dd className="font-mono text-xs tabular">{formatDateTime(o.last_scheduled_at)}</dd></div>
          </dl>
          {late.length > 0 && (
            <Alert tone="yellow">{late.length} scheduled check(s) have waited over 6 hours. The hosted platform runs a few checks per scheduled call; the rest run when the app is next used.</Alert>
          )}
          {o.authorizations_expiring.length > 0 && (
            <p className="mt-3 text-sm">Expiring within 7 days: {o.authorizations_expiring.map((a) => `${a.project_name} (${formatDateTime(a.expires_at)})`).join("; ")}</p>
          )}
          {o.projects_unmonitored.length > 0 && (
            <p className="mt-3 text-xs text-muted">Not monitored: {o.projects_unmonitored.join(", ")}.</p>
          )}
          <p className="mt-3 text-xs text-muted">Rules {o.rules}. Planned, not built: threat hunting, countermeasures, incident response, recovery.</p>
        </Panel>
      </div>
    </>
  );
}
