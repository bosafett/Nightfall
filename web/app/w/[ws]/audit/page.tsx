import type { Metadata } from "next";
import Link from "next/link";
import { ApiError, apiGet } from "@/lib/api/server";
import type { AuditPage, Watchtower } from "@/lib/api/types";
import { formatDateTime, formatRelative } from "@/lib/format";
import { Alert, Badge, PageHeader, Panel, cx } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Audit Log" };

function entityHref(ws: string, type: string | null, id: string | null): string | null {
  if (!id) return null;
  if (type === "operation") return `/w/${ws}/recon/${id}`;
  if (type === "finding") return `/w/${ws}/findings/${id}`;
  if (type === "agent_task") return `/w/${ws}/agents/${id}`;
  if (type === "report") return `/w/${ws}/reports/${id}`;
  return null;
}

const towerText: Record<string, string> = {
  online: "Online", offline: "Offline", never: "Never connected", on_demand: "On demand",
};

function Integrity({ tower }: { tower: Watchtower }) {
  const now = new Date(tower.checked_at);
  const seen = (iso: string | null | undefined) => (iso ? ` · ${formatRelative(iso, now)}` : "");
  const rows: [string, string, boolean][] = [
    ["Audit writes", tower.audit.status === "ok" ? `Working${seen(tower.audit.last_event_at)}` : "Not permitted", tower.audit.status === "ok"],
    ["Worker", `${towerText[tower.worker.status]}${seen(tower.worker.last_seen_at)}`, tower.worker.status !== "offline"],
    ["Lab worker", `${towerText[tower.lab.status]}${seen(tower.lab.last_seen_at)}`, tower.lab.status !== "offline"],
    ["Failed operations (24h)", String(tower.failed_operations_24h), tower.failed_operations_24h === 0],
  ];
  return (
    <Panel title="Platform integrity">
      <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4" data-testid="integrity">
        {rows.map(([k, v, ok]) => (
          <div key={k}>
            <dt className="text-xs text-muted">{k}</dt>
            <dd className={cx("mt-0.5", ok ? "text-text" : "text-orange")}>{v}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  );
}

export default async function AuditLogPage({ params, searchParams }: {
  params: Promise<{ ws: string }>; searchParams: Promise<{ category?: string; before?: string }>;
}) {
  const { ws } = await params;
  const { category, before } = await searchParams;
  const q = new URLSearchParams();
  if (category) q.set("category", category);
  if (before) q.set("before", before);
  let page: AuditPage;
  let tower: Watchtower | null;
  try {
    [page, tower] = await Promise.all([
      apiGet<AuditPage>(`/workspaces/${ws}/audit${q.size ? `?${q}` : ""}`),
      apiGet<Watchtower>(`/workspaces/${ws}/watchtower`).catch(() => null),
    ]);
  } catch (e) {
    if (e instanceof ApiError && e.status === 403) {
      return (
        <>
          <PageHeader title="Audit Log" />
          <Alert tone="yellow">The audit log is available to workspace owners and admins.</Alert>
        </>
      );
    }
    throw e;
  }
  const filter = (c?: string) => (c ? `/w/${ws}/audit?category=${encodeURIComponent(c)}` : `/w/${ws}/audit`);
  const older = page.next_before
    ? `/w/${ws}/audit?${new URLSearchParams({ ...(category ? { category } : {}), before: page.next_before })}`
    : null;
  return (
    <>
      <PageHeader title="Audit Log" subtitle="Every recorded action in this workspace, newest first. Read-only." />
      <div className="space-y-6">
        {tower && <Integrity tower={tower} />}
        <Panel title="Events">
          <nav aria-label="Filter by category" className="mb-4 flex flex-wrap gap-2 text-sm">
            {[undefined, ...page.categories].map((c) => (
              <Link key={c ?? "all"} href={filter(c)} aria-current={c === category ? "page" : undefined}
                className={cx("rounded-md border px-2.5 py-1", c === category ? "border-crimson bg-crimson/10 text-text" : "border-border text-muted hover:text-text")}>
                {c ?? "All"}
              </Link>
            ))}
          </nav>
          {page.events.length === 0 ? <p className="text-sm text-muted">No events{category ? ` in ${category}` : ""}.</p> : (
            <ul className="-my-2 divide-y divide-border">
              {page.events.map((e) => {
                const href = entityHref(ws, e.entity_type, e.entity_id);
                const details = Object.keys(e.data).length ? JSON.stringify(e.data) : "";
                return (
                  <li key={e.id} className="py-2.5 text-sm">
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="font-mono text-text">{e.action}</span>
                      <Badge tone={e.actor_type === "user" ? "blue" : e.actor_type === "agent" ? "yellow" : "gray"}>{e.actor}</Badge>
                      {href && <Link href={href} className="text-crimson-text hover:underline">{e.entity_type}</Link>}
                      <span className="ml-auto text-xs text-muted tabular">{formatDateTime(e.occurred_at)}{e.ip ? ` · ${e.ip}` : ""}</span>
                    </div>
                    {details && <p className="mt-1 break-all font-mono text-xs text-muted">{details}</p>}
                  </li>
                );
              })}
            </ul>
          )}
          <div className="mt-4 flex gap-4 text-sm">
            {before && <Link href={filter(category)} className="text-crimson-text hover:underline">Newest</Link>}
            {older && <Link href={older} className="text-crimson-text hover:underline">Older</Link>}
          </div>
        </Panel>
      </div>
    </>
  );
}
