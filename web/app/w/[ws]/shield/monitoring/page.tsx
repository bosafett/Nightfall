import type { Metadata } from "next";
import { apiGet } from "@/lib/api/server";
import type { MonitorAuthorization, Project, ScopeVersion, ShieldOverview } from "@/lib/api/types";
import { membership } from "@/lib/workspace";
import { Authorizations } from "@/components/shield/Authorizations";
import { PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Monitoring" };

export default async function MonitoringPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [items, projects, overview, me] = await Promise.all([
    apiGet<MonitorAuthorization[]>(`/workspaces/${ws}/monitor-authorizations`),
    apiGet<Project[]>(`/workspaces/${ws}/projects`),
    apiGet<ShieldOverview>(`/workspaces/${ws}/shield/overview`),
    membership(ws),
  ]);
  const scopes: Record<string, ScopeVersion | null> = {};
  if (me.role === "owner") {
    await Promise.all(projects.map(async (p) => {
      const versions = await apiGet<ScopeVersion[]>(`/workspaces/${ws}/projects/${p.id}/scopes`);
      scopes[p.id] = versions.find((v) => v.status === "active") ?? null;
    }));
  }
  return (
    <>
      <PageHeader title="Monitoring" subtitle="Standing authorizations for daily passive and low-risk checks of your own assets. 30 days at most; the owner authorizes with two-factor." />
      <Panel>
        <Authorizations ws={ws} items={items} projects={projects} scopes={scopes} canManage={me.role === "owner"}
          cap={overview.daily_cap} used={overview.checks_per_day_authorized} />
      </Panel>
    </>
  );
}
