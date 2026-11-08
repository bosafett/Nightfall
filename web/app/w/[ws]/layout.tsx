import Image from "next/image";
import { notFound, redirect } from "next/navigation";
import { apiGet, healthOrNull } from "@/lib/api/server";
import type { Health, Me, ShieldAlert, WarRoomSummary, Watchtower } from "@/lib/api/types";
import { mfaRequired } from "@/lib/labels";
import { MobileNav } from "@/components/shell/MobileNav";
import { SidebarContent } from "@/components/shell/SidebarContent";
import { UserMenu } from "@/components/shell/UserMenu";
import { ApprovalsBell } from "@/components/shell/ApprovalsBell";
import { StepUpDialog } from "@/components/shell/StepUpDialog";
import { Badge } from "@/components/ui/primitives";
import pkg from "@/package.json";

/** Read from the hosting platform's own variable (Vercel sets VERCEL_ENV); nothing new to configure. */
const ENV = process.env.VERCEL_ENV ?? (process.env.NODE_ENV === "production" ? "production" : "development");
const envBadge = ENV === "production"
  ? <Badge tone="gray">Production</Badge>
  : ENV === "preview" ? <Badge tone="yellow">Preview</Badge> : <Badge tone="blue">Development</Badge>;

export default async function WorkspaceLayout({ children, params }: { children: React.ReactNode; params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [me, health] = await Promise.all([apiGet<Me>("/auth/me"), healthOrNull<Health>()]);
  const membership = me.workspaces.find((w) => w.id === ws);
  if (!membership) notFound();
  if (mfaRequired(membership.role) && !me.session.mfa_verified) redirect("/account/security");
  const seesIntegrity = membership.role === "owner" || membership.role === "admin";
  const [bell, tower, openAlerts] = await Promise.all([
    apiGet<WarRoomSummary>(`/workspaces/${ws}/war-room/summary`).catch(() => null),
    seesIntegrity ? apiGet<Watchtower>(`/workspaces/${ws}/watchtower`).catch(() => null) : null,
    apiGet<ShieldAlert[]>(`/workspaces/${ws}/alerts?state=open&limit=500`).catch(() => []),
  ]);
  const counts = { alerts: openAlerts.length };
  const lab = tower?.lab ?? null;

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[240px_minmax(0,1fr)]">
      <aside className="sticky top-0 hidden h-screen border-r border-border bg-surface lg:block">
        <SidebarContent ws={ws} health={health} lab={lab} version={pkg.version} counts={counts} />
      </aside>
      <div className="min-w-0">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-border bg-bg/90 px-4 py-3 backdrop-blur sm:px-6">
          <MobileNav ws={ws} health={health} lab={lab} version={pkg.version} counts={counts} />
          <span className="flex items-center gap-2 lg:hidden">
            <Image src="/nightfall-mark.svg" alt="" width={28} height={25} />
            <span className="font-bold tracking-[0.12em] text-crimson-text">JANUS</span>
          </span>
          <p className="hidden flex-1 truncate text-lg tracking-wide text-muted md:block">
            Understand. Investigate. Validate. Defend.
          </p>
          <div className="ml-auto flex items-center gap-3">
            <span className="hidden items-center gap-2 sm:flex" data-testid="environment">
              <span className="max-w-40 truncate text-xs text-muted" title="Active workspace">{membership.name}</span>
              {envBadge}
            </span>
            <ApprovalsBell ws={ws} summary={bell} />
            <UserMenu name={me.user.display_name} email={me.user.email} role={membership.role} workspace={membership.name} />
          </div>
        </header>
        <main className="px-4 py-6 sm:px-6 lg:px-8">{children}</main>
        <StepUpDialog />
      </div>
    </div>
  );
}
