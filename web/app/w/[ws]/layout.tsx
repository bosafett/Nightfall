import Image from "next/image";
import { notFound, redirect } from "next/navigation";
import { apiGet, healthOrNull } from "@/lib/api/server";
import type { Health, Me } from "@/lib/api/types";
import { mfaRequired } from "@/lib/labels";
import { MobileNav } from "@/components/shell/MobileNav";
import { SidebarContent } from "@/components/shell/SidebarContent";
import { UserMenu } from "@/components/shell/UserMenu";
import pkg from "@/package.json";

export default async function WorkspaceLayout({ children, params }: { children: React.ReactNode; params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [me, health] = await Promise.all([apiGet<Me>("/auth/me"), healthOrNull<Health>()]);
  const membership = me.workspaces.find((w) => w.id === ws);
  if (!membership) notFound();
  if (mfaRequired(membership.role) && !me.session.mfa_verified) redirect("/account/security");

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[240px_minmax(0,1fr)]">
      <aside className="sticky top-0 hidden h-screen border-r border-border bg-surface lg:block">
        <SidebarContent ws={ws} health={health} version={pkg.version} />
      </aside>
      <div className="min-w-0">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-border bg-bg/90 px-4 py-3 backdrop-blur sm:px-6">
          <MobileNav ws={ws} health={health} version={pkg.version} />
          <span className="flex items-center gap-2 lg:hidden">
            <Image src="/nightfall-mark.svg" alt="" width={28} height={25} />
            <span className="font-bold tracking-[0.12em] text-crimson-text">NIGHTFALL</span>
          </span>
          <p className="hidden flex-1 truncate text-lg tracking-wide text-muted md:block">
            Understand. Investigate. Validate. Defend.
          </p>
          <div className="ml-auto">
            <UserMenu name={me.user.display_name} email={me.user.email} role={membership.role} workspace={membership.name} />
          </div>
        </header>
        <main className="px-4 py-6 sm:px-6 lg:px-8">{children}</main>
      </div>
    </div>
  );
}
