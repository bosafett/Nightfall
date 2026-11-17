import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { ShieldAlert, SignInAlert } from "@/lib/api/types";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { AlertList } from "@/components/shield/AlertList";
import { SignInAlertList } from "@/components/shield/SignInAlertList";
import { PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Alerts & Detection" };
const STATES = { active: "Open and acknowledged", open: "Open", acknowledged: "Acknowledged", resolved: "Resolved" } as const;

export default async function AlertsPage({ params, searchParams }: {
  params: Promise<{ ws: string }>; searchParams: Promise<{ state?: string }>;
}) {
  const { ws } = await params;
  const { state: raw } = await searchParams;
  const state = raw && raw in STATES ? raw : "active";
  const [alerts, me] = await Promise.all([apiGet<ShieldAlert[]>(`/workspaces/${ws}/alerts?state=${state}&limit=200`), membership(ws)]);
  const signIn = can.manageMembers(me.role) ? await apiGet<SignInAlert[]>(`/workspaces/${ws}/sign-in-alerts`) : null;
  return (
    <>
      <PageHeader title="Alerts & Detection" subtitle="Raised by comparing each scheduled check with the previous one. A person acknowledges and resolves them." />
      <nav className="mb-4 flex flex-wrap gap-3 text-sm" aria-label="Alert state">
        {Object.entries(STATES).map(([k, label]) => (
          <Link key={k} href={`/w/${ws}/shield/alerts?state=${k}`} aria-current={k === state ? "page" : undefined}
            className={k === state ? "text-text underline" : "text-muted hover:text-text"}>{label}</Link>
        ))}
      </nav>
      <Panel><AlertList ws={ws} alerts={alerts} canAct={can.editFindings(me.role)} /></Panel>
      {signIn && (
        <Panel title={`Sign-in alerts for members · ${signIn.filter((a) => a.state === "open").length} open`} className="mt-6">
          <p className="mb-3 text-sm text-muted">Attacks on the accounts of this workspace&apos;s members. Sign-in pauses automatically after repeated failures; only the member can acknowledge.</p>
          <SignInAlertList alerts={signIn} own={false} />
        </Panel>
      )}
    </>
  );
}
