import type { Metadata } from "next";
import { apiGet } from "@/lib/api/server";
import type { Me } from "@/lib/api/types";
import { roleLabel } from "@/lib/labels";
import { Icon } from "@/components/ui/Icon";
import { Badge, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "BLACKSITE" };

/**
 * Restricted-access state only. BLACKSITE will run on the isolated lab machine, not on
 * Vercel-hosted execution; until that environment is configured this page exposes no
 * controls. The backend remains the authority on who may use it.
 */
export default async function Blacksite({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const me = await apiGet<Me>("/auth/me");
  const role = me.workspaces.find((w) => w.id === ws)?.role;
  const owner = role === "owner";

  return (
    <>
      <PageHeader title="BLACKSITE" subtitle="Isolated execution environment" actions={<Badge tone="crimson">Restricted</Badge>} />
      <Panel>
        <div className="flex flex-col items-center px-4 py-10 text-center" data-testid="blacksite-restricted">
          <span className="grid size-14 place-items-center rounded-full border border-crimson/60 text-crimson-text">
            <Icon name="lock" className="size-7" />
          </span>
          {owner ? (
            <>
              <p className="mt-4 text-lg font-medium">Execution environment not configured</p>
              <p className="mt-2 max-w-lg text-sm text-muted">
                BLACKSITE runs on the isolated lab machine, never on the hosted platform. Nothing here can start a probe until
                that environment is connected and verified.
              </p>
            </>
          ) : (
            <>
              <p className="mt-4 text-lg font-medium">Restricted access</p>
              <p className="mt-2 max-w-lg text-sm text-muted">
                BLACKSITE is limited to workspace owners. Your role is {role ? roleLabel[role] : "unknown"}; ask an owner if you need access.
              </p>
            </>
          )}
          <dl className="mt-6 grid w-full max-w-md grid-cols-2 gap-2 text-left text-xs">
            <dt className="text-muted">Access</dt><dd className="font-mono">Owner only</dd>
            <dt className="text-muted">Environment</dt><dd className="font-mono">Isolated lab</dd>
            <dt className="text-muted">Status</dt><dd className="font-mono text-orange">Not configured</dd>
          </dl>
        </div>
      </Panel>
    </>
  );
}
