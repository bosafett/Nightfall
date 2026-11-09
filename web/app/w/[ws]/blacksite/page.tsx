import type { Metadata } from "next";
import { apiGet } from "@/lib/api/server";
import type { Me, Watchtower } from "@/lib/api/types";
import { roleLabel } from "@/lib/labels";
import { Icon } from "@/components/ui/Icon";
import { Badge, LinkButton, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "BLACKSITE" };

/**
 * The probe deck has no controls here: probes run only from the BLACKSITE console on the isolated
 * lab machine. The status line is the lab worker's real last check-in (WATCHTOWER), not a claim
 * about the console's own switches, which JANUS can't see.
 * BLACK OPS (reviewed playbooks built from the existing scope-checked operations) is linked for
 * owners. The backend remains the authority on who may use either.
 */
export default async function Blacksite({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const me = await apiGet<Me>("/auth/me");
  const role = me.workspaces.find((w) => w.id === ws)?.role;
  const owner = role === "owner";
  const lab = owner ? (await apiGet<Watchtower>(`/workspaces/${ws}/watchtower`).catch(() => null))?.lab : null;
  const connected = lab != null && lab.status !== "never";
  const seen = lab?.last_seen_at ? new Date(lab.last_seen_at).toISOString().slice(0, 16).replace("T", " ") + " UTC" : "";
  const status = !connected ? "Not configured" : lab.status === "online" ? "Lab worker online" : `Lab worker offline (last seen ${seen})`;

  return (
    <>
      <PageHeader title="BLACKSITE" subtitle="Isolated execution environment" actions={<Badge tone="crimson">Restricted</Badge>} />
      {owner && (
        <Panel title="Lab console" className="mb-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" data-testid="blacksite-console">
            <p className="text-sm text-muted">
              Lab work is requested and approved in the BLACKSITE console, which runs only on the lab machine. This link works
              only on that machine, while the console is running, and you sign in there separately.
            </p>
            <LinkButton href="http://127.0.0.1:8443/" target="_blank" rel="noopener noreferrer" prefetch={false} className="shrink-0">
              Open BLACKSITE console
            </LinkButton>
          </div>
        </Panel>
      )}
      {owner && (
        <Panel title="BLACK OPS" className="mb-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" data-testid="blackops-entry">
            <p className="text-sm text-muted">
              Reviewed, versioned assessment playbooks. Each step is an ordinary scope-checked operation: preflight first,
              explicit approval above passive, results into BLACK ICE.
            </p>
            <LinkButton href={`/w/${ws}/blacksite/ops`} variant="primary">Open playbook library</LinkButton>
          </div>
        </Panel>
      )}
      <Panel title="Probe deck">
        <div className="flex flex-col items-center px-4 py-10 text-center" data-testid="blacksite-restricted">
          <span className="grid size-14 place-items-center rounded-full border border-crimson/60 text-crimson-text">
            <Icon name="lock" className="size-7" />
          </span>
          {owner && connected ? (
            <>
              <p className="mt-4 text-lg font-medium">Probes run from the BLACKSITE console</p>
              <p className="mt-2 max-w-lg text-sm text-muted">
                The lab machine is connected. Probes are requested, approved and started in the console on that machine, never
                from here, and only while its recorded review is in effect.
              </p>
            </>
          ) : owner ? (
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
            <dt className="text-muted">Status</dt>
            <dd className={`font-mono ${lab?.status === "online" ? "text-green" : "text-orange"}`} data-testid="blacksite-status">{owner ? status : "Owner only"}</dd>
          </dl>
        </div>
      </Panel>
    </>
  );
}
