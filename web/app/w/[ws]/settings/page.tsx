import type { Metadata } from "next";
import { apiGet } from "@/lib/api/server";
import type { Invite, Me, Member, WorkspaceInfo } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can, roleLabel } from "@/lib/labels";
import { InviteForm, MemberActions, RevokeInvite, WorkspaceName } from "@/components/settings/SettingsForms";
import { Badge, DataTable, LinkButton, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Settings" };

export default async function SettingsPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [workspace, members, me] = await Promise.all([
    apiGet<WorkspaceInfo>(`/workspaces/${ws}`),
    apiGet<Member[]>(`/workspaces/${ws}/members`),
    apiGet<Me>("/auth/me"),
  ]);
  const manage = can.manageMembers(workspace.role);
  const invites = manage ? await apiGet<Invite[]>(`/workspaces/${ws}/invites`) : [];

  return (
    <>
      <PageHeader title="Settings" subtitle={workspace.name}
        actions={<LinkButton href="/account/security">Account security</LinkButton>} />
      <div className="space-y-6">
        {manage && <Panel title="Workspace"><WorkspaceName ws={ws} name={workspace.name} /></Panel>}

        <Panel title="Members">
          <DataTable head={manage ? ["Name", "Role", "Two-factor", "Joined", ""] : ["Name", "Role", "Two-factor", "Joined"]}>
            {members.map((m) => (
              <tr key={m.id}>
                <td className="px-4 py-3">
                  <span className="block font-medium">{m.display_name}{m.user_id === me.user.id && <span className="text-muted"> (you)</span>}</span>
                  <span className="block text-xs text-muted">{m.email}</span>
                </td>
                <td className="px-4 py-3">{roleLabel[m.role]}</td>
                <td className="px-4 py-3">{m.mfa_enabled ? <Badge tone="green">On</Badge> : <Badge tone="gray">Off</Badge>}</td>
                <td className="px-4 py-3 font-mono text-xs text-muted tabular">{formatDateTime(m.joined_at)}</td>
                {manage && (
                  <td className="px-4 py-3">
                    {m.user_id !== me.user.id && can.manage(workspace.role, m.role) && (
                      <MemberActions ws={ws} member={m} actorRole={workspace.role} />
                    )}
                  </td>
                )}
              </tr>
            ))}
          </DataTable>
        </Panel>

        {manage && (
          <Panel title="Invites">
            <InviteForm ws={ws} actorRole={workspace.role} />
            {invites.length > 0 && (
              <div className="mt-6">
                <DataTable head={["Email", "Role", "Expires", ""]}>
                  {invites.map((i) => (
                    <tr key={i.id}>
                      <td className="px-4 py-3">{i.email}</td>
                      <td className="px-4 py-3">{roleLabel[i.role]}</td>
                      <td className="px-4 py-3 font-mono text-xs text-muted tabular">{formatDateTime(i.expires_at)}</td>
                      <td className="px-4 py-3 text-right">{can.assign(workspace.role, i.role) && <RevokeInvite ws={ws} invite={i} />}</td>
                    </tr>
                  ))}
                </DataTable>
              </div>
            )}
          </Panel>
        )}
      </div>
    </>
  );
}
