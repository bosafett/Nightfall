import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Organization } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { NewOrganization } from "@/components/registry/Forms";
import { DataTable, EmptyState, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Target Registry" };

export default async function TargetsPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [orgs, me] = await Promise.all([apiGet<Organization[]>(`/workspaces/${ws}/organizations`), membership(ws)]);
  const writable = can.writeRegistry(me.role);

  return (
    <>
      <PageHeader title="Target Registry" subtitle="Organizations and assessment projects. Assets and scope arrive in phase 3." />
      {writable && <div className="mb-6"><NewOrganization ws={ws} /></div>}
      {orgs.length === 0 ? (
        <EmptyState title="No organizations yet"
          body={writable ? "Add the first organization you're authorized to assess." : "Nothing registered yet. An analyst or admin can add organizations."} />
      ) : (
        <Panel title="Organizations">
          <DataTable head={["Name", "Projects", "Updated"]}>
            {orgs.map((o) => (
              <tr key={o.id} className="hover:bg-surface-2">
                <td className="px-4 py-3">
                  <Link href={`/w/${ws}/targets/${o.id}`} className="font-medium hover:text-crimson-text">{o.name}</Link>
                </td>
                <td className="px-4 py-3 font-mono tabular">{o.project_count}</td>
                <td className="px-4 py-3 font-mono text-xs text-muted tabular">{formatDateTime(o.updated_at)}</td>
              </tr>
            ))}
          </DataTable>
        </Panel>
      )}
    </>
  );
}
