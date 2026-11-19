import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { HostView, Incident, Project } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { HostAlerts } from "@/components/shield/HostAlerts";
import { Badge, DataTable, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Machine" };

const groupLabel: Record<string, string> = {
  accounts: "Local accounts", admins: "Administrators", ssh_keys: "SSH keys", listeners: "Listening services",
  persistence: "Services, scheduled tasks and startup items", software: "Installed software",
  files: "Watched files", posture: "Posture",
};

/** What a field shows for an item: its most telling columns, never more than the API kept. */
function describe(group: string, item: Record<string, unknown>): string {
  const v = (k: string) => (item[k] === null || item[k] === undefined ? "" : String(item[k]));
  switch (group) {
    case "accounts": return `${v("username")} (uid ${v("uid")}) ${v("shell")}`;
    case "admins": return `${v("username")} in ${v("groupname")}`;
    case "ssh_keys": return `${v("username")}: ${v("algorithm")} in ${v("key_file")}`;
    case "listeners": return `${v("process") || "?"} on ${v("address")}:${v("port")}/${v("protocol")}`;
    case "persistence": return `${v("kind")}: ${v("name")}${v("path") && v("path") !== v("name") ? ` (${v("path")})` : ""}`;
    case "software": return `${v("name")} ${v("version")} (${v("source")})`;
    case "files": return `${v("path")} sha256 ${v("sha256").slice(0, 12)}…`;
    case "posture": return `${v("check")}: ${v("detail")}`;
    default: return JSON.stringify(item);
  }
}

export default async function MachinePage({ params }: { params: Promise<{ ws: string; sensorId: string }> }) {
  const { ws, sensorId } = await params;
  const [h, me, projects, incidents] = await Promise.all([
    apiGet<HostView>(`/workspaces/${ws}/shield/sensors/${sensorId}/host`), membership(ws),
    apiGet<Project[]>(`/workspaces/${ws}/projects`),
    apiGet<Incident[]>(`/workspaces/${ws}/incidents?state=in_progress`),
  ]);
  return (
    <>
      <PageHeader title={h.sensor_name}
        subtitle="What this machine's osquery reported: what it showed, not proof. Detection only; nothing here changes the machine." />
      <p className="mb-4 text-sm"><Link className="text-muted hover:text-crimson-text" href={`/w/${ws}/shield/intrusion`}>← Intrusion Detection</Link></p>
      {h.groups.length === 0 && h.posture.length === 0 ? (
        <Panel><p className="text-sm text-muted">No host state yet. Turn on the sensor&apos;s osquery module (infra/janus-sensor/README.md).</p></Panel>
      ) : (
        <div className="space-y-6">
          <Panel title="Host alerts">
            <HostAlerts ws={ws} alerts={h.alerts} canAct={can.editFindings(me.role)} projects={projects} incidents={incidents} />
          </Panel>
          <Panel title="Posture">
            <ul className="space-y-1 text-sm" data-testid="posture">
              {h.posture.map((p) => (
                <li key={p.check} className="flex items-center gap-2">
                  {p.ok === null ? <Badge tone="gray">Unknown</Badge> : p.ok ? <Badge tone="green">OK</Badge> : <Badge tone="crimson">Check</Badge>}
                  <span className="font-medium">{p.check.replaceAll("_", " ")}</span>
                  <span className="text-xs text-muted">{p.detail}</span>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title={`Changes (last ${h.retention_days} days)`}>
            {h.changes.length === 0 ? <p className="text-sm text-muted">No changes since the first snapshot.</p> : (
              <DataTable head={["When observed", "What", "Change", "Item"]}>
                {h.changes.map((c, i) => (
                  <tr key={i} data-testid="host-change">
                    <td className="text-xs tabular">{formatDateTime(c.observed_at)}</td>
                    <td className="text-xs">{groupLabel[c.group] ?? c.group}</td>
                    <td>{c.action === "added" ? <Badge tone="yellow">Added</Badge> : c.action === "changed" ? <Badge tone="orange">Changed</Badge> : <Badge tone="gray">Removed</Badge>}</td>
                    <td className="font-mono text-xs">{describe(c.group, c.item)}</td>
                  </tr>
                ))}
              </DataTable>
            )}
          </Panel>
          <Panel title="Current state">
            {h.groups.map((g) => (
              <details key={g.group} className="border-b border-border py-2 text-sm last:border-0" data-testid="host-group">
                <summary className="cursor-pointer">
                  {groupLabel[g.group] ?? g.group} <span className="text-muted">({g.item_count}) · observed {formatDateTime(g.observed_at)}</span>
                </summary>
                <ul className="mt-2 max-h-80 space-y-0.5 overflow-auto font-mono text-xs">
                  {g.items.map((it, i) => <li key={i}>{describe(g.group, it)}</li>)}
                </ul>
              </details>
            ))}
          </Panel>
        </div>
      )}
    </>
  );
}
