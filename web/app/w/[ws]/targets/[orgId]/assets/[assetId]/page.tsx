import type { Metadata } from "next";
import Link from "next/link";
import { AiBadge } from "@/components/agents/AgentBadges";
import { notFound } from "next/navigation";
import { apiGet } from "@/lib/api/server";
import type { AssetDetail, AssetHistory, Chronicle } from "@/lib/api/types";
import { Timeline } from "@/components/chronicle/Timeline";
import { formatDateTime } from "@/lib/format";
import { assetKindLabel, assetStatusLabel, assetStatusTone, can, ownershipLabel } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { EditAsset } from "@/components/assets/AssetForms";
import { EvidenceList } from "@/components/assets/EvidenceList";
import { Badge, DataTable, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Asset" };

const relLabel = { subdomain_of: "Subdomain of", resolves_to: "Resolves to", cname_to: "CNAME to" } as const;
const changeLabel = { created: "Created", status: "Status", ownership: "Ownership", notes: "Notes" } as Record<string, string>;

function describe(h: AssetHistory): string {
  if (h.change === "created") return `Registered (source: ${h.new_value ?? "unknown"})`;
  if (h.change === "notes") return "Notes edited";
  const label = (v: string | null) =>
    v == null ? "—" : h.change === "status" ? (assetStatusLabel as Record<string, string>)[v] ?? v : (ownershipLabel as Record<string, string>)[v] ?? v;
  return `${label(h.old_value)} → ${label(h.new_value)}`;
}

function who(h: AssetHistory): string {
  if (h.recorded_by === "migration") return "Recorded when history began";
  if (h.actor_name) return h.actor_name;
  return h.recorded_by.startsWith("nightfall_") ? `${h.recorded_by.replace("nightfall_", "")} (automated)` : h.recorded_by;
}

const relLabelIn = { subdomain_of: "Has subdomain", resolves_to: "Resolved from", cname_to: "CNAME from" } as const;

export default async function AssetPage({ params }: { params: Promise<{ ws: string; orgId: string; assetId: string }> }) {
  const { ws, orgId, assetId } = await params;
  const [asset, me, activity] = await Promise.all([
    apiGet<AssetDetail>(`/workspaces/${ws}/assets/${assetId}`), membership(ws),
    apiGet<Chronicle>(`/workspaces/${ws}/assets/${assetId}/chronicle?limit=30`),
  ]);
  if (asset.organization_id !== orgId) notFound();

  return (
    <>
      <nav className="mb-2 text-sm text-muted">
        <Link href={`/w/${ws}/targets`} className="hover:text-text">Target Registry</Link> /{" "}
        <Link href={`/w/${ws}/targets/${orgId}`} className="hover:text-text">{asset.organization_name}</Link> /
      </nav>
      <PageHeader title={asset.value} subtitle={`${assetKindLabel[asset.kind]} · ${ownershipLabel[asset.ownership]} · source: ${asset.source}`} actions={<Badge tone={assetStatusTone[asset.status]}>{assetStatusLabel[asset.status]}</Badge>} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-6">
          <Panel title="Relationships">
            {asset.relationships.length === 0 ? <p className="text-sm text-muted">No recorded relationships.</p> : (
              <DataTable head={["Relationship", "Asset", "Status", "Rule", "Last seen"]}>
                {asset.relationships.map((r) => (
                  <tr key={`${r.direction}-${r.rel_type}-${r.other_asset_id}`}>
                    <td className="px-4 py-2.5">{(r.direction === "out" ? relLabel : relLabelIn)[r.rel_type]}</td>
                    <td className="px-4 py-2.5"><Link href={`/w/${ws}/targets/${orgId}/assets/${r.other_asset_id}`} className="font-mono text-sm hover:text-crimson-text">{r.other_value}</Link></td>
                    <td className="px-4 py-2.5"><span className="flex flex-wrap items-center gap-1.5"><Badge tone={r.status === "observed" ? "green" : "gray"}>{r.status === "observed" ? "Observed" : "Hypothesis"}</Badge>{r.proposed_by_task_id && <Link href={`/w/${ws}/agents/${r.proposed_by_task_id}`} title={r.status === "observed" ? "First proposed by the Investigator agent, since observed by a collector" : "Proposed by the Investigator agent"}><AiBadge /></Link>}</span></td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted">{r.rule_id}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted tabular">{formatDateTime(r.last_seen_at)}</td>
                  </tr>
                ))}
              </DataTable>
            )}
          </Panel>
          <Panel title="Evidence"><EvidenceList ws={ws} items={asset.evidence} /></Panel>
          <Panel title="Activity">
            <Timeline ws={ws} path={`/workspaces/${ws}/assets/${assetId}/chronicle`} initial={activity} />
          </Panel>
          <Panel title="History">
            <p className="mb-3 text-xs text-muted">Written by the database on every change to status, ownership or notes. It can&apos;t be edited or deleted.</p>
            <DataTable head={["When", "Change", "Detail", "By"]}>
              {asset.history.map((h) => (
                <tr key={h.id} data-testid="history-row">
                  <td className="px-4 py-2.5 font-mono text-xs text-muted tabular">{formatDateTime(h.occurred_at)}</td>
                  <td className="px-4 py-2.5">{changeLabel[h.change] ?? h.change}</td>
                  <td className="px-4 py-2.5 text-sm">{describe(h)}</td>
                  <td className="px-4 py-2.5 text-xs text-muted">{who(h)}</td>
                </tr>
              ))}
            </DataTable>
          </Panel>
        </div>
        <div className="space-y-6">
          <Panel title="Timeline">
            <dl className="space-y-3 text-sm">
              <div><dt className="text-muted">First seen</dt><dd className="font-mono tabular">{formatDateTime(asset.first_seen_at)}</dd></div>
              <div><dt className="text-muted">Last seen</dt><dd className="font-mono tabular">{formatDateTime(asset.last_seen_at)}</dd></div>
            </dl>
            <p className="mt-4 text-xs text-muted">Being registered doesn&apos;t put an asset in scope. Each project&apos;s authorized scope decides what may be collected.</p>
          </Panel>
          {can.writeRegistry(me.role) && <Panel title="Details"><EditAsset ws={ws} asset={asset} /></Panel>}
        </div>
      </div>
    </>
  );
}
