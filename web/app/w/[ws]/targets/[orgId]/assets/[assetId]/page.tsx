import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { apiGet } from "@/lib/api/server";
import type { AssetDetail } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { assetKindLabel, can, ownershipLabel } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { EditAsset } from "@/components/assets/AssetForms";
import { EvidenceList } from "@/components/assets/EvidenceList";
import { Badge, DataTable, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Asset" };

const relLabel = { subdomain_of: "Subdomain of", resolves_to: "Resolves to", cname_to: "CNAME to" } as const;
const relLabelIn = { subdomain_of: "Has subdomain", resolves_to: "Resolved from", cname_to: "CNAME from" } as const;

export default async function AssetPage({ params }: { params: Promise<{ ws: string; orgId: string; assetId: string }> }) {
  const { ws, orgId, assetId } = await params;
  const [asset, me] = await Promise.all([apiGet<AssetDetail>(`/workspaces/${ws}/assets/${assetId}`), membership(ws)]);
  if (asset.organization_id !== orgId) notFound();

  return (
    <>
      <nav className="mb-2 text-sm text-muted">
        <Link href={`/w/${ws}/targets`} className="hover:text-text">Target Registry</Link> /{" "}
        <Link href={`/w/${ws}/targets/${orgId}`} className="hover:text-text">{asset.organization_name}</Link> /
      </nav>
      <PageHeader title={asset.value} subtitle={`${assetKindLabel[asset.kind]} · ${ownershipLabel[asset.ownership]} · source: ${asset.source}`} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-6">
          <Panel title="Relationships">
            {asset.relationships.length === 0 ? <p className="text-sm text-muted">No recorded relationships.</p> : (
              <DataTable head={["Relationship", "Asset", "Status", "Rule", "Last seen"]}>
                {asset.relationships.map((r) => (
                  <tr key={`${r.direction}-${r.rel_type}-${r.other_asset_id}`}>
                    <td className="px-4 py-2.5">{(r.direction === "out" ? relLabel : relLabelIn)[r.rel_type]}</td>
                    <td className="px-4 py-2.5"><Link href={`/w/${ws}/targets/${orgId}/assets/${r.other_asset_id}`} className="font-mono text-sm hover:text-crimson-text">{r.other_value}</Link></td>
                    <td className="px-4 py-2.5"><Badge tone={r.status === "observed" ? "green" : "gray"}>{r.status === "observed" ? "Observed" : "Hypothesis"}</Badge></td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted">{r.rule_id}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted tabular">{formatDateTime(r.last_seen_at)}</td>
                  </tr>
                ))}
              </DataTable>
            )}
          </Panel>
          <Panel title="Evidence"><EvidenceList ws={ws} items={asset.evidence} /></Panel>
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
