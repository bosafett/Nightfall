import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Indicator } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { assessmentLabel, confidenceTone } from "@/components/shield/labels";
import { Badge, DataTable, EmptyState, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "SENTINEL Indicators" };

export default async function SentinelPage({ params, searchParams }: {
  params: Promise<{ ws: string }>; searchParams: Promise<{ status?: string }>;
}) {
  const { ws } = await params;
  const { status } = await searchParams;
  const all = status === "all";
  const items = await apiGet<Indicator[]>(`/workspaces/${ws}/sentinel/indicators${all ? "?status=all" : ""}`);
  return (
    <>
      <PageHeader title="SENTINEL Indicators"
        subtitle="Addresses and hashes the detectors saw, with every sighting. JANUS's confidence comes from what it observed and stops at medium; only a person's assessment makes it high. Analysis only: nothing here blocks anything." />
      <p className="mb-3 text-sm">
        {all ? <Link className="text-muted hover:text-crimson-text" href={`/w/${ws}/shield/sentinel`}>Show active only</Link>
          : <Link className="text-muted hover:text-crimson-text" href={`/w/${ws}/shield/sentinel?status=all`}>Include expired and suppressed</Link>}
      </p>
      <Panel>
        {items.length === 0 ? (
          <EmptyState title="No indicators" body="Indicators appear when a sensor reports an attack from a public address, a block is applied, or a watched file changes." />
        ) : (
          <DataTable head={["Indicator", "Type", "Sightings", "Last seen", "Confidence", "Assessment", "Status"]}>
            {items.map((i) => (
              <tr key={i.id} data-testid="indicator-row">
                <td className="font-mono text-xs"><Link className="hover:underline" href={`/w/${ws}/shield/sentinel/${i.id}`}>{i.value.length > 40 ? `${i.value.slice(0, 40)}…` : i.value}</Link></td>
                <td className="text-xs">{i.type}</td>
                <td className="tabular">{i.sighting_count}</td>
                <td className="text-xs tabular">{formatDateTime(i.last_seen)}</td>
                <td><Badge tone={confidenceTone[i.confidence] ?? "gray"}>{i.confidence}</Badge></td>
                <td className="text-xs">{assessmentLabel[i.assessment] ?? i.assessment}</td>
                <td className="text-xs">{i.status}</td>
              </tr>
            ))}
          </DataTable>
        )}
      </Panel>
    </>
  );
}
