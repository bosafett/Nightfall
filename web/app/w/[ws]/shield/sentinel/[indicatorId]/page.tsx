import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { IndicatorDetail } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { AssessIndicator } from "@/components/shield/AssessIndicator";
import { Badge, DataTable, PageHeader, Panel } from "@/components/ui/primitives";
import { assessmentLabel, confidenceTone } from "@/components/shield/labels";

export const metadata: Metadata = { title: "Indicator" };

const sourceLabel: Record<string, string> = {
  intrusion_alert: "Intrusion alert", block: "Block", host_alert: "Host alert", host_change: "Host change",
  aegis_alert: "AEGIS alert", incident_entry: "Entered on an incident",
};

export default async function IndicatorPage({ params }: { params: Promise<{ ws: string; indicatorId: string }> }) {
  const { ws, indicatorId } = await params;
  const [d, me] = await Promise.all([
    apiGet<IndicatorDetail>(`/workspaces/${ws}/sentinel/indicators/${indicatorId}`), membership(ws),
  ]);
  return (
    <>
      <PageHeader title={d.value.length > 60 ? `${d.value.slice(0, 60)}…` : d.value} subtitle={`${d.type} indicator · ${d.status}`} />
      <p className="mb-4 text-sm"><Link className="text-muted hover:text-crimson-text" href={`/w/${ws}/shield/sentinel`}>← SENTINEL Indicators</Link></p>
      <div className="space-y-6">
        <Panel title="Observed versus assessed">
          <dl className="grid grid-cols-1 gap-3 text-sm md:grid-cols-2" data-testid="indicator-summary">
            <div>
              <dt className="text-xs text-muted">JANUS observed (computed)</dt>
              <dd><Badge tone={confidenceTone[d.computed_confidence] ?? "gray"}>{d.computed_confidence}</Badge>
                <span className="ml-2 text-xs text-muted tabular">{d.sighting_count} sighting(s), {formatDateTime(d.first_seen)} → {formatDateTime(d.last_seen)}{d.machines.length > 0 && ` · on ${d.machines.join(", ")}`}</span></dd>
            </div>
            <div>
              <dt className="text-xs text-muted">Assessed by a person</dt>
              <dd>{assessmentLabel[d.assessment] ?? d.assessment}{d.assessed_by && <span className="text-xs text-muted"> · {d.assessed_by}, {formatDateTime(d.assessed_at)}: {d.assessment_reason}</span>}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted">Effective confidence</dt>
              <dd><Badge tone={confidenceTone[d.confidence] ?? "gray"}>{d.confidence}</Badge></dd>
            </div>
            <div>
              <dt className="text-xs text-muted">Expires</dt>
              <dd className="text-xs">{d.expires_at ? formatDateTime(d.expires_at) : "Never (hash or fingerprint)"}</dd>
            </div>
          </dl>
          {d.techniques.length > 0 && (
            <p className="mt-3 text-xs">ATT&amp;CK (from the detectors, not proven): {d.techniques.map((t) => `${t.id} ${t.name}`).join(" · ")}</p>
          )}
          {can.editFindings(me.role) && <div className="mt-4"><AssessIndicator ws={ws} id={d.id} current={d.assessment} /></div>}
        </Panel>
        <Panel title="Sightings">
          <DataTable head={["When", "Source", "What (reported by the detector)", "Machine", "Incident"]}>
            {d.sightings.map((s) => (
              <tr key={s.id} data-testid="sighting">
                <td className="text-xs tabular">{formatDateTime(s.event_time)}</td>
                <td className="text-xs">{sourceLabel[s.source_kind] ?? s.source_kind}</td>
                <td className="text-xs">{s.description}</td>
                <td className="text-xs">{s.sensor_name ?? ""}</td>
                <td className="text-xs">{s.incident_id && <Link className="underline" href={`/w/${ws}/shield/incidents/${s.incident_id}`}>Open</Link>}</td>
              </tr>
            ))}
          </DataTable>
        </Panel>
        {d.history.length > 0 && (
          <Panel title="Assessment history">
            <ul className="space-y-1 text-xs">
              {d.history.map((h, i) => <li key={i}>{formatDateTime(h.at)} · {h.by}: {assessmentLabel[h.from_assessment]} → {assessmentLabel[h.to_assessment]} · {h.reason}</li>)}
            </ul>
          </Panel>
        )}
      </div>
    </>
  );
}
