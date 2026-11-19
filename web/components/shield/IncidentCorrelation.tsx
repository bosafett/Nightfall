"use client";

import Link from "next/link";
import { api } from "@/lib/api/client";
import type { Correlation } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Panel } from "@/components/ui/primitives";
import { assessmentLabel, confidenceTone } from "@/components/shield/labels";

/** SENTINEL 3b: computed when read. Suggestions are only suggestions; a person adds them. */
export function IncidentCorrelation({ ws, incidentId, c, canWork }: {
  ws: string; incidentId: string; c: Correlation; canWork: boolean;
}) {
  const { busy, error, run } = useAction();
  if (c.linked_alerts === 0) return null;
  const add = (kind: string, id: string) =>
    run(() => api(`/workspaces/${ws}/shield/escalations/${kind}/${id}`, { method: "POST", body: { incident_id: incidentId } }));
  const list = (items: Correlation["knows"], empty: string, testid: string) => items.length === 0
    ? <p className="text-xs text-muted">{empty}</p>
    : <ul className="space-y-1 text-xs" data-testid={testid}>{items.map((k, i) => (
        <li key={i}>{k.text}{k.by && <span className="text-muted"> · {k.by}</span>}{k.at && <span className="text-muted"> · {formatDateTime(k.at)}</span>}</li>
      ))}</ul>;
  return (
    <Panel title="SENTINEL: what JANUS knows and suspects">
      {error && <Alert>{error}</Alert>}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div><p className="mb-1 text-sm font-medium">Knows (validated by a person)</p>{list(c.knows, "Nothing validated yet.", "knows")}</div>
        <div><p className="mb-1 text-sm font-medium">Suspects (inferred, unconfirmed)</p>{list(c.suspects, "Nothing inferred.", "suspects")}</div>
        <div><p className="mb-1 text-sm font-medium">Unknowns</p>{list(c.unknowns, "None recorded. Add a timeline entry of type Unknown.", "unknowns")}</div>
      </div>
      {c.sequence.length > 0 && (
        <>
          <p className="mt-4 text-sm font-medium">Technique sequence (from the detectors, not proven)</p>
          <ol className="mt-1 space-y-0.5 text-xs" data-testid="sequence">
            {c.sequence.map((s, i) => (
              <li key={i} className="tabular">{formatDateTime(s.event_time)} · <span className="font-mono">{s.technique_id}</span> {s.technique_name} · {s.description}{s.sensor_name && ` · ${s.sensor_name}`}</li>
            ))}
          </ol>
        </>
      )}
      {c.shared_indicators.length > 0 && (
        <>
          <p className="mt-4 text-sm font-medium">Indicators from the linked alerts</p>
          <ul className="mt-1 space-y-1 text-xs">
            {c.shared_indicators.map((s) => (
              <li key={s.indicator.id}>
                <Link className="font-mono hover:underline" href={`/w/${ws}/shield/sentinel/${s.indicator.id}`}>{s.indicator.value}</Link>{" "}
                <Badge tone={confidenceTone[s.indicator.confidence] ?? "gray"}>{s.indicator.confidence}</Badge>{" "}
                {assessmentLabel[s.indicator.assessment]} · seen on {s.machines.join(", ") || "?"} · {s.elsewhere.length} sighting(s) outside this incident
              </li>
            ))}
          </ul>
        </>
      )}
      {c.suggestions.length > 0 && (
        <>
          <p className="mt-4 text-sm font-medium">Related alerts (suggestions)</p>
          <ul className="mt-1 space-y-1 text-xs" data-testid="suggestions">
            {c.suggestions.map((r) => (
              <li key={r.source_id} className="flex flex-wrap items-center gap-2">
                <span>{r.description}{r.sensor_name && ` on ${r.sensor_name}`} · {formatDateTime(r.event_time)} · <span className="text-muted">{r.reason}</span></span>
                {canWork && r.escalation_kind && <Button variant="secondary" disabled={busy} onClick={() => add(r.escalation_kind!, r.source_id)}>Add to incident</Button>}
              </li>
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
}
