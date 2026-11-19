"use client";

import Link from "next/link";
import { useState } from "react";
import { api } from "@/lib/api/client";
import type { Correlation } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Field, Input, Panel, Select } from "@/components/ui/primitives";
import { assessmentLabel, confidenceTone } from "@/components/shield/labels";

const TYPES = [["ip", "IP address"], ["domain", "Domain"], ["url", "URL"], ["sha256", "File SHA-256"],
  ["cert_sha256", "Certificate SHA-256"], ["user_agent", "User agent"]] as const;

/** SENTINEL 3c: a person records an indicator found during the investigation. */
function EnterIndicator({ ws, incidentId }: { ws: string; incidentId: string }) {
  const { busy, error, run } = useAction();
  const [type, setType] = useState("ip");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  return (
    <form className="mt-4 flex flex-wrap items-end gap-2" data-testid="enter-indicator" onSubmit={async (e) => {
      e.preventDefault();
      if (await run(() => api(`/workspaces/${ws}/sentinel/incidents/${incidentId}/indicators`, { method: "POST", body: { type, value, note } }))) {
        setValue(""); setNote("");
      }
    }}>
      {error && <Alert>{error}</Alert>}
      <Field label="Indicator type">
        <Select value={type} onChange={(e) => setType(e.target.value)}>
          {TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </Select>
      </Field>
      <Field label="Value"><Input value={value} onChange={(e) => setValue(e.target.value)} required /></Field>
      <Field label="Where it was found (optional)"><Input value={note} onChange={(e) => setNote(e.target.value)} /></Field>
      <Button type="submit" variant="secondary" disabled={busy || !value.trim()}>Add indicator</Button>
    </form>
  );
}

/** SENTINEL 3b/3c: computed when read. Suggestions are only suggestions; a person adds them. */
export function IncidentCorrelation({ ws, incidentId, c, canWork }: {
  ws: string; incidentId: string; c: Correlation; canWork: boolean;
}) {
  const { busy, error, run } = useAction();
  if (c.linked_alerts === 0 && c.shared_indicators.length === 0 && !canWork) return null;
  const add = (kind: string, id: string) => run(() => kind === "aegis-alerts"
    ? api(`/workspaces/${ws}/incidents/${incidentId}/items`, { method: "POST", body: { kind: "alert", item_id: id } })
    : api(`/workspaces/${ws}/shield/escalations/${kind}/${id}`, { method: "POST", body: { incident_id: incidentId } }));
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
          <p className="mt-4 text-sm font-medium">Indicators from the linked alerts and this investigation</p>
          <ul className="mt-1 space-y-1 text-xs">
            {c.shared_indicators.map((s) => (
              <li key={s.indicator.id}>
                <Link className="font-mono hover:underline" href={`/w/${ws}/shield/sentinel/${s.indicator.id}`}>{s.indicator.value}</Link>{" "}
                <Badge tone={confidenceTone[s.indicator.confidence] ?? "gray"}>{s.indicator.confidence}</Badge>{" "}
                {assessmentLabel[s.indicator.assessment]}{s.machines.length > 0 && ` · seen on ${s.machines.join(", ")}`} · {s.elsewhere.length} sighting(s) outside this incident
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
      {canWork && <EnterIndicator ws={ws} incidentId={incidentId} />}
    </Panel>
  );
}
