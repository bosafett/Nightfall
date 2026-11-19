"use client";

import { useRouter } from "next/navigation";
import { useRef, useState } from "react";
import { api } from "@/lib/api/client";
import type { Incident, Project } from "@/lib/api/types";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Select } from "@/components/ui/primitives";

/** v3 decision 4 (c): a person opens an incident from a sensor alert, or adds it to one in progress. */
export function EscalateButton({ ws, kind, alertId, projects, incidents }: {
  ws: string; kind: "intrusion-alerts" | "host-alerts"; alertId: string; projects: Project[]; incidents: Incident[];
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const router = useRouter();
  const { busy, error, run } = useAction();
  const [target, setTarget] = useState(incidents[0] ? `i:${incidents[0].id}` : projects[0] ? `p:${projects[0].id}` : "");
  return (
    <>
      <Button variant="secondary" onClick={() => ref.current?.showModal()}>Incident…</Button>
      <dialog ref={ref} className="m-auto w-[min(28rem,calc(100%-2rem))] rounded-lg border border-border-strong bg-surface p-5 text-text backdrop:bg-black/70">
        <form className="space-y-3" onSubmit={async (e) => {
          e.preventDefault();
          const [t, id] = target.split(":");
          const out = await run<Incident>(() => api(`/workspaces/${ws}/shield/escalations/${kind}/${alertId}`, {
            method: "POST", body: t === "i" ? { incident_id: id } : { project_id: id },
          }), { refresh: false });
          if (out) { ref.current?.close(); router.push(`/w/${ws}/shield/incidents/${out.id}`); }
        }}>
          <p className="font-medium">Add this alert to an incident</p>
          {error && <Alert>{error}</Alert>}
          <Field label="Incident" hint="The alert is written to the incident's timeline as sensor-reported, unverified data.">
            <Select value={target} onChange={(e) => setTarget(e.target.value)}>
              {incidents.length > 0 && (
                <optgroup label="Add to an incident in progress">
                  {incidents.map((i) => <option key={i.id} value={`i:${i.id}`}>{i.title}</option>)}
                </optgroup>
              )}
              <optgroup label="Open a new incident in">
                {projects.map((p) => <option key={p.id} value={`p:${p.id}`}>{p.organization_name} — {p.name}</option>)}
              </optgroup>
            </Select>
          </Field>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="secondary" onClick={() => ref.current?.close()}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={busy || !target}>Add to incident</Button>
          </div>
        </form>
      </dialog>
    </>
  );
}
