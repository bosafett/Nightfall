"use client";

import { api } from "@/lib/api/client";
import type { HostView, Incident, Project } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, DataTable } from "@/components/ui/primitives";
import { severityTone } from "@/components/shield/labels";
import { EscalateButton } from "@/components/shield/EscalateButton";

/** SHIELD v4 host alerts. "Possible compromise" is a hypothesis from a fixed rule (an attack alert on the same
 * machine within the hour before), never a confirmed finding. */
export function HostAlerts({ ws, alerts, canAct, projects, incidents }: {
  ws: string; alerts: HostView["alerts"]; canAct: boolean; projects: Project[]; incidents: Incident[];
}) {
  const { busy, error, run } = useAction();
  if (alerts.length === 0) return <p className="text-sm text-muted">No host alerts in the last 90 days.</p>;
  const act = (id: string, action: "acknowledge" | "resolve") =>
    run(() => api(`/workspaces/${ws}/shield/host-alerts/${id}/${action}`, { method: "POST" }));
  return (
    <>
      {error && <Alert>{error}</Alert>}
      <DataTable head={["Severity", "What", "Observed", "State", ""]}>
        {alerts.map((a) => (
          <tr key={a.id} data-testid="host-alert">
            <td><Badge tone={severityTone[a.severity] ?? "gray"}>{a.severity}</Badge></td>
            <td>
              <span className="block">{a.title}</span>
              {a.possible_compromise && (
                <span className="text-xs text-crimson-text">Possible compromise, unconfirmed: an attack on this machine was seen within the hour before.</span>
              )}
            </td>
            <td className="text-xs tabular">{formatDateTime(a.observed_at)}</td>
            <td className="text-xs">{a.state}</td>
            <td className="space-x-1 whitespace-nowrap">
              {canAct && a.state === "open" && <Button variant="secondary" disabled={busy} onClick={() => act(a.id, "acknowledge")}>Acknowledge</Button>}
              {canAct && a.state !== "resolved" && <Button variant="secondary" disabled={busy} onClick={() => act(a.id, "resolve")}>Resolve</Button>}
              {canAct && (projects.length > 0 || incidents.length > 0) && (
                <EscalateButton ws={ws} kind="host-alerts" alertId={a.id} projects={projects} incidents={incidents} />
              )}
            </td>
          </tr>
        ))}
      </DataTable>
    </>
  );
}
