"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { MonitorAuthorization, Project, ScopeVersion } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Field, Select } from "@/components/ui/primitives";
import { checkLabel, endedLabel } from "@/components/shield/labels";

const CHECKS = ["ct", "dns", "tls", "headers"] as const;

/** Standing authorizations: the owner approves daily passive and low-risk checks of targets in a
 * project's active scope for at most 30 days. Nothing else can make a check run unapproved. */
export function Authorizations({ ws, items, projects, scopes, canManage, cap, used }: {
  ws: string; items: MonitorAuthorization[]; projects: Project[]; scopes: Record<string, ScopeVersion | null>;
  canManage: boolean; cap: number; used: number;
}) {
  const { busy, error, run } = useAction();
  const eligible = projects.filter((p) => scopes[p.id] && !scopes[p.id]!.is_lab);
  const [projectId, setProjectId] = useState(eligible[0]?.id ?? "");
  const [targets, setTargets] = useState<string[]>([]);
  const [checks, setChecks] = useState<string[]>(["ct", "dns", "tls", "headers"]);
  const scope = scopes[projectId];
  const hosts = scope ? scope.targets.filter((t) => t.kind === "host" || t.kind === "domain_tree").map((t) => t.value) : [];
  const perDay = targets.length * checks.length;
  const live = items.filter((a) => a.live);
  const ended = items.filter((a) => !a.live);
  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  return (
    <div className="space-y-5">
      {error && <Alert>{error}</Alert>}
      <p className="text-sm text-muted">{used} of {cap} scheduled checks a day are authorized in this workspace (hosted platform limit).</p>
      {live.length === 0 ? <p className="text-sm text-muted">No live authorization: nothing is monitored.</p> : (
        <ul className="space-y-2" data-testid="authorizations">
          {live.map((a) => (
            <li key={a.id} className="rounded-md border border-border bg-bg p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{a.project_name}</span>
                <Badge tone="green">Live · scope v{a.scope_version}</Badge>
                {a.expiring_soon && <Badge tone="yellow">Expires soon</Badge>}
                <span className="ml-auto text-xs text-muted">{a.checks_per_day} checks a day</span>
              </div>
              <p className="mt-1 font-mono text-xs">{a.targets.join(", ")}</p>
              <p className="text-xs text-muted">{a.checks.map((c) => checkLabel[c] ?? c).join(" · ")}</p>
              <p className="mt-1 font-mono text-xs text-muted tabular">
                Authorized by {a.authorized_by} {formatDateTime(a.authorized_at)} · expires {formatDateTime(a.expires_at)} · last scheduled {formatDateTime(a.last_run_at)}
              </p>
              {canManage && (
                <div className="mt-2 flex flex-wrap gap-2">
                  <Button variant="secondary" disabled={busy} onClick={() => run(() => api(`/workspaces/${ws}/monitor-authorizations/${a.id}/renew`, { method: "POST" }))}>Renew for 30 days</Button>
                  <ConfirmButton label="Revoke" title="Revoke this authorization?" confirmLabel="Revoke"
                    body="Scheduled checks stop at once; queued ones are refused by the worker."
                    onConfirm={async () => { await run(() => api(`/workspaces/${ws}/monitor-authorizations/${a.id}/revoke`, { method: "POST", body: { reason: "Revoked from the Monitoring page" } })); }} />
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {canManage ? (
        eligible.length === 0 ? <p className="text-sm text-muted">Authorize a non-lab scope on a project first.</p> : (
          <form className="space-y-3 rounded-md border border-border p-3" onSubmit={async (e) => {
            e.preventDefault();
            const ok = await run(() => api(`/workspaces/${ws}/projects/${projectId}/monitor-authorizations`, { method: "POST", body: { targets, checks, days: 30 } }));
            if (ok) setTargets([]);
          }}>
            <p className="text-sm font-medium">New standing authorization (30 days)</p>
            <Field label="Monitored project">
              <Select value={projectId} onChange={(e) => { setProjectId(e.target.value); setTargets([]); }}>
                {eligible.map((p) => <option key={p.id} value={p.id}>{p.organization_name} — {p.name}</option>)}
              </Select>
            </Field>
            <fieldset>
              <legend className="text-sm">Targets from scope v{scope?.version} (up to 20)</legend>
              {hosts.map((h) => (
                <label key={h} className="mr-4 inline-flex items-center gap-2 text-sm font-mono">
                  <input type="checkbox" checked={targets.includes(h)} onChange={() => setTargets((t) => toggle(t, h))} />{h}
                </label>
              ))}
            </fieldset>
            <fieldset>
              <legend className="text-sm">Checks (passive and low risk only)</legend>
              {CHECKS.map((c) => (
                <label key={c} className="mr-4 inline-flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={checks.includes(c)} onChange={() => setChecks((x) => toggle(x, c))} />{checkLabel[c]}
                </label>
              ))}
            </fieldset>
            <p className="text-xs text-muted">{perDay} checks a day. Runs daily for 30 days, then stops unless renewed. A new scope version ends it.</p>
            <Button type="submit" disabled={busy || targets.length === 0 || checks.length === 0}>Authorize monitoring</Button>
          </form>
        )
      ) : <p className="text-xs text-muted">Only the workspace owner authorizes monitoring.</p>}
      {ended.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted">Ended ({ended.length})</summary>
          <ul className="mt-2 space-y-1 text-xs text-muted">
            {ended.map((a) => <li key={a.id}>{a.project_name} · {a.targets.join(", ")} · {endedLabel[a.ended_reason ?? ""] ?? "Expired"} {formatDateTime(a.ended_at ?? a.expires_at)}{a.end_note && ` · ${a.end_note}`}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
}
