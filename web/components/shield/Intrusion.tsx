"use client";

import Link from "next/link";
import { useState } from "react";
import { api } from "@/lib/api/client";
import type { IntrusionView, ShieldBlock, ShieldSensorCreated } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, DataTable, Field, Input, Panel, type Tone } from "@/components/ui/primitives";
import { severityTone } from "@/components/shield/labels";

const blockTone: Record<ShieldBlock["status"], Tone> = {
  pending: "yellow", active: "crimson", lifting: "yellow", lifted: "gray", expired: "gray",
};
const blockLabel: Record<ShieldBlock["status"], string> = {
  pending: "Waiting for sensor", active: "Blocked", lifting: "Lifting", lifted: "Lifted", expired: "Expired",
};
const categoryLabel: Record<string, string> = {
  ssh_bruteforce: "SSH brute force", http_bruteforce: "Web login brute force", exploit_attempt: "Exploit attempt",
  web_scan: "Web scan", other: "Other",
};

function left(expires: string): string {
  const m = Math.max(0, Math.round((new Date(expires).getTime() - Date.now()) / 60000));
  return m >= 120 ? `${Math.round(m / 60)} h left` : `${m} min left`;
}

/** SHIELD v3 phase 2. Owner + fresh two-factor: sensors, the response authorization, resume, removing allow-list
 * entries. Admin: pause, end the authorization, add allow-list entries, lift blocks; approve blocks with fresh
 * two-factor. The API enforces all of it; this only hides what the role can't do. */
export function Intrusion({ ws, view, isOwner, isAdmin, canAct }: {
  ws: string; view: IntrusionView; isOwner: boolean; isAdmin: boolean; canAct: boolean;
}) {
  const { busy, error, run } = useAction();
  const base = `/workspaces/${ws}/shield`;
  const live = view.sensors.filter((s) => !s.revoked_at);
  const names = Object.fromEntries(view.sensors.map((s) => [s.id, s.name]));
  const auth = view.authorization;
  const paused = view.settings.automatic_paused;

  const [created, setCreated] = useState<ShieldSensorCreated | null>(null);
  const [sensorName, setSensorName] = useState("");
  const [authSensors, setAuthSensors] = useState<string[]>(auth?.sensor_ids ?? live.map((s) => s.id));
  const [defMin, setDefMin] = useState(60);
  const [maxMin, setMaxMin] = useState(240);
  const [cap, setCap] = useState(50);
  const [days, setDays] = useState(90);
  const [cidr, setCidr] = useState("");
  const [note, setNote] = useState("");
  const [target, setTarget] = useState("");
  const [blockSensors, setBlockSensors] = useState<string[]>(live.map((s) => s.id));
  const [hours, setHours] = useState(24);
  const [reason, setReason] = useState("");
  const [alertId, setAlertId] = useState<string | null>(null);
  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  const post = (path: string, body?: unknown) => run(() => api(`${base}${path}`, { method: "POST", body }));

  const activeBlocks = view.blocks.filter((b) => b.status === "pending" || b.status === "active" || b.status === "lifting");
  const pastBlocks = view.blocks.filter((b) => !activeBlocks.includes(b));

  const sensorPicker = (value: string[], set: (v: string[]) => void) => (
    <fieldset>
      <legend className="text-sm">Sensors</legend>
      {live.map((s) => (
        <label key={s.id} className="mr-4 inline-flex items-center gap-2 text-sm">
          <input type="checkbox" checked={value.includes(s.id)} onChange={() => set(toggle(value, s.id))} />{s.name}
        </label>
      ))}
    </fieldset>
  );

  return (
    <div className="space-y-6">
      {error && <Alert>{error}</Alert>}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4" data-testid="intrusion-status">
        <div className="rounded-lg border border-border bg-surface p-3">
          <p className="text-xs text-muted">GUARD (automatic blocks)</p>
          <p className="mt-1">{paused ? <Badge tone="yellow">Paused</Badge> : view.automatic_active ? <Badge tone="green">Active</Badge> : <Badge tone="gray">Alert only</Badge>}</p>
        </div>
        <div className="rounded-lg border border-border bg-surface p-3">
          <p className="text-xs text-muted">Sensors online</p>
          <p className="mt-1 text-2xl font-semibold tabular">{live.length - view.sensors_offline}/{live.length}</p>
        </div>
        <div className="rounded-lg border border-border bg-surface p-3">
          <p className="text-xs text-muted">Active blocks</p>
          <p className="mt-1 text-2xl font-semibold tabular">{activeBlocks.length}</p>
        </div>
        <div className="rounded-lg border border-border bg-surface p-3">
          <p className="text-xs text-muted">Blocks in the last 24 h</p>
          <p className="mt-1 text-2xl font-semibold tabular">{view.blocks_24h}</p>
        </div>
      </div>

      {paused && (
        <Alert tone="yellow">
          Automatic response is paused by {view.settings.paused_by} {formatDateTime(view.settings.paused_at)}: {view.settings.pause_reason}.
          Sensors keep sending alerts; nothing is blocked automatically.
        </Alert>
      )}

      <Panel title="Kill switch">
        <p className="text-sm text-muted">Pausing stops every automatic block at once; alerts keep arriving. Blocks already applied run out or can be lifted below.</p>
        <div className="mt-2 flex gap-2">
          {!paused && isAdmin && (
            <ConfirmButton label="Pause automatic response" title="Pause GUARD?" confirmLabel="Pause"
              body="No new automatic blocks until the owner resumes it."
              onConfirm={async () => { await post("/response/pause", { reason: "Paused from Intrusion Detection" }); }} />
          )}
          {paused && isOwner && <Button disabled={busy} onClick={() => post("/response/resume")}>Resume (owner, two-factor)</Button>}
          {!isAdmin && <p className="text-xs text-muted">Owners and admins can pause automatic response.</p>}
        </div>
      </Panel>

      <Panel title="Active blocks">
        {activeBlocks.length === 0 ? <p className="text-sm text-muted">Nothing is blocked.</p> : (
          <DataTable head={["Target", "Sensor", "Tier", "Status", "Expires", "Reason", ""]}>
            {activeBlocks.map((b) => (
              <tr key={b.id} data-testid="block-row">
                <td className="font-mono text-xs">{b.target}</td>
                <td>{b.sensor_name}</td>
                <td>{b.tier === "automatic" ? "GUARD" : `Approved by ${b.approved_by}`}</td>
                <td><Badge tone={blockTone[b.status]}>{blockLabel[b.status]}</Badge></td>
                <td className="text-xs tabular" title={formatDateTime(b.expires_at)}>{left(b.expires_at)}</td>
                <td className="text-xs">{b.reason}</td>
                <td>{isAdmin && b.status !== "lifting" && (
                  <Button variant="secondary" disabled={busy} onClick={() => post(`/blocks/${b.id}/lift`, { reason: "Lifted from Intrusion Detection" })}>Lift</Button>
                )}</td>
              </tr>
            ))}
          </DataTable>
        )}
        {pastBlocks.length > 0 && (
          <details className="mt-3 text-sm">
            <summary className="cursor-pointer text-muted">Last 7 days ({pastBlocks.length})</summary>
            <ul className="mt-2 space-y-1 text-xs text-muted">
              {pastBlocks.map((b) => (
                <li key={b.id}>{b.target} on {b.sensor_name} · {blockLabel[b.status]} · {formatDateTime(b.created_at)}{b.lifted_by && ` · lifted by ${b.lifted_by}: ${b.lifted_reason}`}</li>
              ))}
            </ul>
          </details>
        )}
        {isAdmin && live.length > 0 && (
          <form className="mt-4 space-y-3 rounded-md border border-border p-3" onSubmit={async (e) => {
            e.preventDefault();
            const ok = await post("/blocks", { target, sensor_ids: blockSensors, seconds: hours * 3600, reason, alert_id: alertId });
            if (ok) { setTarget(""); setReason(""); setAlertId(null); }
          }}>
            <p className="text-sm font-medium">Approve a block (person-approved tier, two-factor)</p>
            <Field label="Address or range" hint="An address, or a range no wider than /16 (IPv6 /32). Never on the allow list.">
              <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="203.0.113.7" required />
            </Field>
            {sensorPicker(blockSensors, setBlockSensors)}
            <Field label="Hours" hint={`At most ${view.approved_max_seconds / 3600} hours.`}>
              <Input type="number" min={1} max={view.approved_max_seconds / 3600} value={hours} onChange={(e) => setHours(Number(e.target.value))} />
            </Field>
            <Field label="Reason"><Input value={reason} onChange={(e) => setReason(e.target.value)} required /></Field>
            <Button type="submit" variant="primary" disabled={busy || !target || !reason || blockSensors.length === 0}>Approve block</Button>
          </form>
        )}
      </Panel>

      <Panel title="Intrusion alerts">
        {view.alerts.length === 0 ? <p className="text-sm text-muted">No alerts in the last 7 days.</p> : (
          <DataTable head={["Severity", "What", "Source", "Sensor", "Events", "Last seen", "Response", ""]}>
            {view.alerts.map((a) => (
              <tr key={a.id} data-testid="intrusion-alert">
                <td><Badge tone={severityTone[a.severity] ?? "gray"}>{a.severity}</Badge></td>
                <td><span className="block">{categoryLabel[a.category] ?? a.category}</span><span className="font-mono text-xs text-muted">{a.scenario}</span></td>
                <td className="font-mono text-xs">{a.source}</td>
                <td>{a.sensor_name}</td>
                <td className="tabular">{a.count}</td>
                <td className="text-xs tabular">{formatDateTime(a.last_event_time)}</td>
                <td className="text-xs">{a.block_ids.length > 0 ? "Blocked" : "Alert only"}</td>
                <td className="space-x-1 whitespace-nowrap">
                  {canAct && a.state === "open" && <Button variant="secondary" disabled={busy} onClick={() => post(`/intrusion-alerts/${a.id}/acknowledge`)}>Acknowledge</Button>}
                  {canAct && a.state !== "resolved" && <Button variant="secondary" disabled={busy} onClick={() => post(`/intrusion-alerts/${a.id}/resolve`)}>Resolve</Button>}
                  {isAdmin && a.block_ids.length === 0 && (
                    <Button variant="secondary" onClick={() => { setTarget(a.source); setAlertId(a.id); setReason(`${categoryLabel[a.category] ?? a.category}: ${a.scenario}`); setBlockSensors([a.sensor_id]); }}>Block…</Button>
                  )}
                </td>
              </tr>
            ))}
          </DataTable>
        )}
        <p className="mt-2 text-xs text-muted">Alert content comes from the sensor and is shown as data only. &ldquo;Blocked&rdquo; means blocked on that machine until the block expires; it doesn&apos;t mean the threat is gone.</p>
      </Panel>

      <Panel title="Standing response authorization">
        {auth ? (
          <div className="rounded-md border border-border bg-bg p-3 text-sm" data-testid="response-authorization">
            <div className="flex flex-wrap items-center gap-2"><Badge tone="green">Live</Badge>
              <span>{auth.sensor_ids.map((id) => names[id] ?? id).join(", ")}</span></div>
            <p className="mt-1 text-xs text-muted tabular">
              Block one address for {auth.default_block_seconds / 60} min by default, at most {auth.max_block_seconds / 60} min · at most {auth.per_hour_cap} automatic blocks per sensor per hour ·
              authorized by {auth.authorized_by} {formatDateTime(auth.authorized_at)} · expires {formatDateTime(auth.expires_at)}
            </p>
            {isAdmin && (
              <div className="mt-2">
                <ConfirmButton label="End authorization" title="End the response authorization?" confirmLabel="End"
                  body="GUARD stops creating blocks at once. Recording a new one needs the owner with two-factor."
                  onConfirm={async () => { await post("/response-authorization/end", { reason: "Ended from Intrusion Detection" }); }} />
              </div>
            )}
          </div>
        ) : <p className="text-sm text-muted">None: every alert stays alert-only.</p>}
        {isOwner && live.length > 0 && (
          <form className="mt-4 space-y-3 rounded-md border border-border p-3" onSubmit={async (e) => {
            e.preventDefault();
            await post("/response-authorization", { sensor_ids: authSensors, default_block_seconds: defMin * 60, max_block_seconds: maxMin * 60, per_hour_cap: cap, days });
          }}>
            <p className="text-sm font-medium">{auth ? "Replace the authorization" : "Authorize automatic blocks"} (owner, two-factor)</p>
            <p className="text-xs text-muted">GUARD will block a single address on the machine that saw an SSH or web brute force, exploit attempt or web scan. Never an allow-listed, loopback or reserved address; never a range.</p>
            {sensorPicker(authSensors, setAuthSensors)}
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Field label="Default block (min)"><Input type="number" min={1} max={240} value={defMin} onChange={(e) => setDefMin(Number(e.target.value))} /></Field>
              <Field label="Longest block (min)"><Input type="number" min={1} max={240} value={maxMin} onChange={(e) => setMaxMin(Number(e.target.value))} /></Field>
              <Field label="Cap per sensor per hour"><Input type="number" min={1} max={1000} value={cap} onChange={(e) => setCap(Number(e.target.value))} /></Field>
              <Field label="Days (≤90)"><Input type="number" min={1} max={90} value={days} onChange={(e) => setDays(Number(e.target.value))} /></Field>
            </div>
            <Button type="submit" variant="primary" disabled={busy || authSensors.length === 0 || defMin > maxMin}>Record authorization</Button>
          </form>
        )}
      </Panel>

      <Panel title="Allow list">
        <p className="text-sm text-muted">Never blocked by any tier: your own addresses, the lab, your VPN. Put the same addresses in each sensor&apos;s local allow list, which the sensor enforces itself.</p>
        <ul className="mt-2 space-y-1 text-sm">
          {view.allowlist.map((e) => (
            <li key={e.id} className="flex items-center gap-2">
              <span className="font-mono text-xs">{e.cidr}</span><span className="text-xs text-muted">{e.note} · {e.added_by}</span>
              {isOwner && <Button variant="secondary" disabled={busy} onClick={() => run(() => api(`${base}/allowlist/${e.id}/remove`, { method: "POST" }))}>Remove</Button>}
            </li>
          ))}
        </ul>
        {isAdmin && (
          <form className="mt-3 flex flex-wrap items-end gap-2" onSubmit={async (e) => {
            e.preventDefault();
            if (await post("/allowlist", { cidr, note })) { setCidr(""); setNote(""); }
          }}>
            <Field label="Address or range"><Input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="198.51.100.0/24" required /></Field>
            <Field label="Note"><Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="home" /></Field>
            <Button type="submit" disabled={busy || !cidr}>Add</Button>
          </form>
        )}
      </Panel>

      <Panel title="Sensors">
        {created && (
          <Alert tone="green">
            Sensor <b>{created.name}</b> registered. Its key is shown only now; put it in the machine&apos;s sensor.env:
            <code className="mt-1 block break-all font-mono text-xs" data-testid="sensor-key">{created.key}</code>
          </Alert>
        )}
        {view.sensors.length === 0 ? <p className="text-sm text-muted">No sensors yet. See infra/janus-sensor/README.md.</p> : (
          <DataTable head={["Name", "Status", "Last seen", "Version", "Key", ""]}>
            {view.sensors.map((s) => (
              <tr key={s.id} data-testid="sensor-row">
                <td><Link className="underline-offset-2 hover:underline" href={`/w/${ws}/shield/intrusion/sensors/${s.id}`}>{s.name}</Link></td>
                <td>{s.revoked_at ? <Badge tone="gray">Revoked</Badge> : s.online ? <Badge tone="green">Online</Badge> : <Badge tone="yellow">Offline</Badge>}
                  {s.open_host_alerts > 0 && <span className="ml-1"><Badge tone="orange">{s.open_host_alerts} host alert{s.open_host_alerts === 1 ? "" : "s"}</Badge></span>}</td>
                <td className="text-xs tabular">{formatDateTime(s.last_seen_at)}</td>
                <td className="font-mono text-xs">{s.agent_version}</td>
                <td className="font-mono text-xs">{s.key_prefix}…</td>
                <td>{isOwner && !s.revoked_at && (
                  <ConfirmButton label="Revoke" title={`Revoke ${s.name}?`} confirmLabel="Revoke"
                    body="Its key stops working at once. Bans it already applied expire on their own."
                    onConfirm={async () => { await post(`/sensors/${s.id}/revoke`, { reason: "Revoked from Intrusion Detection" }); }} />
                )}</td>
              </tr>
            ))}
          </DataTable>
        )}
        {isOwner && (
          <form className="mt-3 flex flex-wrap items-end gap-2" onSubmit={async (e) => {
            e.preventDefault();
            const out = await run(() => api<ShieldSensorCreated>(`${base}/sensors`, { method: "POST", body: { name: sensorName } }));
            if (out) { setCreated(out); setSensorName(""); }
          }}>
            <Field label="New sensor name"><Input value={sensorName} onChange={(e) => setSensorName(e.target.value)} placeholder="lab-host" required /></Field>
            <Button type="submit" disabled={busy || !sensorName}>Register sensor (two-factor)</Button>
          </form>
        )}
      </Panel>
    </div>
  );
}
