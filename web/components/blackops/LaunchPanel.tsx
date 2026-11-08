"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api/client";
import type { PlaybookDetail, PlaybookRunDetail, Preflight, Project, TestIdentities } from "@/lib/api/types";
import { profileLabel, riskLabel, riskTone } from "@/lib/blackops";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Field, Input, Select, Textarea } from "@/components/ui/primitives";

const mark = { pass: "✓ Pass", fail: "✕ Fail", info: "ℹ Note" } as const;
const markTone = { pass: "text-green", fail: "text-crimson-text", info: "text-muted" } as const;

/**
 * Target selection → preflight → proposed steps → launch. The server runs the same
 * preflight again on launch and is the only authority; this panel just shows it first.
 */
export function LaunchPanel({ ws, playbook, projects, canRun, identities }: {
  ws: string; playbook: PlaybookDetail; projects: Project[]; canRun: boolean; identities?: TestIdentities["identities"];
}) {
  const router = useRouter();
  const { busy, error, setError, run } = useAction();
  const [projectId, setProjectId] = useState(projects[0]?.id ?? "");
  const [target, setTarget] = useState("");
  const [pre, setPre] = useState<Preflight | null>(null);
  const [chosen, setChosen] = useState<string[]>([]);
  const [pathsText, setPathsText] = useState("");
  const paths = pathsText.split("\n").map((p) => p.trim()).filter(Boolean);
  const profileB = playbook.profiles.includes("validation");
  const host = target.trim().toLowerCase().replace(/\.$/, "");
  const usable = (identities ?? []).filter((i) => !i.retired_at && i.origin.replace("https://", "").split(":")[0] === host);

  async function check() {
    const res = await run(() => api<Preflight>(`/workspaces/${ws}/blackops/projects/${projectId}/preflight`, {
      method: "POST", body: { playbook_id: playbook.id, target, identity_ids: chosen.filter(Boolean), paths },
    }), { refresh: false });
    setPre(res ?? null);
  }

  if (projects.length === 0) return <p className="text-sm text-muted">Create a project with an authorized scope first.</p>;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="Project">
          <Select value={projectId} onChange={(e) => { setProjectId(e.target.value); setPre(null); }} data-testid="launch-project">
            {projects.map((p) => <option key={p.id} value={p.id}>{p.organization_name} — {p.name}</option>)}
          </Select>
        </Field>
        <Field label="Target" hint={`Type: ${playbook.target_types.join(" or ")}. Must be in the project's authorized scope.`}>
          <Input value={target} onChange={(e) => { setTarget(e.target.value); setPre(null); }} maxLength={300} placeholder="www.example.com" data-testid="launch-target" />
        </Field>
      </div>
      {profileB && (
        <fieldset className="space-y-1" data-testid="launch-identities">
          <legend className="text-sm font-medium">Test identities ({playbook.identities_required} needed)</legend>
          {usable.length === 0
            ? <p className="text-xs text-muted">No active test identity is registered for {host || "this target"}. Register one under Test identities on the BLACK OPS page.</p>
            : playbook.identities_required >= 2
              ? (["Higher-role identity", "Lower-role identity"] as const).map((label, n) => (
                <Field key={label} label={label}>
                  <Select value={chosen[n] ?? ""} onChange={(e) => {
                    setPre(null);
                    setChosen((c) => { const next = [...c]; next[n] = e.target.value; return next; });
                  }}>
                    <option value="">Choose…</option>
                    {usable.map((i) => <option key={i.id} value={i.id}>{i.label}{i.role_description && ` (${i.role_description})`}</option>)}
                  </Select>
                </Field>
              ))
              : usable.map((i) => (
                <label key={i.id} className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={chosen.includes(i.id)} onChange={(e) => {
                    setPre(null);
                    setChosen((c) => (e.target.checked ? [...c, i.id] : c.filter((x) => x !== i.id)));
                  }} />
                  {i.label} <span className="text-xs text-muted">{i.role_description}</span>
                </label>
              ))}
          {playbook.takes_paths && (
            <Field label="Paths that belong to the higher role" hint="One per line, on this target only, like /admin/users. Up to 50. You choose them; nothing is guessed.">
              <Textarea rows={4} value={pathsText} onChange={(e) => { setPathsText(e.target.value); setPre(null); }} className="font-mono" data-testid="launch-paths" />
            </Field>
          )}
        </fieldset>
      )}
      <Button onClick={check} disabled={busy || !target.trim() || !projectId} data-testid="run-preflight">{busy ? "Checking…" : "Run preflight"}</Button>
      {error && <Alert>{error}</Alert>}
      {pre && (
        <div className="space-y-4" data-testid="preflight">
          <ul className="divide-y divide-border rounded-lg border border-border">
            {pre.checks.map((c) => (
              <li key={c.key} className="flex flex-col gap-1 px-4 py-2.5 sm:flex-row sm:items-baseline sm:gap-4" data-check={c.key} data-status={c.status}>
                <span className={`w-20 shrink-0 font-mono text-xs ${markTone[c.status]}`}>{mark[c.status]}</span>
                <span className="w-48 shrink-0 text-sm font-medium">{c.label}</span>
                <span className="text-sm text-muted">{c.detail}</span>
              </li>
            ))}
          </ul>
          <div>
            <h3 className="mb-2 text-sm font-medium">Proposed actions{pre.profile && <> · profile {profileLabel[pre.profile]}</>}{pre.scope_version != null && <> · scope v{pre.scope_version}</>}</h3>
            <ol className="space-y-1 text-sm">
              {pre.steps.map((s) => (
                <li key={s.step} className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-muted">{s.step}.</span>{s.label} on <span className="font-mono">{pre.target}</span>
                  <Badge tone={riskTone[s.risk_class]}>{riskLabel[s.risk_class]}</Badge>
                </li>
              ))}
            </ol>
          </div>
          {!canRun ? <Alert tone="blue">Only workspace owners launch playbooks.</Alert>
            : !pre.allowed ? <Alert tone="yellow">Preflight failed: nothing can be launched until every check passes.</Alert>
            : (
              <ConfirmButton variant="secondary" label="Launch playbook"
                title={`Launch ${playbook.name} v${pre.version}?`}
                body={`${pre.steps.length} operation(s) against ${pre.target}, pinned to scope v${pre.scope_version}. ${pre.needs_approval ? "They wait for an explicit approval (with a fresh two-factor check)." : "Passive steps run immediately."} Your name and the definition hash are recorded.`}
                confirmLabel="Launch"
                onConfirm={async () => {
                  setError(null);
                  const r = await api<PlaybookRunDetail>(`/workspaces/${ws}/blackops/projects/${projectId}/runs`, {
                    method: "POST",
                    body: { playbook_id: playbook.id, target, identity_ids: chosen.filter(Boolean), paths, version: pre.version, definition_sha256: pre.definition_sha256 },
                  });
                  router.push(`/w/${ws}/blacksite/ops/runs/${r.id}`);
                }} />
            )}
        </div>
      )}
    </div>
  );
}
