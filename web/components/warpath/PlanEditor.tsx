"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api/client";
import type { Project, ScopeVersion, WarpathCatalogue, WarpathExerciseDetail } from "@/lib/api/types";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Input, Select, Textarea } from "@/components/ui/primitives";

type Step = { playbook_id: string; target: string; technique_id: string; expected_detection: string };

/** Draft a WARPATH exercise: lab playbook steps, each tagged with a technique its playbook
 * really performs. The owner approves it separately; approving runs nothing. */
export function PlanEditor({ ws, projects, labScopes, catalogue }: {
  ws: string; projects: Project[]; labScopes: Record<string, ScopeVersion>; catalogue: WarpathCatalogue;
}) {
  const router = useRouter();
  const { busy, error, run } = useAction();
  const eligible = projects.filter((p) => labScopes[p.id]);
  const [projectId, setProjectId] = useState(eligible[0]?.id ?? "");
  const targets = (labScopes[projectId]?.targets ?? []).map((t) => t.value);
  const first = catalogue.playbooks[0];
  const blank = (): Step => ({ playbook_id: first?.id ?? "", target: targets[0] ?? "", technique_id: first?.techniques[0]?.id ?? "", expected_detection: "" });
  const [steps, setSteps] = useState<Step[]>([blank()]);
  const set = (i: number, patch: Partial<Step>) => setSteps((s) => s.map((x, j) => (j === i ? { ...x, ...patch } : x)));

  if (eligible.length === 0) {
    return <p className="text-sm text-muted">WARPATH exercises need a project with an active lab scope (lab addresses only). Authorize one on a project first.</p>;
  }
  return (
    <form className="space-y-3" onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      const res = await run(() => api<WarpathExerciseDetail>(`/workspaces/${ws}/projects/${projectId}/warpath/exercises`, {
        method: "POST", body: { name: String(f.get("name")), objective: String(f.get("objective") ?? ""), steps },
      }), { refresh: false });
      if (res) router.push(`/w/${ws}/warpath/${res.id}`);
    }}>
      {error && <Alert>{error}</Alert>}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <Field label="Exercise name"><Input name="name" required maxLength={200} placeholder="Recon detection drill" /></Field>
        <Field label="Lab project">
          <Select value={projectId} onChange={(e) => { setProjectId(e.target.value); setSteps([blank()]); }}>
            {eligible.map((p) => <option key={p.id} value={p.id}>{p.organization_name} — {p.name}</option>)}
          </Select>
        </Field>
      </div>
      <Field label="Objective"><Textarea name="objective" rows={2} maxLength={2000} placeholder="What should the defenders see?" /></Field>
      <ol className="space-y-2">
        {steps.map((s, i) => {
          const pb = catalogue.playbooks.find((p) => p.id === s.playbook_id);
          return (
            <li key={i} className="grid grid-cols-1 gap-2 rounded border border-border p-2 md:grid-cols-[2rem_1fr_1fr_1fr_1.5fr_auto] md:items-end">
              <span className="font-mono text-xs text-muted">{i + 1}.</span>
              <Field label="Lab playbook">
                <Select value={s.playbook_id} onChange={(e) => {
                  const p = catalogue.playbooks.find((x) => x.id === e.target.value);
                  set(i, { playbook_id: e.target.value, technique_id: p?.techniques[0]?.id ?? "" });
                }}>
                  {catalogue.playbooks.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </Select>
              </Field>
              <Field label="Lab target">
                <Select value={s.target} onChange={(e) => set(i, { target: e.target.value })}>
                  {targets.map((t) => <option key={t} value={t}>{t}</option>)}
                </Select>
              </Field>
              <Field label="ATT&CK technique">
                <Select value={s.technique_id} onChange={(e) => set(i, { technique_id: e.target.value })}>
                  {(pb?.techniques ?? []).map((t) => <option key={t.id} value={t.id}>{t.id} {t.name}</option>)}
                </Select>
              </Field>
              <Field label="Expected detection"><Input value={s.expected_detection} maxLength={500} onChange={(e) => set(i, { expected_detection: e.target.value })} placeholder="e.g. IDS alert" /></Field>
              <Button type="button" variant="ghost" className="text-xs" disabled={steps.length === 1}
                onClick={() => setSteps((x) => x.filter((_, j) => j !== i))} aria-label={`Remove step ${i + 1}`}>Remove</Button>
            </li>
          );
        })}
      </ol>
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="secondary" disabled={steps.length >= 20} onClick={() => setSteps((x) => [...x, blank()])}>Add step</Button>
        <Button type="submit" disabled={busy}>Save draft</Button>
      </div>
      <p className="text-xs text-muted">{catalogue.note}</p>
    </form>
  );
}
