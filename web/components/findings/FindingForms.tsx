"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api/client";
import type { Asset, EvidenceSummary, FindingDetail, Project, Severity, ValidationStatus } from "@/lib/api/types";
import { SEVERITIES, STATUSES, severityLabel, statusHelp, statusLabel } from "@/lib/labels";
import { Icon } from "@/components/ui/Icon";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Input, Select, Textarea } from "@/components/ui/primitives";

const s = (f: FormData, k: string) => String(f.get(k) ?? "");

export function NewFinding({ ws, projects, assets }: { ws: string; projects: Project[]; assets: Asset[] }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [projectId, setProjectId] = useState(projects[0]?.id ?? "");
  const { busy, error, run } = useAction();
  const orgId = projects.find((p) => p.id === projectId)?.organization_id;
  const orgAssets = assets.filter((a) => a.organization_id === orgId);
  if (!open) return <Button variant="primary" onClick={() => setOpen(true)} disabled={!projects.length}><Icon name="plus" className="size-4" />Record a finding</Button>;
  return (
    <form className="space-y-3 rounded-lg border border-border-strong bg-surface p-4" onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      const created = await run(() => api<FindingDetail>(`/workspaces/${ws}/findings`, { method: "POST", body: {
        project_id: projectId, asset_id: s(f, "asset") || null, title: s(f, "title"), severity: s(f, "severity"),
        confidence: s(f, "confidence"), validation_status: s(f, "status"), description: s(f, "description"),
        impact: s(f, "impact"), remediation: s(f, "remediation"),
      } }), { refresh: false });
      if (created) router.push(`/w/${ws}/findings/${created.id}`);
    }}>
      {error && <Alert>{error}</Alert>}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <Field label="Project"><Select value={projectId} onChange={(e) => setProjectId(e.target.value)}>{projects.map((p) => <option key={p.id} value={p.id}>{p.organization_name} — {p.name}</option>)}</Select></Field>
        <Field label="Affected asset (optional)"><Select name="asset" defaultValue=""><option value="">None</option>{orgAssets.map((a) => <option key={a.id} value={a.id}>{a.value}</option>)}</Select></Field>
      </div>
      <Field label="Title"><Input name="title" required maxLength={300} /></Field>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Field label="Severity"><Select name="severity" defaultValue="medium">{SEVERITIES.map((v) => <option key={v} value={v}>{severityLabel[v]}</option>)}</Select></Field>
        <Field label="Confidence"><Select name="confidence" defaultValue="medium"><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></Select></Field>
        <Field label="Status" hint="Validate later, with evidence and a note.">
          <Select name="status" defaultValue="unverified">
            <option value="unverified">Unverified — evidence shows it</option>
            <option value="hypothesis">Hypothesis — not shown yet</option>
          </Select>
        </Field>
      </div>
      <Field label="Description"><Textarea name="description" maxLength={20000} /></Field>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <Field label="Potential impact"><Textarea name="impact" maxLength={10000} /></Field>
        <Field label="Recommended remediation"><Textarea name="remediation" maxLength={10000} /></Field>
      </div>
      <div className="flex gap-2"><Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : "Record finding"}</Button><Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button></div>
    </form>
  );
}

export function StatusDecision({ ws, finding }: { ws: string; finding: FindingDetail }) {
  const [status, setStatus] = useState<ValidationStatus>(finding.validation_status);
  const [note, setNote] = useState("");
  const { busy, error, run } = useAction();
  const needsNote = status === "validated" || status === "false_positive" || status === "remediated";
  return (
    <form className="space-y-3" onSubmit={async (e) => {
      e.preventDefault();
      if (await run(() => api(`/workspaces/${ws}/findings/${finding.id}/status`, { method: "POST", body: { status, note } }))) setNote("");
    }}>
      {error && <Alert>{error}</Alert>}
      <fieldset className="space-y-1.5">
        <legend className="mb-1 text-sm font-medium">Status</legend>
        {STATUSES.map((v) => (
          <label key={v} className="flex items-start gap-2 text-sm">
            <input type="radio" name="status" value={v} checked={status === v} onChange={() => setStatus(v)} className="mt-1 accent-[#CC1426]" />
            <span><span className="font-medium">{statusLabel[v]}</span> <span className="text-muted">— {statusHelp[v]}</span></span>
          </label>
        ))}
      </fieldset>
      <Field label={needsNote ? "Why (required, kept with the decision)" : "Note (optional)"}>
        <Textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} required={needsNote} />
      </Field>
      <Button type="submit" disabled={busy || status === finding.validation_status}>{busy ? "Saving…" : "Record decision"}</Button>
    </form>
  );
}

export function EditFinding({ ws, finding }: { ws: string; finding: FindingDetail }) {
  const { busy, error, run } = useAction();
  const [saved, setSaved] = useState(false);
  return (
    <form className="space-y-3" onSubmit={async (e) => {
      e.preventDefault();
      setSaved(false);
      const f = new FormData(e.currentTarget);
      if (await run(() => api(`/workspaces/${ws}/findings/${finding.id}`, { method: "PATCH", body: {
        title: s(f, "title"), severity: s(f, "severity") as Severity, confidence: s(f, "confidence"),
        description: s(f, "description"), impact: s(f, "impact"), remediation: s(f, "remediation"),
      } }))) setSaved(true);
    }}>
      {error && <Alert>{error}</Alert>}
      {saved && <Alert tone="green">Saved.</Alert>}
      <Field label="Title"><Input name="title" defaultValue={finding.title} required maxLength={300} /></Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Severity"><Select name="severity" defaultValue={finding.severity}>{SEVERITIES.map((v) => <option key={v} value={v}>{severityLabel[v]}</option>)}</Select></Field>
        <Field label="Confidence"><Select name="confidence" defaultValue={finding.confidence}><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></Select></Field>
      </div>
      <Field label="Description"><Textarea name="description" defaultValue={finding.description} maxLength={20000} /></Field>
      <Field label="Potential impact"><Textarea name="impact" defaultValue={finding.impact} maxLength={10000} /></Field>
      <Field label="Recommended remediation"><Textarea name="remediation" defaultValue={finding.remediation} maxLength={10000} /></Field>
      <Button type="submit" disabled={busy}>{busy ? "Saving…" : "Save changes"}</Button>
    </form>
  );
}

export function LinkEvidence({ ws, finding, options }: { ws: string; finding: FindingDetail; options: EvidenceSummary[] }) {
  const linked = new Set(finding.evidence.map((e) => e.id));
  const available = options.filter((o) => !linked.has(o.id));
  const { busy, error, run } = useAction();
  if (available.length === 0) return <p className="text-xs text-muted">All of this project&apos;s evidence is already linked.</p>;
  return (
    <form className="flex flex-col gap-2 sm:flex-row sm:items-end" onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      await run(() => api(`/workspaces/${ws}/findings/${finding.id}/evidence`, { method: "POST", body: { evidence_id: s(f, "evidence"), note: s(f, "note") } }));
    }}>
      <div className="flex-1"><Field label="Link evidence">
        <Select name="evidence">{available.map((o) => <option key={o.id} value={o.id}>{o.collected_at.slice(0, 16).replace("T", " ")} · {o.tool_name} · {o.sha256.slice(0, 10)}</option>)}</Select>
      </Field></div>
      <div className="flex-1"><Field label="Note"><Input name="note" maxLength={1000} /></Field></div>
      <Button type="submit" disabled={busy}>Link</Button>
      {error && <Alert>{error}</Alert>}
    </form>
  );
}
