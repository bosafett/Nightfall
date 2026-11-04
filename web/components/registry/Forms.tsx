"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api/client";
import type { AssessmentType, Organization, Project, ProjectStatus } from "@/lib/api/types";
import { assessmentTypeLabel, projectStatusLabel } from "@/lib/labels";
import { useAction } from "@/components/ui/useAction";
import { Icon } from "@/components/ui/Icon";
import { Alert, Button, Field, Input, Select, Textarea } from "@/components/ui/primitives";

const str = (f: FormData, k: string) => String(f.get(k) ?? "");

/** Collapsible "new …" form: a button that opens an inline panel. */
function Creator({ label, children }: { label: string; children: (close: () => void) => React.ReactNode }) {
  const [open, setOpen] = useState(false);
  if (!open) {
    return <Button variant="primary" onClick={() => setOpen(true)}><Icon name="plus" className="size-4" />{label}</Button>;
  }
  return <div className="w-full rounded-lg border border-border-strong bg-surface p-4 sm:w-[28rem]">{children(() => setOpen(false))}</div>;
}

export function NewOrganization({ ws }: { ws: string }) {
  const router = useRouter();
  const { busy, error, run } = useAction();
  return (
    <Creator label="New organization">
      {(close) => (
        <form className="space-y-3" onSubmit={async (e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          const org = await run(() => api<Organization>(`/workspaces/${ws}/organizations`, {
            method: "POST", body: { name: str(f, "name"), notes: str(f, "notes") },
          }), { refresh: false });
          if (org) router.push(`/w/${ws}/targets/${org.id}`);
        }}>
          {error && <Alert>{error}</Alert>}
          <Field label="Organization name"><Input name="name" maxLength={200} required autoFocus /></Field>
          <Field label="Notes" hint="Optional. Context, contacts, engagement reference."><Textarea name="notes" maxLength={10000} /></Field>
          <div className="flex gap-2">
            <Button type="submit" variant="primary" disabled={busy}>{busy ? "Creating…" : "Create organization"}</Button>
            <Button variant="ghost" onClick={close}>Cancel</Button>
          </div>
        </form>
      )}
    </Creator>
  );
}

export function EditOrganization({ ws, org }: { ws: string; org: Organization }) {
  const { busy, error, run } = useAction();
  const [saved, setSaved] = useState(false);
  return (
    <form className="space-y-3" onSubmit={async (e) => {
      e.preventDefault();
      setSaved(false);
      const f = new FormData(e.currentTarget);
      const ok = await run(() => api(`/workspaces/${ws}/organizations/${org.id}`, {
        method: "PATCH", body: { name: str(f, "name"), notes: str(f, "notes") },
      }));
      if (ok) setSaved(true);
    }}>
      {error && <Alert>{error}</Alert>}
      {saved && <Alert tone="green">Saved.</Alert>}
      <Field label="Name"><Input name="name" defaultValue={org.name} maxLength={200} required /></Field>
      <Field label="Notes"><Textarea name="notes" defaultValue={org.notes} maxLength={10000} /></Field>
      <Button type="submit" disabled={busy}>{busy ? "Saving…" : "Save changes"}</Button>
    </form>
  );
}

const typeOptions = Object.entries(assessmentTypeLabel) as [AssessmentType, string][];
const statusOptions = Object.entries(projectStatusLabel) as [ProjectStatus, string][];

export function NewProject({ ws, orgId }: { ws: string; orgId: string }) {
  const router = useRouter();
  const { busy, error, run } = useAction();
  return (
    <Creator label="New project">
      {(close) => (
        <form className="space-y-3" onSubmit={async (e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          const p = await run(() => api<Project>(`/workspaces/${ws}/projects`, {
            method: "POST",
            body: { organization_id: orgId, name: str(f, "name"), description: str(f, "description"), assessment_type: str(f, "assessment_type") },
          }), { refresh: false });
          if (p) router.push(`/w/${ws}/targets/${orgId}/projects/${p.id}`);
        }}>
          {error && <Alert>{error}</Alert>}
          <Field label="Project name"><Input name="name" maxLength={200} required autoFocus /></Field>
          <Field label="Assessment type">
            <Select name="assessment_type" required defaultValue="reconnaissance">
              {typeOptions.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select>
          </Field>
          <Field label="Description" hint="Optional."><Textarea name="description" maxLength={10000} /></Field>
          <div className="flex gap-2">
            <Button type="submit" variant="primary" disabled={busy}>{busy ? "Creating…" : "Create project"}</Button>
            <Button variant="ghost" onClick={close}>Cancel</Button>
          </div>
        </form>
      )}
    </Creator>
  );
}

export function EditProject({ ws, project, canWrite }: { ws: string; project: Project; canWrite: boolean }) {
  const { busy, error, run } = useAction();
  const [saved, setSaved] = useState(false);
  return (
    <form className="space-y-3" onSubmit={async (e) => {
      e.preventDefault();
      setSaved(false);
      const f = new FormData(e.currentTarget);
      const ok = await run(() => api(`/workspaces/${ws}/projects/${project.id}`, {
        method: "PATCH",
        body: { name: str(f, "name"), description: str(f, "description"), assessment_type: str(f, "assessment_type"), status: str(f, "status") },
      }));
      if (ok) setSaved(true);
    }}>
      {error && <Alert>{error}</Alert>}
      {saved && <Alert tone="green">Saved.</Alert>}
      <fieldset disabled={!canWrite} className="space-y-3">
        <Field label="Name"><Input name="name" defaultValue={project.name} maxLength={200} required /></Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Assessment type">
            <Select name="assessment_type" defaultValue={project.assessment_type}>
              {typeOptions.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select>
          </Field>
          <Field label="Status">
            <Select name="status" defaultValue={project.status}>
              {statusOptions.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select>
          </Field>
        </div>
        <Field label="Description"><Textarea name="description" defaultValue={project.description} maxLength={10000} /></Field>
        {canWrite && <Button type="submit" disabled={busy}>{busy ? "Saving…" : "Save changes"}</Button>}
      </fieldset>
    </form>
  );
}
