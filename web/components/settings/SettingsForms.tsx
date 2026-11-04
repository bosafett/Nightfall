"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { Invite, InviteCreated, Link as ResetLink, Member, Role } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can, roleDescription, roleLabel } from "@/lib/labels";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { Icon } from "@/components/ui/Icon";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Input, Select } from "@/components/ui/primitives";

const ROLES: Role[] = ["owner", "admin", "operator", "analyst", "viewer"];

export function WorkspaceName({ ws, name }: { ws: string; name: string }) {
  const { busy, error, run } = useAction();
  const [saved, setSaved] = useState(false);
  return (
    <form className="flex flex-col gap-3 sm:flex-row sm:items-end" onSubmit={async (e) => {
      e.preventDefault();
      setSaved(false);
      const value = String(new FormData(e.currentTarget).get("name"));
      if (await run(() => api(`/workspaces/${ws}`, { method: "PATCH", body: { name: value } }))) setSaved(true);
    }}>
      <div className="flex-1"><Field label="Workspace name"><Input name="name" defaultValue={name} maxLength={120} required /></Field></div>
      <Button type="submit" disabled={busy}>{busy ? "Saving…" : "Save name"}</Button>
      {error && <Alert>{error}</Alert>}
      {saved && <Alert tone="green">Saved.</Alert>}
    </form>
  );
}

/** Shows a one-time link with a copy button. The link is not retrievable later. */
function OneTimeLink({ label, link }: { label: string; link: ResetLink }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mt-3 rounded-md border border-yellow/50 bg-yellow/5 p-3 text-sm">
      <p className="font-medium text-yellow">{label}</p>
      <p className="mt-1 text-xs text-muted">Shown once. Send it over a channel you trust. Expires {formatDateTime(link.expires_at)}.</p>
      <div className="mt-2 flex gap-2">
        <Input readOnly value={link.url} className="font-mono text-xs" aria-label={label} data-testid="one-time-link" />
        <Button onClick={async () => { await navigator.clipboard.writeText(link.url); setCopied(true); }} aria-label="Copy link">
          <Icon name={copied ? "check" : "copy"} className="size-4" />{copied ? "Copied" : "Copy"}
        </Button>
      </div>
    </div>
  );
}

export function InviteForm({ ws, actorRole }: { ws: string; actorRole: Role }) {
  const { busy, error, run } = useAction();
  const [created, setCreated] = useState<InviteCreated | null>(null);
  const assignable = ROLES.filter((r) => can.assign(actorRole, r));
  return (
    <div>
      <form className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_12rem_auto] sm:items-end" onSubmit={async (e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        const form = e.currentTarget;
        const res = await run(() => api<InviteCreated>(`/workspaces/${ws}/invites`, {
          method: "POST", body: { email: String(f.get("email")), role: String(f.get("role")) },
        }));
        if (res) { setCreated(res); form.reset(); }
      }}>
        <Field label="Email"><Input name="email" type="email" required /></Field>
        <Field label="Role">
          <Select name="role" defaultValue="analyst">
            {assignable.map((r) => <option key={r} value={r}>{roleLabel[r]} — {roleDescription[r]}</option>)}
          </Select>
        </Field>
        <Button type="submit" variant="primary" disabled={busy}>{busy ? "Creating…" : "Create invite link"}</Button>
      </form>
      {error && <div className="mt-3"><Alert>{error}</Alert></div>}
      {created && <OneTimeLink label={`Invite link for ${created.invite.email}`} link={created.link} />}
    </div>
  );
}

export function RevokeInvite({ ws, invite }: { ws: string; invite: Invite }) {
  const { run } = useAction();
  return (
    <ConfirmButton label="Revoke" title="Revoke invite?" body={`The link sent to ${invite.email} will stop working.`}
      confirmLabel="Revoke invite"
      onConfirm={async () => { await run(() => api(`/workspaces/${ws}/invites/${invite.id}`, { method: "DELETE" })); }} />
  );
}

export function MemberActions({ ws, member, actorRole }: { ws: string; member: Member; actorRole: Role }) {
  const { busy, error, run } = useAction();
  const [link, setLink] = useState<ResetLink | null>(null);
  const assignable = ROLES.filter((r) => can.assign(actorRole, r));
  return (
    <div className="flex flex-wrap items-center justify-end gap-2">
      <Select aria-label={`Role for ${member.display_name}`} defaultValue={member.role} disabled={busy} className="w-auto py-1 text-xs"
        onChange={(e) => run(() => api(`/workspaces/${ws}/members/${member.id}`, { method: "PATCH", body: { role: e.target.value } }))}>
        {!assignable.includes(member.role) && <option value={member.role}>{roleLabel[member.role]}</option>}
        {assignable.map((r) => <option key={r} value={r}>{roleLabel[r]}</option>)}
      </Select>
      <ConfirmButton variant="secondary" label="Reset link" title="Issue a password reset link?"
        body={`Creates a single-use link for ${member.display_name}, valid 30 minutes. Their sessions end when it's used. Two-factor stays on.`}
        confirmLabel="Create link"
        onConfirm={async () => {
          const l = await run(() => api<ResetLink>(`/workspaces/${ws}/members/${member.id}/password-reset`, { method: "POST" }), { refresh: false });
          if (l) setLink(l);
        }} />
      <ConfirmButton label="Remove" title={`Remove ${member.display_name}?`} body="They lose access to this workspace immediately."
        confirmLabel="Remove member"
        onConfirm={async () => { await run(() => api(`/workspaces/${ws}/members/${member.id}`, { method: "DELETE" })); }} />
      {error && <p role="alert" className="w-full text-right text-xs text-crimson-text">{error}</p>}
      {link && <div className="w-full text-left"><OneTimeLink label={`Reset link for ${member.display_name}`} link={link} /></div>}
    </div>
  );
}
