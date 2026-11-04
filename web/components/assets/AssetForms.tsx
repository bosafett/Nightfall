"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { Asset, AssetKind, AssetOwnership } from "@/lib/api/types";
import { assetKindLabel, ownershipLabel } from "@/lib/labels";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button, Field, Input, Select, Textarea } from "@/components/ui/primitives";

const KINDS = Object.keys(assetKindLabel) as AssetKind[];
const OWNERSHIP = Object.keys(ownershipLabel) as AssetOwnership[];

export function NewAsset({ ws, orgId }: { ws: string; orgId: string }) {
  const { busy, error, run } = useAction();
  return (
    <form className="grid grid-cols-1 gap-2 sm:grid-cols-[11rem_minmax(0,1fr)_13rem_auto] sm:items-end" onSubmit={async (e) => {
      e.preventDefault();
      const form = e.currentTarget;
      const f = new FormData(form);
      const ok = await run(() => api<Asset>(`/workspaces/${ws}/assets`, { method: "POST", body: {
        organization_id: orgId, kind: String(f.get("kind")), value: String(f.get("value")), ownership: String(f.get("ownership")),
      } }));
      if (ok) form.reset();
    }}>
      <Field label="Asset type"><Select name="kind" defaultValue="domain">{KINDS.map((k) => <option key={k} value={k}>{assetKindLabel[k]}</option>)}</Select></Field>
      <Field label="Asset value"><Input name="value" required maxLength={500} className="font-mono" /></Field>
      <Field label="Ownership"><Select name="ownership" defaultValue="organization">{OWNERSHIP.map((o) => <option key={o} value={o}>{ownershipLabel[o]}</option>)}</Select></Field>
      <Button type="submit" disabled={busy}>{busy ? "Adding…" : "Register asset"}</Button>
      {error && <div className="sm:col-span-4"><Alert>{error}</Alert></div>}
    </form>
  );
}

export function EditAsset({ ws, asset }: { ws: string; asset: Asset }) {
  const { busy, error, run } = useAction();
  const [saved, setSaved] = useState(false);
  return (
    <form className="space-y-3" onSubmit={async (e) => {
      e.preventDefault();
      setSaved(false);
      const f = new FormData(e.currentTarget);
      if (await run(() => api(`/workspaces/${ws}/assets/${asset.id}`, { method: "PATCH", body: {
        ownership: String(f.get("ownership")), notes: String(f.get("notes")),
      } }))) setSaved(true);
    }}>
      {error && <Alert>{error}</Alert>}
      {saved && <Alert tone="green">Saved.</Alert>}
      <Field label="Ownership"><Select name="ownership" defaultValue={asset.ownership}>{OWNERSHIP.map((o) => <option key={o} value={o}>{ownershipLabel[o]}</option>)}</Select></Field>
      <Field label="Notes"><Textarea name="notes" defaultValue={asset.notes} maxLength={10000} /></Field>
      <Button type="submit" disabled={busy}>{busy ? "Saving…" : "Save changes"}</Button>
    </form>
  );
}
