"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { Playbook, PlaybookCategory } from "@/lib/api/types";
import { availability, availabilityLabel, availabilityTone, categoryLabel, profileLabel, riskLabel, riskTone } from "@/lib/blackops";
import { Badge, EmptyState, Field, Input, Select } from "@/components/ui/primitives";

/** Browsable playbook library: search and category filter run in the browser over the server's list. */
export function Library({ ws, playbooks }: { ws: string; playbooks: Playbook[] }) {
  const [q, setQ] = useState("");
  const [category, setCategory] = useState<PlaybookCategory | "">("");
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return playbooks.filter((p) =>
      (!category || p.category === category) &&
      (!needle || `${p.name} ${p.summary} ${p.steps.map((s) => s.label).join(" ")}`.toLowerCase().includes(needle)));
  }, [playbooks, q, category]);
  const categories = [...new Set(playbooks.map((p) => p.category))];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Field label="Search"><Input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Name, purpose or tool" data-testid="playbook-search" /></Field>
        <Field label="Category">
          <Select value={category} onChange={(e) => setCategory(e.target.value as PlaybookCategory | "")} data-testid="playbook-category">
            <option value="">All categories</option>
            {categories.map((c) => <option key={c} value={c}>{categoryLabel[c]}</option>)}
          </Select>
        </Field>
      </div>
      {shown.length === 0 ? <EmptyState title="No playbooks match" body="Clear the search or pick another category." /> : (
        <ul className="grid grid-cols-1 gap-3 lg:grid-cols-2" data-testid="playbook-list">
          {shown.map((p) => {
            const a = availability(p);
            return (
              <li key={p.id}>
                <Link href={`/w/${ws}/blacksite/ops/${p.id}`} className="block h-full rounded-lg border border-border bg-surface p-4 hover:border-border-strong">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <span>
                      <span className="font-medium">{p.name}</span>
                      <span className="ml-2 font-mono text-xs text-muted">v{p.version}</span>
                    </span>
                    <Badge tone={availabilityTone[a]}>{availabilityLabel[a]}</Badge>
                  </div>
                  <p className="mt-1 text-sm text-muted">{p.summary}</p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    <Badge tone="gray">{categoryLabel[p.category]}</Badge>
                    <Badge tone={riskTone[p.risk_class]}>{riskLabel[p.risk_class]}</Badge>
                    {p.profiles.map((pr) => <Badge key={pr} tone={pr === "lab" ? "orange" : "blue"}>{profileLabel[pr]}</Badge>)}
                    <Badge tone={p.needs_approval_live ? "yellow" : "green"}>{p.needs_approval_live ? "Needs approval" : "No approval (passive)"}</Badge>
                  </div>
                  {p.blocked_reason && <p className="mt-2 text-xs text-crimson-text">{p.blocked_reason}</p>}
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
