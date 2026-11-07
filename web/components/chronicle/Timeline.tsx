"use client";

import Link from "next/link";
import { useState } from "react";
import { api } from "@/lib/api/client";
import type { Chronicle, ChronicleEntry } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { Alert, Badge, Button } from "@/components/ui/primitives";

const LINKS: Record<string, (ws: string, id: string) => string> = {
  operation: (ws, id) => `/w/${ws}/recon/${id}`,
  finding: (ws, id) => `/w/${ws}/findings/${id}`,
  report: (ws, id) => `/w/${ws}/reports/${id}`,
  agent_task: (ws, id) => `/w/${ws}/agents/${id}`,
  playbook_run: (ws, id) => `/w/${ws}/blacksite/ops/runs/${id}`,
};
const LINK_TEXT: Record<string, string> = {
  operation: "Operation", finding: "Finding", report: "Report", agent_task: "Agent task", playbook_run: "Playbook run",
};

function detailText(d: Record<string, unknown>): string {
  return Object.entries(d)
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

function Entry({ ws, e }: { ws: string; e: ChronicleEntry }) {
  const link = e.entity_type && e.entity_id ? LINKS[e.entity_type] : undefined;
  return (
    <li className="relative border-l border-border pb-4 pl-4 last:pb-0">
      <span className={`absolute -left-[5px] top-1.5 h-2.5 w-2.5 rounded-full ${e.actor_type === "agent" ? "bg-blue" : e.actor_type === "system" ? "bg-faint" : "bg-crimson"}`} aria-hidden />
      <p className="font-mono text-xs text-muted tabular">{formatDateTime(e.occurred_at)}</p>
      <p className="text-sm">
        {e.summary}
        {e.actor_type === "agent" && <span className="ml-2"><Badge tone="blue">AI</Badge></span>}
      </p>
      {Object.keys(e.details).length > 0 && <p className="break-words text-xs text-muted">{detailText(e.details)}</p>}
      <p className="text-xs">
        {link && e.entity_id && <Link className="text-muted hover:text-crimson-text" href={link(ws, e.entity_id)}>{LINK_TEXT[e.entity_type ?? ""]} →</Link>}
        {e.evidence_ids.length > 0 && <span className="ml-2 font-mono text-muted">evidence {e.evidence_ids.map((i) => i.slice(0, 8)).join(", ")}</span>}
      </p>
    </li>
  );
}

/** CHRONICLE: the project's history, newest first, from the audit log (nothing copied). */
export function Timeline({ ws, path, initial, query = {} }: {
  ws: string; path: string; initial: Chronicle; query?: Record<string, string>;
}) {
  const [entries, setEntries] = useState(initial.entries);
  const [next, setNext] = useState(initial.next_before);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function older() {
    if (!next) return;
    setBusy(true);
    setError(null);
    try {
      const q = new URLSearchParams({ ...query, before: next, limit: "50" });
      const page = await api<Chronicle>(`${path}?${q}`);
      setEntries((cur) => [...cur, ...page.entries]);
      setNext(page.next_before);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't load older entries.");
    } finally {
      setBusy(false);
    }
  }

  if (entries.length === 0) return <p className="text-sm text-muted">Nothing has been recorded yet.</p>;
  return (
    <div className="space-y-3" data-testid="chronicle">
      <ol className="ml-1">{entries.map((e) => <Entry key={e.id} ws={ws} e={e} />)}</ol>
      {error && <Alert>{error}</Alert>}
      {next && <Button variant="ghost" className="text-xs" disabled={busy} onClick={older}>Show older</Button>}
      <p className="text-xs text-muted">Built from the audit log on request. Entries link to the original records; the full audit log is under SYSTEM → Audit Log.</p>
    </div>
  );
}
