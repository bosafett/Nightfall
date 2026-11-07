"use client";

import { useState } from "react";
import { api } from "@/lib/api/client";
import type { AuditExportCheck, AuditExportPage } from "@/lib/api/types";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button } from "@/components/ui/primitives";

type Line = { position: number; hash: string; record: { id: string } };

/** Downloads the hash-chained export, and checks a kept export against the live log. */
export function AuditExport({ ws }: { ws: string }) {
  const exp = useAction();
  const chk = useAction();
  const [count, setCount] = useState<number | null>(null);
  const [check, setCheck] = useState<AuditExportCheck | null>(null);

  async function download() {
    setCount(null);
    await exp.run(async () => {
      const lines: string[] = [];
      let cursor: AuditExportPage["next"] = null;
      for (;;) {
        const page: AuditExportPage = await api<AuditExportPage>(`/workspaces/${ws}/audit/export`, { method: "POST", body: cursor ?? undefined });
        if (lines.length === 0) {
          lines.push(JSON.stringify({ format: page.format, workspace_id: page.workspace_id, genesis: page.genesis, cutoff: page.cutoff }));
        }
        page.records.forEach((r) => lines.push(JSON.stringify(r)));
        if (!page.next) break;
        cursor = page.next;
      }
      const blob = new Blob([lines.join("\n") + "\n"], { type: "application/x-ndjson" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `audit-export-${ws}-${new Date().toISOString().slice(0, 19).replace(/:/g, "")}.ndjson`;
      a.click();
      URL.revokeObjectURL(a.href);
      setCount(lines.length - 1);
    });
  }

  async function verify(file: File) {
    setCheck(null);
    await chk.run(async () => {
      const rows = (await file.text()).trim().split("\n");
      let last: Line | null = null;
      try {
        const parsed = JSON.parse(rows[rows.length - 1] ?? "") as Line;
        if (rows.length > 1 && parsed.position && parsed.hash && parsed.record?.id) last = parsed;
      } catch { /* handled below */ }
      if (!last) throw new Error("That file isn't an audit export with at least one event.");
      setCheck(await api<AuditExportCheck>(`/workspaces/${ws}/audit/export/check`, {
        method: "POST", body: { through_id: last.record.id, position: last.position, hash: last.hash },
      }));
    });
  }

  return (
    <div className="space-y-3 text-sm">
      {exp.error && <Alert>{exp.error}</Alert>}
      {count !== null && <Alert tone="green">Exported {count} events. Keep the file somewhere this system can&apos;t change.</Alert>}
      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={download} disabled={exp.busy}>{exp.busy ? "Exporting…" : "Export audit log"}</Button>
        <label className="cursor-pointer text-muted hover:text-text">
          <span className="underline">Check a kept export</span>
          <input type="file" accept=".ndjson,application/x-ndjson,application/json" className="sr-only" data-testid="check-export"
            disabled={chk.busy} onChange={(e) => { const f = e.target.files?.[0]; if (f) void verify(f); e.target.value = ""; }} />
        </label>
      </div>
      {chk.error && <Alert>{chk.error}</Alert>}
      {check && <Alert tone={check.match ? "green" : "crimson"}><span data-testid="check-result">{check.detail}</span></Alert>}
      <p className="text-xs text-muted">
        Each event is chained to the one before it with SHA-256, so changing, removing or inserting an exported event
        shows up when you check the file later. This detects tampering; it doesn&apos;t prevent it. Secret-looking fields
        are redacted before hashing, sign-in events without a workspace aren&apos;t included, and events from the last
        five minutes wait for the next export.
      </p>
    </div>
  );
}
