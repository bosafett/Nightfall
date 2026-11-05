"use client";

import { useRouter } from "next/navigation";
import { api } from "@/lib/api/client";
import type { ReportSummary } from "@/lib/api/types";
import { useAction } from "@/components/ui/useAction";
import { Alert, Button } from "@/components/ui/primitives";

export function GenerateReport({ ws, projectId }: { ws: string; projectId: string }) {
  const router = useRouter();
  const { busy, error, run } = useAction();
  return (
    <div className="space-y-2">
      <Button variant="primary" disabled={busy} onClick={async () => {
        const r = await run(() => api<ReportSummary>(`/workspaces/${ws}/projects/${projectId}/reports`, { method: "POST" }), { refresh: false });
        if (r) router.push(`/w/${ws}/reports/${r.id}`);
      }}>{busy ? "Freezing current state…" : "Generate report"}</Button>
      {error && <Alert>{error}</Alert>}
    </div>
  );
}

export function PrintButton() {
  return <Button onClick={() => window.print()} className="print:hidden">Print or save as PDF</Button>;
}
