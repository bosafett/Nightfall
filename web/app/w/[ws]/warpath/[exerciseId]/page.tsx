import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { WarpathExerciseDetail } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { membership } from "@/lib/workspace";
import { ExerciseView } from "@/components/warpath/ExerciseView";
import { Badge, DataTable, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "WARPATH exercise" };

export default async function ExercisePage({ params }: { params: Promise<{ ws: string; exerciseId: string }> }) {
  const { ws, exerciseId } = await params;
  const [ex, me] = await Promise.all([apiGet<WarpathExerciseDetail>(`/workspaces/${ws}/warpath/exercises/${exerciseId}`), membership(ws)]);
  const c = ex.scorecard;
  return (
    <>
      <nav className="mb-2 text-sm text-muted"><Link href={`/w/${ws}/warpath`} className="hover:text-text">WARPATH</Link> /</nav>
      <PageHeader title={ex.name} subtitle={`${ex.project_name} · ${ex.objective || "No objective stated"}`} actions={<Badge tone="blue">{ex.state}</Badge>} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Steps"><ExerciseView ws={ws} ex={ex} role={me.role} /></Panel>
        <div className="space-y-6">
          <Panel title="Scorecard">
            <dl className="space-y-1 text-sm" data-testid="scorecard">
              {([["Steps scored", `${c.scored} / ${c.steps}`], ["Attacks succeeded", c.attacks_succeeded], ["Attacks blocked", c.attacks_blocked],
                ["Detected", c.detected], ["Partly detected", c.partial], ["Missed", c.missed],
                ["Median time to detect", c.median_minutes_to_detect != null ? `${c.median_minutes_to_detect} min` : "—"]] as const).map(([k, v]) => (
                <div key={k} className="flex justify-between"><dt className="text-muted">{k}</dt><dd className="tabular">{v}</dd></div>
              ))}
            </dl>
            <div className="mt-4">
              <DataTable head={["Tactic", "Detected", "Partly", "Missed", "Not scored"]}>
                {Object.entries(c.by_tactic).map(([t, r]) => (
                  <tr key={t}><td className="px-4 py-2 text-sm">{t}</td><td className="px-4 py-2 tabular">{r.detected}</td><td className="px-4 py-2 tabular">{r.partial}</td><td className="px-4 py-2 tabular">{r.missed}</td><td className="px-4 py-2 tabular">{r.not_scored}</td></tr>
                ))}
              </DataTable>
            </div>
          </Panel>
          <Panel title="Plan">
            <p className="font-mono text-xs text-muted">SHA-256 {ex.plan_sha256.slice(0, 16)}… · ATT&CK {ex.attack_release}</p>
            <p className="mt-1 text-xs text-muted">Created by {ex.created_by} {formatDateTime(ex.created_at)}{ex.approved_by && ` · approved by ${ex.approved_by} ${formatDateTime(ex.approved_at)}`}</p>
            {ex.workflow_run_id && <p className="mt-1 text-xs"><Link className="text-muted hover:text-crimson-text" href={`/w/${ws}/nexus/runs/${ex.workflow_run_id}`}>NEXUS run →</Link></p>}
          </Panel>
        </div>
      </div>
    </>
  );
}
