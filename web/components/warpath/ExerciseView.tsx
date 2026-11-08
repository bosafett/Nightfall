"use client";

import { api } from "@/lib/api/client";
import type { Role, WarpathExerciseDetail } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can } from "@/lib/labels";
import { ConfirmButton } from "@/components/ui/ConfirmButton";
import { useAction } from "@/components/ui/useAction";
import { Alert, Badge, Button, Input, Select } from "@/components/ui/primitives";

const detectionTone = { detected: "green", partial: "yellow", missed: "crimson", not_applicable: "gray" } as const;

export function ExerciseView({ ws, ex, role }: { ws: string; ex: WarpathExerciseDetail; role: Role }) {
  const { busy, error, run } = useAction();
  const base = `/workspaces/${ws}/warpath/exercises/${ex.id}`;
  const owner = can.launchPlaybooks(role);
  return (
    <div className="space-y-4">
      {error && <Alert>{error}</Alert>}
      <div className="flex flex-wrap gap-2">
        {ex.state === "draft" && owner && (
          <ConfirmButton label="Approve plan" title="Approve this exercise plan?" confirmLabel="Approve"
            body="The plan is frozen (fingerprinted). Approving runs nothing: each attack step is started by a person from BLACKSITE and needs its own lab approval."
            onConfirm={async () => { await run(() => api(`${base}/approve`, { method: "POST" })); }} />
        )}
        {ex.state === "approved" && owner && (
          <Button disabled={busy} onClick={() => run(() => api(`${base}/start`, { method: "POST" }))}>Start exercise</Button>
        )}
        {ex.state === "draft" && can.editFindings(role) && (
          <ConfirmButton label="Delete draft" title="Delete this draft?" confirmLabel="Delete"
            body="Only drafts can be deleted." onConfirm={async () => { await run(() => api(base, { method: "DELETE" })); }} />
        )}
        {(ex.state === "approved" || ex.state === "running") && owner && (
          <ConfirmButton label="Cancel exercise" title="Cancel this exercise?" confirmLabel="Cancel exercise"
            body="Steps not yet run are cancelled, with their queued lab operations."
            onConfirm={async () => { await run(() => api(`${base}/cancel`, { method: "POST" })); }} />
        )}
      </div>
      {ex.state === "running" && (
        <Alert tone="blue">Attack steps are started from BLACKSITE on the lab machine (lab runs never start from the hosted app). Score each step here after it runs.</Alert>
      )}
      <ol className="space-y-3" data-testid="exercise-steps">
        {ex.steps.map((s) => (
          <li key={s.step} className="rounded-md border border-border bg-bg p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-muted">{s.step}.</span>
              <Badge tone="blue">{s.technique.id}</Badge>
              <span className="font-medium">{s.technique.name}</span>
              <span className="text-xs text-muted">{s.technique.tactics.join(", ")}</span>
              {s.attack_state && <Badge tone="gray">attack: {s.attack_state.replace("_", " ")}</Badge>}
              {s.score && <Badge tone={detectionTone[s.score.detection as keyof typeof detectionTone] ?? "gray"}>{s.score.detection.replace("_", " ")}</Badge>}
            </div>
            <p className="mt-1 text-sm text-muted"><span className="font-mono">{s.playbook_id}</span> on <span className="font-mono">{s.target}</span> · expected: {s.expected_detection || "not stated"}</p>
            {s.score && (
              <p className="mt-1 text-xs text-muted">Attack {s.score.attack_result} · {s.score.minutes_to_detect != null ? `${s.score.minutes_to_detect} min to detect · ` : ""}scored by {s.score.scored_by} {formatDateTime(s.score.scored_at)}{s.score.note && ` · ${s.score.note}`}</p>
            )}
            {(s.score_state === "running" || (s.score && ex.state !== "cancelled")) && can.editFindings(role) && (
              <form className="mt-2 flex flex-wrap items-end gap-2" onSubmit={(e) => {
                e.preventDefault();
                const f = new FormData(e.currentTarget);
                const minutes = String(f.get("minutes") ?? "");
                run(() => api(`${base}/steps/${s.step}/score`, { method: "POST", body: {
                  attack_result: String(f.get("attack")), detection: String(f.get("detection")),
                  minutes_to_detect: minutes ? Number(minutes) : null, note: String(f.get("note") ?? ""),
                } }));
              }}>
                <Select name="attack" aria-label={`Attack result, step ${s.step}`} defaultValue="succeeded">
                  <option value="succeeded">Attack succeeded</option><option value="failed">Attack failed</option><option value="blocked">Attack blocked</option>
                </Select>
                <Select name="detection" aria-label={`Detection, step ${s.step}`} defaultValue="detected">
                  <option value="detected">Detected</option><option value="partial">Partly detected</option><option value="missed">Missed</option><option value="not_applicable">Not applicable</option>
                </Select>
                <Input name="minutes" type="number" min={0} placeholder="Minutes to detect" aria-label={`Minutes to detect, step ${s.step}`} className="w-40" />
                <Input name="note" placeholder="Note (which alert, which tool)" aria-label={`Note, step ${s.step}`} maxLength={2000} className="min-w-0 flex-1" />
                <Button type="submit" disabled={busy}>{s.score ? "Re-score" : "Score step"}</Button>
              </form>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}
