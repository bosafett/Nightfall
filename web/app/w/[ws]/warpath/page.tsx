import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Project, ScopeVersion, WarpathCatalogue, WarpathExercise } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { can } from "@/lib/labels";
import { membership } from "@/lib/workspace";
import { PlanEditor } from "@/components/warpath/PlanEditor";
import { Badge, DataTable, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "WARPATH" };
const stateTone = { draft: "gray", approved: "blue", running: "yellow", finished: "green", cancelled: "gray" } as const;

export default async function WarpathPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  const [exercises, catalogue, projects, me] = await Promise.all([
    apiGet<WarpathExercise[]>(`/workspaces/${ws}/warpath/exercises`),
    apiGet<WarpathCatalogue>(`/workspaces/${ws}/warpath/catalogue`),
    apiGet<Project[]>(`/workspaces/${ws}/projects`),
    membership(ws),
  ]);
  const labScopes: Record<string, ScopeVersion> = {};
  if (can.editFindings(me.role)) {
    await Promise.all(projects.map(async (p) => {
      const active = (await apiGet<ScopeVersion[]>(`/workspaces/${ws}/projects/${p.id}/scopes`)).find((v) => v.status === "active");
      if (active?.is_lab) labScopes[p.id] = active;
    }));
  }
  return (
    <>
      <PageHeader title="WARPATH" subtitle="Purple-team exercises in the lab: attack steps a person starts, each followed by a detection score." />
      <div className="space-y-6">
        <Panel title="Exercises">
          {exercises.length === 0 ? <p className="text-sm text-muted">No exercises yet.</p> : (
            <DataTable head={["Exercise", "Project", "State", "Created"]}>
              {exercises.map((x) => (
                <tr key={x.id}>
                  <td className="px-4 py-2.5"><Link className="font-medium hover:text-crimson-text" href={`/w/${ws}/warpath/${x.id}`}>{x.name}</Link></td>
                  <td className="px-4 py-2.5 text-sm">{x.project_name}</td>
                  <td className="px-4 py-2.5"><Badge tone={stateTone[x.state as keyof typeof stateTone] ?? "gray"}>{x.state}</Badge></td>
                  <td className="px-4 py-2.5 font-mono text-xs text-muted tabular">{formatDateTime(x.created_at)}<span className="block">{x.created_by}</span></td>
                </tr>
              ))}
            </DataTable>
          )}
        </Panel>
        {can.editFindings(me.role) && (
          <Panel title="Plan an exercise">
            <PlanEditor ws={ws} projects={projects} labScopes={labScopes} catalogue={catalogue} />
          </Panel>
        )}
        <p className="text-xs text-muted" data-testid="attack-attribution">
          Techniques: {catalogue.release && `ATT&CK Enterprise ${catalogue.release}`}. {catalogue.attribution}
        </p>
      </div>
    </>
  );
}
