import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { PlaybookDetail, PlaybookLibrary, PlaybookRun, Project, TestIdentities } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { availability, availabilityLabel, availabilityTone, categoryLabel, profileLabel, riskLabel, riskTone } from "@/lib/blackops";
import { membership } from "@/lib/workspace";
import { EnableToggle } from "@/components/blackops/Controls";
import { LaunchPanel } from "@/components/blackops/LaunchPanel";
import { RunsTable } from "@/components/blackops/RunsTable";
import { Alert, Badge, DataTable, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "Playbook" };

export default async function PlaybookPage({ params }: { params: Promise<{ ws: string; playbookId: string }> }) {
  const { ws, playbookId } = await params;
  const m = await membership(ws);
  if (m.role !== "owner") return <Alert tone="blue">BLACK OPS is part of BLACKSITE and limited to workspace owners.</Alert>;
  const [p, lib, projects, runs] = await Promise.all([
    apiGet<PlaybookDetail>(`/workspaces/${ws}/blackops/playbooks/${encodeURIComponent(playbookId)}`),
    apiGet<PlaybookLibrary>(`/workspaces/${ws}/blackops/playbooks`),
    apiGet<Project[]>(`/workspaces/${ws}/projects`),
    apiGet<PlaybookRun[]>(`/workspaces/${ws}/blackops/runs?playbook_id=${encodeURIComponent(playbookId)}&limit=10`),
  ]);
  const a = availability(p);
  const identities = p.profiles.includes("validation")
    ? (await apiGet<TestIdentities>(`/workspaces/${ws}/test-identities`)).identities
    : undefined;
  const facts: [string, string][] = [
    ["Version", `v${p.version}`],
    ["Definition SHA-256", `${p.definition_sha256.slice(0, 16)}…`],
    ["Category", categoryLabel[p.category]],
    ["Target types", p.target_types.join(", ")],
    ["Expected duration", p.expected_duration],
    ["Approval (live)", p.needs_approval_live ? "Explicit approval" : "None (passive)"],
    ["Runs in this workspace", String(p.runs)],
  ];
  return (
    <>
      <nav className="mb-2 text-sm text-muted">
        <Link href={`/w/${ws}/blacksite`} className="hover:text-text">BLACKSITE</Link> / <Link href={`/w/${ws}/blacksite/ops`} className="hover:text-text">BLACK OPS</Link> /
      </nav>
      <PageHeader title={p.name} subtitle={p.summary}
        actions={<span className="flex flex-wrap items-center gap-2"><Badge tone={riskTone[p.risk_class]}>{riskLabel[p.risk_class]}</Badge><Badge tone={availabilityTone[a]}>{availabilityLabel[a]}</Badge>{lib.can_manage && <EnableToggle ws={ws} playbookId={p.id} enabled={p.enabled} />}</span>} />
      {p.blocked_reason && <Alert>{p.blocked_reason}</Alert>}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-6">
          <Panel title="Launch">
            {a === "available" || a === "lab_only"
              ? <LaunchPanel ws={ws} playbook={p} projects={projects} canRun={lib.can_run} identities={identities} />
              : <p className="text-sm text-muted">{a === "disabled" ? "Disabled in this workspace." : "Blocked on this deployment."}</p>}
          </Panel>
          <Panel title="Steps">
            <DataTable head={["#", "Tool", "Purpose", "Risk", "Lab"]}>
              {p.steps.map((s, i) => (
                <tr key={s.tool}>
                  <td className="px-4 py-2.5 font-mono text-xs text-muted">{i + 1}</td>
                  <td className="px-4 py-2.5 font-medium">{s.label}<span className="block font-mono text-xs text-muted">{s.tool}</span></td>
                  <td className="px-4 py-2.5 text-sm text-muted">{s.purpose}</td>
                  <td className="px-4 py-2.5"><Badge tone={riskTone[s.risk_class]}>{riskLabel[s.risk_class]}</Badge></td>
                  <td className="px-4 py-2.5 text-xs">{s.lab_capable ? "Yes" : "No"}</td>
                </tr>
              ))}
            </DataTable>
            <p className="mt-3 text-sm text-muted">{p.description}</p>
          </Panel>
          <Panel title="Recent runs"><RunsTable ws={ws} runs={runs} /></Panel>
        </div>
        <div className="space-y-6">
          <Panel title="Definition">
            <dl className="space-y-2 text-sm">
              {facts.map(([k, v]) => <div key={k} className="flex justify-between gap-4"><dt className="text-muted">{k}</dt><dd className="text-right font-mono text-xs tabular">{v}</dd></div>)}
              <div className="flex justify-between gap-4"><dt className="text-muted">Profiles</dt><dd className="flex flex-wrap justify-end gap-1">{p.profiles.map((x) => <Badge key={x} tone={x === "lab" ? "orange" : "blue"}>{profileLabel[x]}</Badge>)}</dd></div>
            </dl>
          </Panel>
          <Panel title="Limits">
            <ul className="list-disc space-y-1 pl-5 text-sm text-muted">{p.limits.map((l) => <li key={l}>{l}</li>)}</ul>
            <h3 className="mt-4 text-sm font-medium">Outputs</h3>
            <ul className="list-disc space-y-1 pl-5 text-sm text-muted">{p.outputs.map((o) => <li key={o}>{o}</li>)}</ul>
            <h3 className="mt-4 text-sm font-medium">Cleanup</h3>
            <p className="text-sm text-muted">{p.cleanup}</p>
          </Panel>
          <Panel title="Dependencies and licenses">
            <ul className="space-y-2 text-sm">{p.dependencies.map((d) => <li key={d.name}><span className="font-medium">{d.name}</span><span className="block text-xs text-muted">{d.license} · pinned: {d.pinned}</span></li>)}</ul>
          </Panel>
          <Panel title="Verification">
            <p className="mb-2 text-xs text-muted">Automated tests that exercise this playbook (run in CI on every push).</p>
            <ul className="space-y-1 font-mono text-xs">{p.tests.map((t) => <li key={t} className="break-all">{t}</li>)}</ul>
          </Panel>
          <Panel title="Change history">
            <ul className="space-y-2 text-sm">
              {p.changelog.map((c) => <li key={c.version}><span className="font-mono text-xs">v{c.version}</span> · {c.date}<span className="block text-xs text-muted">{c.note}</span></li>)}
              {p.setting_history.map((h) => <li key={h.changed_at}><span className="font-mono text-xs">{h.enabled ? "Enabled" : "Disabled"}</span> by {h.changed_by ?? "—"}<span className="block text-xs text-muted">{formatDateTime(h.changed_at)}</span></li>)}
            </ul>
          </Panel>
        </div>
      </div>
    </>
  );
}
