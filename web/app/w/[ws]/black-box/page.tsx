import type { Metadata } from "next";
import { ApiError, apiGet } from "@/lib/api/server";
import type { BlackBox } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { VerifyEvidence } from "@/components/blackbox/VerifyEvidence";
import { Alert, Badge, PageHeader, Panel } from "@/components/ui/primitives";

export const metadata: Metadata = { title: "BLACK BOX" };

const kindText: Record<string, string> = {
  observation: "Observations", tool_output: "Tool output", document: "Documents", screenshot: "Screenshots", agent_note: "Agent notes",
};

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export default async function BlackBoxPage({ params }: { params: Promise<{ ws: string }> }) {
  const { ws } = await params;
  let box: BlackBox;
  try {
    box = await apiGet<BlackBox>(`/workspaces/${ws}/blackbox`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 403) {
      return (
        <>
          <PageHeader title="BLACK BOX" />
          <Alert tone="yellow">BLACK BOX is available to workspace owners and admins.</Alert>
        </>
      );
    }
    throw e;
  }
  const last = box.last_verification;
  const stats: [string, string][] = [
    ["Evidence records", String(box.total)],
    ["Stored size", bytes(box.total_bytes)],
    ["Oldest", formatDateTime(box.oldest_collected_at)],
    ["Newest", formatDateTime(box.newest_collected_at)],
  ];
  return (
    <>
      <PageHeader title="BLACK BOX" subtitle="Evidence integrity and retention. Evidence is write-once: nothing here edits or deletes it." />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-6">
          <Panel title="Inventory">
            <dl className="grid grid-cols-2 gap-3 text-sm xl:grid-cols-4" data-testid="blackbox-inventory">
              {stats.map(([k, v]) => (
                <div key={k}><dt className="text-xs text-muted">{k}</dt><dd className="mt-0.5 font-mono tabular">{v}</dd></div>
              ))}
            </dl>
            {box.by_kind.length > 0 && (
              <ul className="mt-4 flex flex-wrap gap-2 text-xs">
                {box.by_kind.map((k) => <li key={k.kind}><Badge tone="gray">{kindText[k.kind] ?? k.kind}: {k.count}</Badge></li>)}
                {box.simulated > 0 && <li><Badge tone="blue">Simulated: {box.simulated}</Badge></li>}
              </ul>
            )}
          </Panel>
          <Panel title="Integrity">
            <p className="mb-3 text-sm" data-testid="last-verification">
              {last
                ? <>Last run {formatDateTime(last.occurred_at)}: {last.checked} checked, {last.failed} failed{last.complete ? "" : " (did not finish)"}.</>
                : "Never verified."}
            </p>
            <VerifyEvidence ws={ws} />
          </Panel>
        </div>
        <Panel title="Retention">
          <p className="text-sm">Policy: <strong>keep indefinitely</strong>.</p>
          <dl className="mt-3 space-y-2 text-sm">
            {box.by_age.map((a) => (
              <div key={a.older_than_days} className="flex justify-between"><dt className="text-muted">Older than {a.older_than_days} days</dt><dd className="font-mono tabular">{a.count}</dd></div>
            ))}
          </dl>
          <p className="mt-4 text-xs text-muted">Nothing is deleted automatically. Deleting evidence would need a reviewed retention policy; until then this panel only reports age.</p>
        </Panel>
      </div>
    </>
  );
}
