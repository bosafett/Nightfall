import type { Sources } from "@/lib/api/types";
import { formatDateTime, formatRelative } from "@/lib/format";
import { Badge, DataTable, Panel, type Tone } from "@/components/ui/primitives";

const states: Record<string, [Tone, string]> = {
  fresh: ["green", "Up to date"],
  stale: ["yellow", "Stale"],
  failing: ["crimson", "Failing"],
  never_run: ["gray", "Never run"],
  unavailable: ["gray", "Not available here"],
};

/** BLACK ICE freshness: when each source last worked, from the collection records. */
export function SourcesPanel({ data, now }: { data: Sources; now: Date }) {
  return (
    <Panel title="Data sources" className="mb-6">
      <p className="mb-3 text-xs text-muted">
        From your real-world collections (lab runs excluded). Stale means no success in {data.stale_after_days} days; failing means the latest run failed.
      </p>
      <DataTable head={["Source", "State", "Last success", "Last failure"]}>
        {data.sources.map((s) => {
          const [tone, label] = states[s.state] ?? ["gray", s.state];
          return (
            <tr key={s.key} data-testid={`source-${s.key}`}>
              <td className="px-4 py-3 text-sm">{s.label}</td>
              <td className="px-4 py-3"><Badge tone={tone}>{label}</Badge></td>
              <td className="px-4 py-3 font-mono text-xs text-muted tabular" title={s.last_success_at ? formatDateTime(s.last_success_at) : undefined}>
                {s.last_success_at ? formatRelative(s.last_success_at, now) : "—"}
              </td>
              <td className="max-w-sm px-4 py-3 text-xs text-muted">
                {s.last_failure_at ? <><span className="font-mono tabular">{formatRelative(s.last_failure_at, now)}</span>{s.last_error && <span className="block truncate" title={s.last_error}>{s.last_error}</span>}</> : "—"}
              </td>
            </tr>
          );
        })}
      </DataTable>
    </Panel>
  );
}
