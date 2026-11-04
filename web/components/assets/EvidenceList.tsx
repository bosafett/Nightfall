import type { EvidenceSummary } from "@/lib/api/types";
import { formatDateTime } from "@/lib/format";
import { Badge, DataTable } from "@/components/ui/primitives";

/** Evidence rows with provenance. Downloads go through the API, which verifies the hash. */
export function EvidenceList({ ws, items }: { ws: string; items: EvidenceSummary[] }) {
  if (items.length === 0) return <p className="text-sm text-muted">No evidence yet.</p>;
  return (
    <DataTable head={["Collected", "Source", "Method", "Confidence", "SHA-256", ""]}>
      {items.map((e) => (
        <tr key={e.id}>
          <td className="px-4 py-3 font-mono text-xs text-muted tabular">{formatDateTime(e.collected_at)}</td>
          <td className="px-4 py-3">
            {e.source}
            {e.tool_name.startsWith("fixture") && <span className="ml-2"><Badge tone="yellow">Test fixture</Badge></span>}
            <span className="block text-xs text-muted">{e.tool_name} {e.tool_version}</span>
          </td>
          <td className="px-4 py-3 text-xs text-muted">{e.collection_method}</td>
          <td className="px-4 py-3 capitalize">{e.confidence}</td>
          <td className="px-4 py-3 font-mono text-xs text-muted" title={e.sha256}>{e.sha256.slice(0, 12)}…</td>
          <td className="px-4 py-3 text-right">
            <a href={`/api/workspaces/${ws}/evidence/${e.id}/content`} className="text-sm text-crimson-text hover:underline" download>Download</a>
          </td>
        </tr>
      ))}
    </DataTable>
  );
}
