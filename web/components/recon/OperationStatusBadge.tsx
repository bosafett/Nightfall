import type { OperationStatus } from "@/lib/api/types";
import { operationStatusLabel } from "@/lib/labels";
import { Badge, type Tone } from "@/components/ui/primitives";

const tone: Record<OperationStatus, Tone> = {
  awaiting_approval: "yellow", queued: "gray", running: "blue", succeeded: "green", failed: "crimson", denied: "orange",
  rejected: "orange", cancelled: "gray",
};

export function OperationStatusBadge({ status }: { status: OperationStatus }) {
  return <Badge tone={tone[status]}>{operationStatusLabel[status]}</Badge>;
}
