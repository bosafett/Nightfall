import type { AgentTaskStatus, GuardianReview } from "@/lib/api/types";
import { Badge, type Tone } from "@/components/ui/primitives";

const status: Record<AgentTaskStatus, [Tone, string]> = {
  queued: ["gray", "Queued"],
  running: ["blue", "Running"],
  succeeded: ["green", "Done"],
  failed: ["crimson", "Failed"],
  cancelled: ["gray", "Cancelled"],
};

export function AgentTaskStatusBadge({ value }: { value: AgentTaskStatus }) {
  const [tone, label] = status[value];
  return <Badge tone={tone}>{label}</Badge>;
}

const verdict: Record<GuardianReview["verdict"], [Tone, string]> = {
  supported: ["green", "Evidence supports it"],
  not_supported: ["crimson", "Evidence doesn't support it"],
  insufficient_evidence: ["yellow", "Not enough evidence"],
};

export function GuardianVerdictBadge({ value }: { value: GuardianReview["verdict"] }) {
  const [tone, label] = verdict[value];
  return <Badge tone={tone}>Guardian: {label}</Badge>;
}

/** AI output is always labelled as such, never styled like verified data. */
export function AiBadge() {
  return <Badge tone="blue">AI proposal</Badge>;
}
