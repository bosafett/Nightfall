import type { Tone } from "@/components/ui/primitives";

export const runStateLabel: Record<string, [string, Tone]> = {
  running: ["Running", "blue"], succeeded: ["Finished", "green"], failed: ["Failed", "crimson"],
  cancelled: ["Cancelled", "gray"], timed_out: ["Timed out", "orange"],
};
export const stepStateLabel: Record<string, [string, Tone]> = {
  pending: ["Waiting on earlier steps", "gray"], ready: ["Ready to start", "yellow"], blocked: ["Couldn't start", "orange"],
  running: ["In progress", "blue"], succeeded: ["Done", "green"], failed: ["Failed", "crimson"],
  skipped: ["Skipped", "gray"], cancelled: ["Cancelled", "gray"], timed_out: ["Timed out", "orange"],
};
export const kindLabel: Record<string, string> = {
  playbook: "Playbook", rerun: "Re-run", review: "Review by a person", checkpoint: "Checkpoint", wait: "Wait for a condition",
};
