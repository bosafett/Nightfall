import type { Playbook, PlaybookCategory, PlaybookProfile, PlaybookRunStatus } from "./api/types";
import type { Tone } from "@/components/ui/primitives";

export const categoryLabel: Record<PlaybookCategory, string> = {
  reconnaissance: "Reconnaissance",
  vulnerability_assessment: "Vulnerability assessment",
  controlled_validation: "Controlled validation",
  adversary_simulation: "Adversary simulation",
};

/** Profile letters follow Addendum 4 §4. */
export const profileLabel: Record<PlaybookProfile, string> = {
  live: "A · Live",
  validation: "B · Validation",
  lab: "C · Lab",
};

export const riskTone: Record<Playbook["risk_class"], Tone> = { passive: "green", low: "blue", moderate: "orange", high: "crimson" };
export const riskLabel: Record<Playbook["risk_class"], string> = { passive: "Passive", low: "Low risk", moderate: "Moderate", high: "High" };

export const runStatusLabel: Record<PlaybookRunStatus, string> = {
  awaiting_approval: "Awaiting approval",
  running: "Running",
  succeeded: "Succeeded",
  partial: "Partly succeeded",
  failed: "Failed",
  denied: "Denied",
  rejected: "Rejected",
  cancelled: "Cancelled",
};
export const runStatusTone: Record<PlaybookRunStatus, Tone> = {
  awaiting_approval: "yellow", running: "blue", succeeded: "green", partial: "orange", failed: "crimson",
  denied: "orange", rejected: "orange", cancelled: "gray",
};

export type Availability = "available" | "disabled" | "blocked" | "lab_only";

/** What the library shows: blocked and disabled win over lab-only. */
export function availability(p: Playbook): Availability {
  if (p.availability !== "available") return p.availability;
  return p.lab_only ? "lab_only" : "available";
}
export const availabilityLabel: Record<Availability, string> = {
  available: "Available", disabled: "Disabled", blocked: "Blocked", lab_only: "Lab only",
};
export const availabilityTone: Record<Availability, Tone> = { available: "green", disabled: "gray", blocked: "crimson", lab_only: "orange" };
