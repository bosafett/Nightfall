import type { AssessmentType, AssetKind, AssetOwnership, OperationStatus, ProjectStatus, Role, ScopeEntryKind, Severity, ValidationStatus } from "./api/types";

export const assessmentTypeLabel: Record<AssessmentType, string> = {
  reconnaissance: "Reconnaissance",
  security_assessment: "Security assessment",
  ai_system_assessment: "AI system assessment",
  adversarial_simulation: "Adversarial simulation",
};

export const projectStatusLabel: Record<ProjectStatus, string> = {
  planning: "Planning",
  active: "Active",
  paused: "Paused",
  completed: "Completed",
  archived: "Archived",
};

export const roleLabel: Record<Role, string> = {
  owner: "Owner",
  admin: "Admin",
  operator: "Operator",
  analyst: "Analyst",
  viewer: "Viewer",
};

export const roleDescription: Record<Role, string> = {
  owner: "Everything, including other owners",
  admin: "Members, settings and scope",
  operator: "Approves operations",
  analyst: "Registers targets, works findings",
  viewer: "Read only",
};

const rank: Record<Role, number> = { owner: 4, admin: 3, operator: 2, analyst: 1, viewer: 0 };

/** Mirrors the API's rules (core/tenancy/permissions.py). The API is authoritative. */
export const can = {
  writeRegistry: (r: Role) => rank[r] >= rank.analyst,
  manageMembers: (r: Role) => rank[r] >= rank.admin,
  authorizeScope: (r: Role) => rank[r] >= rank.admin,
  approveOperations: (r: Role) => rank[r] >= rank.operator,
  editFindings: (r: Role) => rank[r] >= rank.analyst,
  assign: (actor: Role, role: Role) => actor === "owner" || rank[role] < rank[actor],
  manage: (actor: Role, target: Role) => actor === "owner" || rank[target] < rank[actor],
};

/** D1: under the single-operator policy the owner decides their own requests (the API and
 * the database enforce this; the UI only mirrors it). */
export const decidesOwn = (r: Role, policy: string | undefined) => policy !== "two_person" && r === "owner";

export const mfaRequired = (r: Role) => r === "owner" || r === "admin" || r === "operator";


export const assetKindLabel: Record<AssetKind, string> = {
  domain: "Domain", hostname: "Hostname", ip_address: "IP address", ip_range: "IP range",
  application: "Application", api: "API", cloud_resource: "Cloud resource", other: "Other",
};

export const ownershipLabel: Record<AssetOwnership, string> = {
  organization: "Owned by the organization", third_party: "Third party", unknown: "Unknown",
};

export const scopeKindLabel: Record<ScopeEntryKind, string> = {
  host: "Exact host", domain_tree: "Domain and all subdomains", ip: "IP address", cidr: "IP range (CIDR)",
};

export const scopeKindHint: Record<ScopeEntryKind, string> = {
  host: "Only this hostname, e.g. portal.example.com",
  domain_tree: "example.com and every name under it",
  ip: "One address, e.g. 192.0.2.10",
  cidr: "A network, e.g. 192.0.2.0/24",
};

export const operationStatusLabel: Record<OperationStatus, string> = {
  awaiting_approval: "Awaiting approval", queued: "Queued", running: "Running", succeeded: "Done", failed: "Failed",
  denied: "Denied", rejected: "Rejected", cancelled: "Cancelled",
};

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const severityLabel: Record<Severity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
};

export const STATUSES: ValidationStatus[] = ["hypothesis", "unverified", "validated", "false_positive", "remediated"];
export const statusLabel: Record<ValidationStatus, string> = {
  hypothesis: "Hypothesis", unverified: "Unverified", validated: "Validated",
  false_positive: "False positive", remediated: "Remediated",
};
export const statusHelp: Record<ValidationStatus, string> = {
  hypothesis: "Plausible, not shown by evidence",
  unverified: "Evidence shows the condition; not yet reviewed",
  validated: "A person confirmed it against the evidence",
  false_positive: "A person ruled it out",
  remediated: "A person confirmed it was fixed",
};
