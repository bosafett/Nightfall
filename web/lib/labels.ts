import type { AssessmentType, ProjectStatus, Role } from "./api/types";

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
  assign: (actor: Role, role: Role) => actor === "owner" || rank[role] < rank[actor],
  manage: (actor: Role, target: Role) => actor === "owner" || rank[target] < rank[actor],
};

export const mfaRequired = (r: Role) => r === "owner" || r === "admin" || r === "operator";
