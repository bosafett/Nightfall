import type { components } from "./schema";

type S = components["schemas"];
export type Me = S["MeOut"];
export type WorkspaceSummary = S["WorkspaceSummary"];
export type Role = S["Role"];
export type Health = S["HealthOut"];
export type Organization = S["OrganizationOut"];
export type Project = S["ProjectOut"];
export type ProjectStatus = S["ProjectStatus"];
export type AssessmentType = S["AssessmentType"];
export type Member = S["MemberOut"];
export type Invite = S["InviteOut"];
export type InviteCreated = S["InviteCreatedOut"];
export type InviteInfo = S["InviteInfoOut"];
export type Link = S["LinkOut"];
export type MfaSetup = S["MfaSetupOut"];
export type WorkspaceInfo = S["WorkspaceOut"];
