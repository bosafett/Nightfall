import { apiGet } from "./api/server";
import type { Me, WorkspaceSummary } from "./api/types";

/** The caller's membership in this workspace (the layout already 404s non-members). */
export async function membership(ws: string): Promise<WorkspaceSummary> {
  const me = await apiGet<Me>("/auth/me");
  const m = me.workspaces.find((w) => w.id === ws);
  if (!m) throw new Error("not a member");
  return m;
}
