import { redirect } from "next/navigation";
import { apiGetOptional } from "@/lib/api/server";
import type { Me } from "@/lib/api/types";
import { mfaRequired } from "@/lib/labels";
import { AuthCard } from "@/components/AuthCard";

export default async function Home() {
  const me = await apiGetOptional<Me>("/auth/me");
  if (!me) redirect("/login");
  const first = me.workspaces[0];
  if (!first) {
    return (
      <AuthCard title="No workspace yet">
        <p className="text-sm text-muted">Your account isn&apos;t a member of any workspace. Ask a workspace admin for an invite.</p>
      </AuthCard>
    );
  }
  if (me.workspaces.some((w) => mfaRequired(w.role)) && !me.session.mfa_verified) redirect("/account/security");
  redirect(`/w/${first.id}`);
}
