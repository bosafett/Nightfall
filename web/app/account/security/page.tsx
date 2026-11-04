import type { Metadata } from "next";
import Link from "next/link";
import { apiGet } from "@/lib/api/server";
import type { Me } from "@/lib/api/types";
import { mfaRequired } from "@/lib/labels";
import { AuthCard } from "@/components/AuthCard";
import { Alert } from "@/components/ui/primitives";
import { MfaSetup, SignOutEverywhere } from "./SecurityActions";

export const metadata: Metadata = { title: "Account security" };

export default async function SecurityPage() {
  const me = await apiGet<Me>("/auth/me");
  const required = me.workspaces.some((w) => mfaRequired(w.role));
  const first = me.workspaces[0];
  const { mfa_enabled } = me.user;
  const verified = me.session.mfa_verified;

  return (
    <AuthCard title="Account security" subtitle={me.user.email}>
      <div className="space-y-5">
        {!mfa_enabled && required && (
          <Alert tone="yellow">Your role requires two-factor authentication before you can continue.</Alert>
        )}
        {mfa_enabled && !verified && (
          <Alert tone="yellow">This session hasn&apos;t passed two-factor. Sign out, then sign in again with your code.</Alert>
        )}

        <section>
          <h2 className="font-semibold">Two-factor authentication</h2>
          {mfa_enabled ? (
            <p className="mt-1 text-sm text-green">On. Lost your authenticator? The host operator can reset it.</p>
          ) : (
            <MfaSetup />
          )}
        </section>

        <section className="border-t border-border pt-5">
          <h2 className="font-semibold">Sessions</h2>
          <p className="mt-1 text-sm text-muted">Signs out this browser and every other device.</p>
          <div className="mt-3"><SignOutEverywhere /></div>
        </section>

        {first && (!required || (mfa_enabled && verified)) && (
          <Link href={`/w/${first.id}`} className="block text-sm text-crimson-text underline">Back to {first.name}</Link>
        )}
      </div>
    </AuthCard>
  );
}
