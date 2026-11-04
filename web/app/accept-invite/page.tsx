import type { Metadata } from "next";
import { AuthCard } from "@/components/AuthCard";
import { AcceptInvite } from "./AcceptInvite";

export const metadata: Metadata = { title: "Join workspace" };

export default function AcceptInvitePage() {
  return (
    <AuthCard title="Join a workspace">
      <AcceptInvite />
    </AuthCard>
  );
}
