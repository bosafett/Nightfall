import type { Metadata } from "next";
import { AuthCard } from "@/components/AuthCard";
import { ResetForm } from "./ResetForm";

export const metadata: Metadata = { title: "Reset password" };

export default function ResetPage() {
  return (
    <AuthCard title="Choose a new password" subtitle="This link works once and expires 30 minutes after it was issued.">
      <ResetForm />
    </AuthCard>
  );
}
