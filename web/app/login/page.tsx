import type { Metadata } from "next";
import { AuthCard } from "@/components/AuthCard";
import { LoginForm } from "./LoginForm";

export const metadata: Metadata = { title: "Sign in" };

export default function LoginPage() {
  return (
    <AuthCard title="Sign in" subtitle="Understand. Investigate. Validate. Defend.">
      <LoginForm />
    </AuthCard>
  );
}
