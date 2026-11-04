import Link from "next/link";
import { AuthCard } from "@/components/AuthCard";

export default function NotFound() {
  return (
    <AuthCard title="Not found">
      <p className="text-sm text-muted">That page doesn&apos;t exist, or you don&apos;t have access to it.</p>
      <Link href="/" className="mt-4 inline-block text-sm text-crimson-text underline">Go to your workspace</Link>
    </AuthCard>
  );
}
