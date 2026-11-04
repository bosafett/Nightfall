"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api/client";
import type { Role } from "@/lib/api/types";
import { roleLabel } from "@/lib/labels";
import { Icon } from "@/components/ui/Icon";

export function UserMenu({ name, email, role, workspace }: { name: string; email: string; role: Role; workspace: string }) {
  const router = useRouter();
  const initials = name.split(/\s+/).map((p) => p[0]).join("").slice(0, 2).toUpperCase();

  async function signOut() {
    await api("/auth/logout", { method: "POST" }).catch(() => undefined);
    router.replace("/login");
    router.refresh();
  }

  return (
    <details className="relative">
      <summary className="flex cursor-pointer list-none items-center gap-3 rounded-md px-2 py-1 hover:bg-surface-2">
        <span className="grid size-9 place-items-center rounded-full border border-border-strong text-sm font-semibold">{initials}</span>
        <span className="hidden text-left sm:block">
          <span className="block text-sm leading-tight">{name}</span>
          <span className="block text-xs text-muted">{roleLabel[role]} · {workspace}</span>
        </span>
      </summary>
      <div className="absolute right-0 z-30 mt-2 w-60 rounded-md border border-border-strong bg-surface p-1 shadow-xl">
        <p className="truncate px-3 py-2 text-xs text-muted">{email}</p>
        <Link href="/account/security" className="flex items-center gap-2 rounded px-3 py-2 text-sm hover:bg-surface-2">
          <Icon name="shield" className="size-4" /> Account security
        </Link>
        <button type="button" onClick={signOut} className="flex w-full items-center gap-2 rounded px-3 py-2 text-left text-sm hover:bg-surface-2">
          <Icon name="logout" className="size-4" /> Sign out
        </button>
      </div>
    </details>
  );
}
