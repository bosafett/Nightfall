"use client";

import { useState } from "react";
import type { Health } from "@/lib/api/types";
import { Icon } from "@/components/ui/Icon";
import { SidebarContent } from "./SidebarContent";

export function MobileNav(props: { ws: string; health: Health | null; version: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="lg:hidden">
      <button type="button" onClick={() => setOpen(true)} aria-label="Open navigation" aria-expanded={open}
        className="rounded-md border border-border-strong p-2 text-muted hover:text-text">
        <Icon name="menu" />
      </button>
      {open && (
        <div className="fixed inset-0 z-40" role="dialog" aria-modal="true" aria-label="Navigation">
          <div className="absolute inset-0 bg-black/70" onClick={() => setOpen(false)} />
          <div className="absolute inset-y-0 left-0 w-72 max-w-[85%] border-r border-border bg-surface">
            <button type="button" onClick={() => setOpen(false)} aria-label="Close navigation"
              className="absolute right-3 top-3 rounded-md p-1.5 text-muted hover:text-text">
              <Icon name="close" />
            </button>
            <SidebarContent {...props} onNavigate={() => setOpen(false)} />
          </div>
        </div>
      )}
    </div>
  );
}
