"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { Health } from "@/lib/api/types";
import { NAV, isActive } from "@/lib/nav";
import { Icon } from "@/components/ui/Icon";
import { StatusDot, cx } from "@/components/ui/primitives";

export function SidebarContent({ ws, health, version, onNavigate }: {
  ws: string; health: Health | null; version: string; onNavigate?: () => void;
}) {
  const pathname = usePathname();
  return (
    <div className="flex h-full flex-col">
      <Link href={`/w/${ws}`} onClick={onNavigate} className="flex flex-col items-center border-b border-border px-4 py-6 text-center">
        <Image src="/nightfall-mark.svg" alt="" width={64} height={58} priority />
        <span className="mt-2 text-xs font-semibold tracking-[0.3em] text-crimson-text">DRE</span>
        <span className="text-xl font-bold tracking-[0.12em] text-crimson-text">NIGHTFALL</span>
        <span className="mt-1 text-xs leading-snug text-muted">Adversarial Intelligence<br />&amp; Operations Platform</span>
      </Link>

      <nav aria-label="Primary" className="flex-1 overflow-y-auto py-3">
        <ul>
          {NAV.map((item) => {
            const active = isActive(item, ws, pathname);
            return (
              <li key={item.key}>
                <Link
                  href={item.href(ws)}
                  onClick={onNavigate}
                  aria-current={active ? "page" : undefined}
                  className={cx(
                    "flex items-center gap-3 border-l-2 px-5 py-2.5 text-sm transition-colors",
                    active ? "border-crimson bg-crimson/10 text-text" : "border-transparent text-muted hover:text-text",
                  )}
                >
                  <Icon name={item.icon} className={cx("size-5", active && "text-crimson-text")} />
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <SystemStatus health={health} />
      <p className="px-5 pb-4 text-xs text-muted tabular">v{version}</p>
    </div>
  );
}

const componentLabel: Record<string, string> = { api: "API", database: "Database" };

function SystemStatus({ health }: { health: Health | null }) {
  const components = health?.components ?? [];
  const allOk = health?.status === "ok";
  return (
    <div className="mx-4 mb-3 rounded-md border border-border bg-bg/60 p-3" aria-live="polite">
      <p className="text-sm font-medium">System status</p>
      {health === null ? (
        <p className="mt-1 flex items-center gap-2 text-xs text-crimson-text"><StatusDot ok={false} /> API unreachable</p>
      ) : (
        <>
          <p className={cx("mt-1 flex items-center gap-2 text-xs", allOk ? "text-green" : "text-orange")}>
            <StatusDot ok={allOk} /> {allOk ? "All systems online" : "Degraded"}
          </p>
          <ul className="mt-2 space-y-1">
            {components.map((c) => (
              <li key={c.name} className="flex items-center justify-between text-xs text-muted">
                <span>{componentLabel[c.name] ?? c.name}</span>
                <span className={c.status === "ok" ? "text-green" : "text-crimson-text"}>{c.status === "ok" ? "Online" : "Down"}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
