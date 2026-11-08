"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import type { Health, Watchtower } from "@/lib/api/types";
import { NAV_GROUPS, groupHasActive, isActive, isPlanned, type NavEntry, type NavGroup } from "@/lib/nav";
import { Icon } from "@/components/ui/Icon";
import { StatusDot, cx } from "@/components/ui/primitives";

/** `lab` comes from WATCHTOWER (owner and admin only); null means this viewer isn't shown it. */
export type LabStatus = Watchtower["lab"] | null;

export function SidebarContent({ ws, health, lab, version, onNavigate, counts }: {
  ws: string; health: Health | null; lab: LabStatus; version: string; onNavigate?: () => void;
  counts?: Record<string, number>;
}) {
  const pathname = usePathname();
  return (
    <div className="flex h-full flex-col">
      <Link href={`/w/${ws}`} onClick={onNavigate} className="flex flex-col items-center border-b border-border px-4 py-6 text-center">
        <Image src="/nightfall-mark.svg" alt="" width={64} height={58} priority />
        <span className="mt-2 text-xs font-semibold tracking-[0.3em] text-crimson-text">DRE</span>
        <span className="text-xl font-bold tracking-[0.12em] text-crimson-text">JANUS</span>
        <span className="font-mono text-[10px] tracking-[0.3em] text-muted">JNS.OS</span>
        <span className="mt-1 text-xs leading-snug text-muted">Adversarial Intelligence<br />&amp; Operations Platform</span>
      </Link>

      <nav aria-label="Primary" className="flex-1 overflow-y-auto py-3">
        {NAV_GROUPS.map((group) => (
          <NavSection key={group.key} group={group} ws={ws} pathname={pathname} onNavigate={onNavigate} counts={counts} />
        ))}
      </nav>

      <SystemStatus health={health} lab={lab} />
      <p className="px-5 pb-4 text-xs text-muted tabular">v{version}</p>
    </div>
  );
}

function NavSection({ group, ws, pathname, onNavigate, counts }: {
  group: NavGroup; ws: string; pathname: string; onNavigate?: () => void; counts?: Record<string, number>;
}) {
  const [open, setOpen] = useState(() => !group.collapsible || group.collapsible.open || groupHasActive(group, ws, pathname));
  const listId = `nav-${group.key}`;
  const list = (
    <ul id={listId} hidden={!open}>
      {group.items.map((item) => <NavRow key={item.key} item={item} ws={ws} pathname={pathname} onNavigate={onNavigate} count={counts?.[item.key]} />)}
    </ul>
  );
  if (group.label === null) return list;
  const heading = (
    <>
      <span className="font-mono text-xs font-semibold tracking-[0.2em] text-crimson-text">{group.label}</span>
      {group.description && <span className="truncate text-[11px] text-muted">{group.description}</span>}
    </>
  );
  return (
    <div className="mt-3 border-t border-border pt-2">
      {group.collapsible ? (
        <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-controls={listId}
          className="flex w-full items-center gap-2 px-5 py-1.5 text-left hover:bg-white/5">
          <Icon name="chevron" className={cx("size-3.5 shrink-0 text-muted transition-transform", open && "rotate-90")} />
          {heading}
        </button>
      ) : (
        <p className="flex items-center gap-2 px-5 py-1.5 pl-[2.375rem]">{heading}</p>
      )}
      {list}
    </div>
  );
}

function NavRow({ item, ws, pathname, onNavigate, count }: {
  item: NavEntry; ws: string; pathname: string; onNavigate?: () => void; count?: number;
}) {
  if (isPlanned(item)) {
    return (
      <li className="flex items-center gap-3 px-5 py-2 pl-[3.25rem] text-sm text-muted/70" title={item.title}>
        <span>{item.label}</span>
        <span className="ml-auto rounded border border-border px-1.5 text-[10px] uppercase tracking-wider text-muted">{item.tag}</span>
      </li>
    );
  }
  const active = isActive(item, ws, pathname);
  return (
    <li>
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
        <span className={cx(item.restricted && "font-mono tracking-wider")}>{item.label}</span>
        {!!count && (
          <span className="ml-auto rounded-full bg-crimson px-1.5 text-[11px] font-semibold tabular text-white" data-testid={`nav-count-${item.key}`}>
            {count}<span className="sr-only"> open</span>
          </span>
        )}
        {item.restricted && (
          <span className="ml-auto flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted" title="Restricted: owner access only">
            <Icon name="lock" className="size-3.5" /><span className="sr-only">Restricted</span>
          </span>
        )}
      </Link>
    </li>
  );
}

const componentLabel: Record<string, string> = { api: "API", database: "Database", worker: "Worker", ai: "AI provider" };
const componentStatus: Record<string, string> = { ok: "Online", on_demand: "On demand", off: "Off", down: "Down" };

const labText: Record<string, [string, string]> = {
  online: ["Online", "text-green"], offline: ["Offline", "text-orange"], never: ["Never connected", "text-muted"],
};

function SystemStatus({ health, lab }: { health: Health | null; lab: LabStatus }) {
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
                <span className={c.status === "down" ? "text-crimson-text" : c.status === "off" ? "text-muted" : "text-green"}>{componentStatus[c.status] ?? c.status}</span>
              </li>
            ))}
            {/* /api/health is public and never reports the lab; owners and admins get it from WATCHTOWER. */}
            {lab && labText[lab.status] ? (
              <li className="flex items-center justify-between text-xs text-muted"
                title={lab.last_seen_at ? `Last heartbeat ${new Date(lab.last_seen_at).toLocaleString()}` : "No heartbeat recorded"}>
                <span>Lab</span><span className={labText[lab.status]![1]}>{labText[lab.status]![0]}</span>
              </li>
            ) : (
              <li className="flex items-center justify-between text-xs text-muted" title="Lab status is shown to owners and admins">
                <span>Lab</span><span className="text-muted">Not reported</span>
              </li>
            )}
          </ul>
        </>
      )}
    </div>
  );
}
