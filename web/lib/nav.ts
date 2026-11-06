/** `restricted` only changes presentation (lock indicator); the backend stays the authority on access. */
export type NavItem = { key: string; label: string; href: (ws: string) => string; icon: IconName; phase?: number; restricted?: boolean };
/**
 * A module from the architecture (Addendum 5) without its own page: shown as a label, never as a link, so the
 * sidebar never implies something exists. `tag` says why ("Planned", or where the capability lives today).
 */
export type PlannedItem = { key: string; label: string; planned: true; tag: string; title: string };
export type NavEntry = NavItem | PlannedItem;
/** `label: null` is the ungrouped top entry (Command Center). */
export type NavGroup = {
  key: string; label: string | null; description?: string; items: NavEntry[];
  /** Expandable division; `open` is its initial state (a group holding the current page always starts open). */
  collapsible?: { open: boolean };
};
export type IconName =
  | "command" | "target" | "recon" | "findings" | "graph" | "warroom" | "blacksite" | "reports" | "settings" | "agents";

const planned = (key: string, label: string): PlannedItem =>
  ({ key, label, planned: true, tag: "Planned", title: "Not built yet" });

/** Addendum 5 §14: Command Center, SWORD, SHIELD, JANUS CORE, SYSTEM. Existing pages are regrouped, not duplicated. */
export const NAV_GROUPS: NavGroup[] = [
  { key: "top", label: null, items: [
    { key: "command", label: "Command Center", href: (ws) => `/w/${ws}`, icon: "command" },
  ] },
  { key: "sword", label: "SWORD", description: "Offensive operations", collapsible: { open: true }, items: [
    { key: "targets", label: "Target Registry", href: (ws) => `/w/${ws}/targets`, icon: "target" },
    { key: "recon", label: "Reconnaissance", href: (ws) => `/w/${ws}/recon`, icon: "recon" },
    { key: "blacksite", label: "BLACKSITE", href: (ws) => `/w/${ws}/blacksite`, icon: "blacksite", restricted: true },
    { key: "graph", label: "Attack Graph", href: (ws) => `/w/${ws}/attack-graph`, icon: "graph", phase: 4 },
    { key: "findings", label: "Findings", href: (ws) => `/w/${ws}/findings`, icon: "findings", phase: 4 },
    { key: "reports", label: "Reports", href: (ws) => `/w/${ws}/reports`, icon: "reports", phase: 4 },
    planned("warpath", "WARPATH"),
  ] },
  { key: "shield", label: "SHIELD", description: "Defensive operations", collapsible: { open: false }, items: [
    planned("aegis", "AEGIS Overview"),
    planned("monitoring", "Monitoring"),
    planned("alerts", "Alerts & Detection"),
    planned("hunting", "Threat Hunting"),
    planned("countermeasures", "Countermeasures"),
    planned("incidents", "Incident Response"),
    planned("recovery", "Recovery & Verification"),
  ] },
  { key: "core", label: "JANUS CORE", description: "Shared infrastructure", collapsible: { open: false }, items: [
    { key: "blackice", label: "BLACK ICE", planned: true, tag: "In Findings",
      title: "Correlation and finding rules run behind Findings; it has no separate page" },
    planned("blackbox", "BLACK BOX"),
    planned("atlas", "ATLAS"),
    planned("chronicle", "CHRONICLE"),
    planned("nexus", "NEXUS"),
    planned("control", "CONTROL"),
    planned("watchtower", "WATCHTOWER"),
  ] },
  { key: "system", label: "SYSTEM", items: [
    { key: "agents", label: "Agents", href: (ws) => `/w/${ws}/agents`, icon: "agents" },
    { key: "warroom", label: "War Room", href: (ws) => `/w/${ws}/war-room`, icon: "warroom", phase: 6 },
    { key: "settings", label: "Settings", href: (ws) => `/w/${ws}/settings`, icon: "settings" },
  ] },
];

export function isPlanned(entry: NavEntry): entry is PlannedItem {
  return "planned" in entry;
}

/** Every navigable page, in sidebar order. */
export const NAV: NavItem[] = NAV_GROUPS.flatMap((g) => g.items.filter((i): i is NavItem => !isPlanned(i)));

export function isActive(item: NavItem, ws: string, pathname: string): boolean {
  const href = item.href(ws);
  return item.key === "command" ? pathname === href : pathname === href || pathname.startsWith(`${href}/`);
}

export function groupHasActive(group: NavGroup, ws: string, pathname: string): boolean {
  return group.items.some((i) => !isPlanned(i) && isActive(i, ws, pathname));
}
