/** `restricted` only changes presentation (lock indicator); the backend stays the authority on access. */
export type NavItem = { key: string; label: string; href: (ws: string) => string; icon: IconName; phase?: number; restricted?: boolean };
export type IconName =
  | "command" | "target" | "recon" | "findings" | "graph" | "warroom" | "blacksite" | "reports" | "settings";

/** Primary navigation (spec §3.2). BLACKSITE is owner-only (§16) and not yet configured. */
export const NAV: NavItem[] = [
  { key: "command", label: "Command Center", href: (ws) => `/w/${ws}`, icon: "command" },
  { key: "targets", label: "Target Registry", href: (ws) => `/w/${ws}/targets`, icon: "target" },
  { key: "recon", label: "Reconnaissance", href: (ws) => `/w/${ws}/recon`, icon: "recon" },
  { key: "findings", label: "Findings", href: (ws) => `/w/${ws}/findings`, icon: "findings", phase: 4 },
  { key: "graph", label: "Attack Graph", href: (ws) => `/w/${ws}/attack-graph`, icon: "graph", phase: 4 },
  { key: "warroom", label: "War Room", href: (ws) => `/w/${ws}/war-room`, icon: "warroom", phase: 6 },
  { key: "blacksite", label: "BLACKSITE", href: (ws) => `/w/${ws}/blacksite`, icon: "blacksite", restricted: true },
  { key: "reports", label: "Reports", href: (ws) => `/w/${ws}/reports`, icon: "reports", phase: 4 },
  { key: "settings", label: "Settings", href: (ws) => `/w/${ws}/settings`, icon: "settings" },
];

export function isActive(item: NavItem, ws: string, pathname: string): boolean {
  const href = item.href(ws);
  return item.key === "command" ? pathname === href : pathname === href || pathname.startsWith(`${href}/`);
}
