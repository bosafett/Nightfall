import type { IconName } from "@/lib/nav";

type Name = IconName | "menu" | "close" | "plus" | "logout" | "shield" | "alert" | "copy" | "check";

const paths: Record<Name, React.ReactNode> = {
  command: <path d="M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z" />,
  target: (<><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="M12 2v4M12 18v4M2 12h4M18 12h4" /></>),
  recon: (<><circle cx="11" cy="11" r="7" /><path d="M16.5 16.5L21 21M11 8v6M8 11h6" /></>),
  findings: (<><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><path d="M12 8v5M12 16h.01" /></>),
  graph: (<><circle cx="5" cy="6" r="2" /><circle cx="19" cy="6" r="2" /><circle cx="12" cy="18" r="2" /><path d="M7 6h10M6 8l5 8.3M18 8l-5 8.3" /></>),
  warroom: (<><rect x="3" y="4" width="18" height="12" rx="1" /><path d="M8 20h8M12 16v4M7 12l3-3 2 2 4-4" /></>),
  reports: (<><path d="M7 3h7l5 5v13H7z" /><path d="M14 3v5h5M10 13h6M10 17h6" /></>),
  settings: (<><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1L7 17M17 7l2.1-2.1" /></>),
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  close: <path d="M6 6l12 12M18 6L6 18" />,
  plus: <path d="M12 5v14M5 12h14" />,
  logout: (<><path d="M15 4h4v16h-4" /><path d="M10 8l-4 4 4 4M6 12h10" /></>),
  shield: (<><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><path d="M9 12l2 2 4-4" /></>),
  alert: (<><path d="M12 3l10 18H2z" /><path d="M12 10v4M12 17h.01" /></>),
  copy: (<><rect x="9" y="9" width="11" height="11" rx="1" /><path d="M5 15V5a1 1 0 0 1 1-1h10" /></>),
  check: <path d="M5 12l5 5 9-10" />,
};

export function Icon({ name, className = "size-5" }: { name: Name; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      {paths[name]}
    </svg>
  );
}
