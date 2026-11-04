import type { Metadata } from "next";
import { PhasePlaceholder } from "@/components/PhasePlaceholder";

export const metadata: Metadata = { title: "War Room" };

export default function Page() {
  return <PhasePlaceholder title="War Room" subtitle="Agent operations and approvals" phase={6} body="Proposed operations, approval requests and agent activity will be reviewed here." />;
}
