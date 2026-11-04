import type { Metadata } from "next";
import { PhasePlaceholder } from "@/components/PhasePlaceholder";

export const metadata: Metadata = { title: "Findings" };

export default function Page() {
  return <PhasePlaceholder title="Findings" subtitle="Security findings with evidence and validation status" phase={4} body="Findings will show severity, confidence and validation status, each traceable to its evidence." />;
}
