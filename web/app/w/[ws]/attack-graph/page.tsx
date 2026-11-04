import type { Metadata } from "next";
import { PhasePlaceholder } from "@/components/PhasePlaceholder";

export const metadata: Metadata = { title: "Attack Graph" };

export default function Page() {
  return <PhasePlaceholder title="Attack Graph" subtitle="Relationships between assets, findings and potential paths" phase={4} body="Confirmed relationships and hypotheses will be drawn differently, with the evidence behind each." />;
}
