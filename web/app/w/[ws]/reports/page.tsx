import type { Metadata } from "next";
import { PhasePlaceholder } from "@/components/PhasePlaceholder";

export const metadata: Metadata = { title: "Reports" };

export default function Page() {
  return <PhasePlaceholder title="Reports" subtitle="Assessment reports from stored data" phase={4} body="Reports will be generated from stored findings and evidence, including limitations and unverified hypotheses." />;
}
