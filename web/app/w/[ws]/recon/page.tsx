import type { Metadata } from "next";
import { PhasePlaceholder } from "@/components/PhasePlaceholder";

export const metadata: Metadata = { title: "Reconnaissance" };

export default function Page() {
  return <PhasePlaceholder title="Reconnaissance" subtitle="Passive collection with source and evidence tracking" phase={3} body="Public DNS, certificate transparency and subdomain discovery, limited to authorized scope." />;
}
