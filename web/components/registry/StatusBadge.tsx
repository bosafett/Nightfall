import type { ProjectStatus } from "@/lib/api/types";
import { projectStatusLabel } from "@/lib/labels";
import { Badge, type Tone } from "@/components/ui/primitives";

const tone: Record<ProjectStatus, Tone> = {
  planning: "gray", active: "blue", paused: "yellow", completed: "green", archived: "gray",
};

export function ProjectStatusBadge({ status }: { status: ProjectStatus }) {
  return <Badge tone={tone[status]}>{projectStatusLabel[status]}</Badge>;
}
