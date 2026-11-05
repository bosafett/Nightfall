import { Badge } from "@/components/ui/primitives";

/** Lab work is always labelled in text, never by colour alone (review §16.8). */
export function LabBadge() {
  return <Badge tone="blue">LAB · ISOLATED</Badge>;
}
