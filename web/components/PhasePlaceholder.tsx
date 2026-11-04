import { EmptyState, PageHeader } from "@/components/ui/primitives";

/** Honest placeholder for sections that are not built yet: no sample data. */
export function PhasePlaceholder({ title, subtitle, phase, body }: { title: string; subtitle: string; phase: number; body: string }) {
  return (
    <>
      <PageHeader title={title} subtitle={subtitle} />
      <EmptyState title={`Arrives in phase ${phase}`} body={body} />
    </>
  );
}
