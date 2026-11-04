import { Skeleton } from "@/components/ui/primitives";

export default function Loading() {
  return (
    <div aria-busy="true" aria-label="Loading">
      <Skeleton className="mb-2 h-9 w-64" />
      <Skeleton className="mb-6 h-5 w-96 max-w-full" />
      <Skeleton className="h-64 w-full" />
    </div>
  );
}
