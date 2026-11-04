"use client";

import { Alert, Button } from "@/components/ui/primitives";

export default function WorkspaceError({ reset }: { error: Error; reset: () => void }) {
  return (
    <div className="max-w-lg space-y-4">
      <Alert>Couldn&apos;t load this page. The API may be unavailable.</Alert>
      <Button onClick={reset}>Try again</Button>
    </div>
  );
}
