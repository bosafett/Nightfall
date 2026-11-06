import Image from "next/image";
import type { ReactNode } from "react";

export function AuthCard({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <main className="grid min-h-screen place-items-center px-4 py-10">
      <div className="w-full max-w-md">
        <div className="mb-6 flex flex-col items-center text-center">
          <Image src="/nightfall-mark.svg" alt="" width={72} height={65} priority />
          <p className="mt-2 text-xs font-semibold tracking-[0.3em] text-crimson-text">DRE</p>
          <p className="text-2xl font-bold tracking-[0.12em] text-crimson-text">JANUS</p>
          <p className="font-mono text-xs tracking-[0.3em] text-muted">JNS.OS</p>
        </div>
        <div className="rounded-lg border border-border bg-surface p-6">
          <h1 className="text-xl font-semibold">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
          <div className="mt-5">{children}</div>
        </div>
        <p className="mt-6 text-center text-xs text-muted">Authorized use only. All activity is recorded.</p>
      </div>
    </main>
  );
}
