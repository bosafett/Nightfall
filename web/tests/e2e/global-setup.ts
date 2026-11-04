import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { E2E, workerEnv } from "../../playwright.config";

/** Fresh schema + one owner account (no 2FA yet; enrolment is part of the test) + worker. */
export default function globalSetup() {
  rmSync(E2E.evidenceDir, { recursive: true, force: true });
  mkdirSync(E2E.evidenceDir, { recursive: true });
  const api = path.resolve(import.meta.dirname, "../../../api");
  const env = { ...process.env, NIGHTFALL_MIGRATION_DATABASE_URL: E2E.ownerDb, NIGHTFALL_ADMIN_PASSWORD: E2E.ownerPassword };
  const run = (...args: string[]) => execFileSync(E2E.python, args, { cwd: api, env, stdio: "inherit" });
  run("-m", "alembic", "downgrade", "base");
  run("-m", "alembic", "upgrade", "head");
  run("-m", "nightfall.cli", "create-owner", "--email", E2E.ownerEmail, "--name", "Nick Operator",
    "--workspace-name", "DRE Lab", "--workspace-slug", "dre-lab");

  const worker = spawn(E2E.python, ["-m", "nightfall.recon.worker"], {
    cwd: api, env: { ...process.env, ...workerEnv }, stdio: ["ignore", "inherit", "inherit"],
  });
  return () => { worker.kill("SIGTERM"); };
}
