import { execFileSync } from "node:child_process";
import path from "node:path";
import { E2E } from "../../playwright.config";

/** Fresh schema + one owner account (no 2FA yet; enrolment is part of the test). */
export default function globalSetup() {
  const api = path.resolve(import.meta.dirname, "../../../api");
  const env = { ...process.env, NIGHTFALL_MIGRATION_DATABASE_URL: E2E.ownerDb, NIGHTFALL_ADMIN_PASSWORD: E2E.ownerPassword };
  const run = (...args: string[]) => execFileSync(E2E.python, args, { cwd: api, env, stdio: "inherit" });
  run("-m", "alembic", "downgrade", "base");
  run("-m", "alembic", "upgrade", "head");
  run("-m", "nightfall.cli", "create-owner", "--email", E2E.ownerEmail, "--name", "Nick Operator",
    "--workspace-name", "DRE Lab", "--workspace-slug", "dre-lab");
}
