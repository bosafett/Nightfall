import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end: real API (uvicorn) + production Next build against a throwaway database.
 * Defaults target the local dev cluster; CI overrides E2E_* variables.
 */
const API_PORT = 8765;
const WEB_PORT = 3100;
const PY = process.env.E2E_PYTHON ?? "../api/.venv/bin/python";
export const E2E = {
  web: `http://localhost:${WEB_PORT}`,
  appDb: process.env.E2E_DATABASE_URL ?? "postgresql://nightfall_app:app_dev_only@127.0.0.1:5432/nightfall_e2e",
  ownerDb: process.env.E2E_MIGRATION_DATABASE_URL ?? "postgresql://nightfall_owner:owner_dev_only@127.0.0.1:5432/nightfall_e2e",
  python: PY,
  ownerEmail: "owner@nightfall.test",
  ownerPassword: "e2e owner password, long enough",
};

const apiEnv = {
  NIGHTFALL_DATABASE_URL: E2E.appDb,
  NIGHTFALL_MIGRATION_DATABASE_URL: E2E.ownerDb,
  NIGHTFALL_SECRET_KEY: Buffer.alloc(32, 7).toString("base64"),
  NIGHTFALL_PUBLIC_ORIGIN: E2E.web,
  // Next.js rewrites pass client X-Forwarded-For through untouched; never trust it here.
  NIGHTFALL_FORWARDED_HOPS: "0",
};

export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  globalSetup: "./tests/e2e/global-setup.ts",
  use: { baseURL: E2E.web, trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `${PY} -m uvicorn nightfall.asgi:app --app-dir ../api --host 127.0.0.1 --port ${API_PORT}`,
      url: `http://127.0.0.1:${API_PORT}/api/health`,
      env: apiEnv,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `npm run build && npx next start -p ${WEB_PORT}`,
      url: `${E2E.web}/login`,
      env: { API_INTERNAL_URL: `http://127.0.0.1:${API_PORT}` },
      reuseExistingServer: false,
      timeout: 300_000,
    },
  ],
});
