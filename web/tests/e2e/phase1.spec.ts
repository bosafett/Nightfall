import { expect, test, type Page } from "@playwright/test";
import { E2E } from "../../playwright.config";
import { totp } from "./totp";

test.describe.configure({ mode: "serial" });

const STATE = "test-results/owner-state.json";
// Next.js renders its own empty role="alert" route announcer; exclude it.
const alertIn = (p: Page) => p.locator("[role=alert]:not(#__next-route-announcer__)");
let workspaceUrl = "";

async function noHorizontalScroll(page: Page) {
  const [scroll, client] = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
  expect(scroll).toBeLessThanOrEqual(client);
}

test("signed-out visitors are sent to sign in", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/w/00000000-0000-0000-0000-000000000000/targets");
  await expect(page).toHaveURL(/\/login$/);
  const res = await page.request.get("/login");
  expect(res.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(res.headers()["x-frame-options"]).toBe("DENY");
});

test("owner signs in, is required to enrol two-factor, then reaches the workspace", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(E2E.ownerEmail);
  await page.getByLabel("Password").fill("wrong password entirely");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(alertIn(page)).toContainText("Email or password is incorrect");

  await page.getByLabel("Password").fill(E2E.ownerPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/account\/security$/);
  await expect(page.getByText("Your role requires two-factor")).toBeVisible();

  await page.getByRole("button", { name: "Set up two-factor" }).click();
  const secret = await page.getByTestId("totp-secret").getAttribute("data-secret");
  expect(secret).toBeTruthy();
  await page.getByLabel("Authentication code").fill("000000");
  await page.getByRole("button", { name: "Turn on two-factor" }).click();
  await expect(alertIn(page)).toContainText("didn't work");
  await page.getByLabel("Authentication code").fill(totp(secret!));
  await page.getByRole("button", { name: "Turn on two-factor" }).click();
  await expect(page.getByText(/^On\./)).toBeVisible();

  await page.getByRole("link", { name: /Back to DRE Lab/ }).click();
  await expect(page.getByRole("heading", { name: "Command Center" })).toBeVisible();
  workspaceUrl = new URL(page.url()).pathname;
  await page.context().storageState({ path: STATE });
});

test.describe("as the owner", () => {
  test.use({ storageState: STATE });

  test("every primary section is reachable from the sidebar", async ({ page }) => {
    await page.goto(workspaceUrl);
    const nav = page.getByRole("navigation", { name: "Primary" });
    for (const [link, heading] of [
      ["Target Registry", "Target Registry"], ["Reconnaissance", "Reconnaissance"], ["Findings", "Findings"],
      ["Attack Graph", "Attack Graph"], ["War Room", "War Room"], ["Reports", "Reports"],
      ["Settings", "Settings"], ["Command Center", "Command Center"],
    ]) {
      await nav.getByRole("link", { name: link }).click();
      await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
      await expect(nav.getByRole("link", { name: link })).toHaveAttribute("aria-current", "page");
    }
    await expect(page.getByText("All systems online")).toBeVisible();
  });

  test("create an organization and a project; data persists after reload", async ({ page }) => {
    await page.goto(`${workspaceUrl}/targets`);
    await expect(page.getByText("No organizations yet")).toBeVisible();
    await page.getByRole("button", { name: "New organization" }).click();
    await page.getByLabel("Organization name").fill("Acme Corporation");
    await page.getByLabel("Notes").fill("Signed engagement letter #42");
    await page.getByRole("button", { name: "Create organization" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Acme Corporation" })).toBeVisible();

    await page.getByRole("button", { name: "New project" }).click();
    await page.getByLabel("Project name").fill("External reconnaissance");
    await page.getByLabel("Assessment type").selectOption("reconnaissance");
    await page.getByRole("button", { name: "Create project" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "External reconnaissance" })).toBeVisible();

    await page.getByLabel("Status").selectOption("active");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("Saved.")).toBeVisible();
    await page.reload();
    await expect(page.getByLabel("Status")).toHaveValue("active");
    await expect(page.locator("main").getByText("Active", { exact: true }).first()).toBeVisible();

    await page.goto(`${workspaceUrl}/targets`);
    const row = page.getByRole("row", { name: /Acme Corporation/ });
    await expect(row).toContainText("1");

    // Duplicate names are rejected with a readable message.
    await page.getByRole("button", { name: "New organization" }).click();
    await page.getByLabel("Organization name").fill("acme corporation");
    await page.getByRole("button", { name: "Create organization" }).click();
    await expect(alertIn(page)).toContainText("already exists");
  });

  test("invite an analyst who joins and sees the shared registry read-only for settings", async ({ page, browser }) => {
    await page.goto(`${workspaceUrl}/settings`);
    await page.getByLabel("Email").fill("analyst@nightfall.test");
    await page.getByLabel("Role").selectOption("analyst");
    await page.getByRole("button", { name: "Create invite link" }).click();
    const link = await page.getByTestId("one-time-link").inputValue();
    expect(link).toContain("/accept-invite#token=");
    await expect(page.getByRole("row", { name: /analyst@nightfall.test/ })).toBeVisible();

    const guest = await browser.newContext();
    const g = await guest.newPage();
    await g.goto(link);
    await expect(g.getByText(/invited to DRE Lab as Analyst/)).toBeVisible();
    await g.getByLabel("Your name").fill("Ana Lyst");
    await g.getByLabel("Password", { exact: true }).fill("analyst password long enough");
    await g.getByLabel("Repeat password").fill("analyst password long enough");
    await g.getByRole("button", { name: "Join workspace" }).click();
    await expect(g.getByRole("heading", { name: "Command Center" })).toBeVisible();

    await g.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Target Registry" }).click();
    await expect(g.getByRole("link", { name: "Acme Corporation" })).toBeVisible();
    await g.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Settings" }).click();
    await expect(g.getByRole("heading", { name: "Invites" })).toHaveCount(0);
    await expect(g.getByText("Ana Lyst")).toBeVisible();

    // Reusing the invite fails.
    const again = await browser.newContext();
    const a = await again.newPage();
    await a.goto(link);
    await expect(alertIn(a)).toContainText("invalid or has expired");
    await again.close();
    await guest.close();
  });

  test("mobile: drawer navigation, no horizontal scroll", async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: STATE, viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
    const page = await ctx.newPage();
    await page.goto(`${workspaceUrl}/targets`);
    await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);
    await noHorizontalScroll(page);
    await page.getByRole("button", { name: "Open navigation" }).click();
    await page.getByRole("dialog", { name: "Navigation" }).getByRole("link", { name: "Settings" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toBeVisible();
    await expect(page.getByRole("dialog", { name: "Navigation" })).toHaveCount(0);
    await noHorizontalScroll(page);
    await ctx.close();
  });

  test("sign out ends the session", async ({ page }) => {
    await page.goto(workspaceUrl);
    await page.locator("summary").click();
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page).toHaveURL(/\/login$/);
    await page.goto(`${workspaceUrl}/targets`);
    await expect(page).toHaveURL(/\/login$/);
  });

  test("signing in again requires the authenticator code", async ({ page }) => {
    await page.context().clearCookies();
    await page.goto("/login");
    await page.getByLabel("Email").fill(E2E.ownerEmail);
    await page.getByLabel("Password").fill(E2E.ownerPassword);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByLabel("Authentication code")).toBeVisible();
  });
});
