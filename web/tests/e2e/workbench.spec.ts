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
  // Empty workspace: real zeros for what exists, honest "not tracked yet" for the rest.
  await expect(page.getByTestId("kpi-Active projects")).toContainText("0");
  await expect(page.getByTestId("kpi-Critical findings")).toContainText("0");
  await expect(page.getByText("No relationships yet")).toBeVisible();
  await expect(page.getByText("No open assessments")).toBeVisible();
  // Command Center panels: real empty states, no simulated activity.
  await expect(page.getByTestId("secondary-metrics")).toContainText("Pending approvals");
  await expect(page.getByTestId("recent-findings")).toContainText("No findings yet");
  await expect(page.getByTestId("recent-operations")).toContainText("No operations yet");
  await expect(page.getByTestId("risk-overview")).toContainText("No open findings");
  const agents = page.getByTestId("agent-activity");
  for (const name of ["Director", "Scout", "Investigator", "Hunter", "Adversary", "Guardian", "Analyst"]) {
    await expect(agents.getByText(name, { exact: true })).toBeVisible();
  }
  await expect(agents.getByText("No runs yet")).toHaveCount(7);
  // Lab status comes from heartbeats (WATCHTOWER); with no lab worker it must never read as online.
  await expect(page.locator("aside").getByText("Never connected")).toBeVisible();
  await expect(page.getByTestId("environment")).toContainText("DRE Lab");
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
      ["Attack Graph", "Attack Graph"], ["War Room", "War Room"], ["BLACKSITE", "BLACKSITE"], ["Reports", "Reports"],
      ["Agents", "AI agents"], ["Audit Log", "Audit Log"], ["Settings", "Settings"], ["Command Center", "Command Center"],
    ]) {
      await nav.getByRole("link", { name: link }).click();
      await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
      await expect(nav.getByRole("link", { name: link })).toHaveAttribute("aria-current", "page");
    }
    await expect(page.getByText("All systems online")).toBeVisible();
    await nav.getByRole("link", { name: "Audit Log" }).click();
    await expect(page.getByTestId("integrity")).toContainText("Audit writes");
    await expect(page.getByTestId("integrity")).toContainText("Never connected");
    await expect(page.locator("main").getByRole("navigation", { name: "Filter by category" })).toBeVisible();
    // The chained export downloads as NDJSON (events from the last five minutes wait, so it may be short).
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export audit log" }).click();
    const file = await (await download).path();
    const header = JSON.parse((await import("node:fs")).readFileSync(file, "utf8").split("\n")[0] ?? "");
    expect(header.format).toBe("janus-audit-export/v1");
    await expect(page.getByText(/Exported \d+ events/)).toBeVisible();
    // Unbuilt divisions are collapsible labels, never links.
    const shield = nav.getByRole("button", { name: /SHIELD/ });
    await expect(shield).toHaveAttribute("aria-expanded", "false");
    await shield.click();
    await expect(nav.getByText("AEGIS Overview")).toBeVisible();
    await expect(nav.getByRole("link", { name: /AEGIS/ })).toHaveCount(0);
  });

  test("BLACKSITE shows a restricted, not-configured state with no execution controls", async ({ page }) => {
    await page.goto(workspaceUrl);
    const nav = page.getByRole("navigation", { name: "Primary" });
    await expect(nav.getByRole("link", { name: /BLACKSITE/ }).getByText("Restricted")).toBeAttached();
    await nav.getByRole("link", { name: /BLACKSITE/ }).click();
    const panel = page.getByTestId("blacksite-restricted");
    await expect(panel).toContainText("Execution environment not configured");
    await expect(page.locator("main").getByRole("button")).toHaveCount(0);
    await expect(page.locator("main form")).toHaveCount(0);
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

  test("authorize a scope, refuse out-of-scope targets, run passive collection", async ({ page }) => {
    await page.goto(`${workspaceUrl}/targets`);
    await page.getByRole("link", { name: "Acme Corporation" }).click();
    await page.getByRole("link", { name: "External reconnaissance" }).click();
    await expect(page.getByText("No authorized scope")).toBeVisible();

    await page.getByRole("button", { name: "Draft a scope" }).click();
    const draft = page.getByRole("region", { name: "Draft scope" });
    await draft.getByLabel("Target type").selectOption("domain_tree");
    await draft.getByLabel("Target value").fill("Acme.TEST.");
    await draft.getByRole("button", { name: "Add" }).first().click();
    await expect(draft.getByText("acme.test", { exact: true })).toBeVisible();
    await draft.getByLabel("Exclusion type").selectOption("host");
    await draft.getByLabel("Exclusion value").fill("mail.acme.test");
    await draft.getByLabel("Reason (optional)").fill("Client mail server: out of bounds");
    await draft.getByRole("button", { name: "Add" }).nth(1).click();
    await expect(draft.getByText("mail.acme.test")).toBeVisible();
    await draft.getByLabel("Authorization reference").fill("SOW-2026-042");
    await draft.getByRole("button", { name: "Save details" }).click();
    await draft.getByRole("button", { name: "Authorize v1" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Authorize scope" }).click();
    await expect(page.getByText("Authorized · v1")).toBeVisible();

    // Proof of control (Profile B G1): the owner gets a one-time token; checks contact real
    // DNS, so they're refused in fixture mode rather than faked.
    await page.getByLabel("Hostname or domain").fill("acme.test");
    await page.getByRole("button", { name: "Issue token" }).click();
    await expect(page.getByTestId("claim-token")).toContainText("janus-verify=");
    await page.getByRole("button", { name: "I've copied it" }).click();
    await page.getByTestId("ownership-claims").getByRole("button", { name: "Check now" }).click();
    await expect(alertIn(page)).toContainText("only run with live collection");
    await page.reload();

    // CHRONICLE: the project's history shows what just happened, newest first.
    const history = page.getByTestId("chronicle");
    await expect(history).toContainText("authorized the scope");
    await expect(history).toContainText("started a scope draft");

    // Server-side refusal of out-of-scope and excluded targets.
    for (const target of ["evil.test", "mail.acme.test"]) {
      await page.getByLabel("Target", { exact: true }).fill(target);
      await page.getByRole("button", { name: "Request collection" }).click();
      await expect(alertIn(page)).toContainText(target === "evil.test" ? "Not in the authorized scope" : "Excluded by scope");
    }

    await page.getByLabel("Collector").selectOption("ct");
    await page.getByLabel("Target", { exact: true }).fill("acme.test");
    await page.getByRole("button", { name: "Request collection" }).click();
    await expect(page.getByText("Queued Certificate transparency")).toBeVisible();
    await expect(page.getByRole("row", { name: /acme\.test.*Done/ })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/4 new · 0 seen · 2 outside scope/)).toBeVisible();

    await page.getByRole("link", { name: "Acme Corporation" }).click();
    await expect(page.getByRole("link", { name: "www.acme.test" })).toBeVisible();
    await expect(page.getByRole("link", { name: "api.acme.test" })).toBeVisible();
    await expect(page.getByRole("link", { name: "mail.acme.test" })).toHaveCount(0);

    await page.getByRole("link", { name: "www.acme.test" }).click();
    await expect(page.getByRole("cell", { name: "Subdomain of" })).toBeVisible();
    await expect(page.getByText("Test fixture").first()).toBeVisible();
    const href = await page.getByRole("link", { name: "Download" }).first().getAttribute("href");
    const download = await page.request.get(href!);
    expect(download.status()).toBe(200);
    expect(download.headers()["content-disposition"]).toContain("attachment");

    // ATLAS: a collected asset starts unverified; a person verifies it and the history records who.
    await expect(page.getByTestId("history-row")).toHaveCount(1);
    await expect(page.getByTestId("history-row").first()).toContainText("automated");
    await page.getByLabel("Status").selectOption("verified");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByTestId("history-row")).toHaveCount(2);
    await expect(page.getByTestId("history-row").first()).toContainText("Unverified → Verified");

    // BLACK BOX: inventory of the collected evidence and an on-demand integrity check.
    const primary = page.getByRole("navigation", { name: "Primary" });
    await primary.getByRole("button", { name: /JANUS CORE/ }).click();
    await primary.getByRole("link", { name: "BLACK BOX" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "BLACK BOX" })).toBeVisible();
    await expect(page.getByTestId("last-verification")).toHaveText("Never verified.");
    await page.getByRole("button", { name: "Verify all evidence" }).click();
    await expect(page.getByText(/^All \d+ evidence records match their SHA-256\.$/)).toBeVisible();
    await expect(page.getByTestId("last-verification")).toContainText("0 failed");

    await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Reconnaissance" }).click();
    await expect(page.getByRole("heading", { name: "Discovery history" })).toBeVisible();
    await page.getByRole("link", { name: "acme.test", exact: true }).click();
    await expect(page.getByText("names outside scope or excluded")).toBeVisible();
  });

  test("command center reflects the registry and graph nodes open records", async ({ page }) => {
    await page.goto(workspaceUrl);
    await expect(page.getByTestId("kpi-Active projects")).toContainText("1");
    await expect(page.getByTestId("kpi-Assets discovered")).toContainText("4");
    await expect(page.getByTestId("kpi-Operations")).toContainText("1");
    await expect(page.getByRole("link", { name: "Acme Corporation — External reconnaissance" })).toBeVisible();
    await expect(page.getByTestId("recent-operations")).toContainText("acme.test");
    await expect(page.getByTestId("recent-operations")).toContainText("Acme Corporation — External reconnaissance");
    await page.getByRole("navigation", { name: "Time window" }).getByRole("link", { name: "1h" }).click();
    await expect(page).toHaveURL(/window=1h/);
    await expect(page.getByTestId("kpi-Active projects")).toContainText("1 started in the last hour");

    const graph = page.getByTestId("intelligence-graph");
    await expect(graph.getByText("Acme Corporation")).toBeVisible();
    await graph.getByText("External reconnaissance").click();
    await expect(page.getByRole("heading", { level: 1, name: "External reconnaissance" })).toBeVisible();
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
    await g.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: /BLACKSITE/ }).click();
    await expect(g.getByTestId("blacksite-restricted")).toContainText("Restricted access");
    await expect(g.getByTestId("blacksite-restricted")).not.toContainText("not configured");
    await expect(g.getByText("Ana Lyst")).toBeVisible();

    // The analyst requests a low-risk probe; it waits for an explicit approval.
    await g.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Target Registry" }).click();
    await g.getByRole("link", { name: "Acme Corporation" }).click();
    await g.getByRole("link", { name: "External reconnaissance" }).click();
    await g.getByLabel("Collector").selectOption("http");
    await g.getByLabel("Target", { exact: true }).fill("www.acme.test");
    await g.getByRole("button", { name: "Request collection" }).click();
    await expect(g.getByText(/runs once it is explicitly approved/)).toBeVisible();
    // An analyst can't approve, not even their own request.
    await expect(g.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);

    await page.goto(`${workspaceUrl}/recon`);
    await page.getByRole("region").or(page.locator("section")).filter({ hasText: "Awaiting approval" }).first()
      .getByRole("link", { name: "www.acme.test" }).click();
    await expect(page.getByText("Approval is tied to scope v1")).toBeVisible();
    await page.getByLabel("Reason (recorded with your decision)").fill("Client approved web fingerprinting");
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Approve and queue" }).click();
    await expect(page.getByText(/Approved by Nick Operator/)).toBeVisible();
    await expect(page.getByRole("cell", { name: "WordPress", exact: true }).first()).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText("High: stated by server").first()).toBeVisible();

    // Web exposure checks (Nuclei, through the scope proxy) take the same approval path.
    await g.getByLabel("Collector").selectOption("nuclei");
    await g.getByLabel("Target", { exact: true }).fill("www.acme.test");
    await g.getByRole("button", { name: "Request collection" }).click();
    await expect(g.getByText(/Requested Web exposure checks \(Nuclei, curated\) for www.acme.test/)).toBeVisible();
    await page.goto(`${workspaceUrl}/recon`);
    await page.getByRole("region").or(page.locator("section")).filter({ hasText: "Awaiting approval" }).first()
      .getByRole("link", { name: "www.acme.test" }).click();
    await page.getByLabel("Reason (recorded with your decision)").fill("Client approved exposure checks");
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Approve and queue" }).click();
    await expect(page.getByText("Git repository metadata is publicly readable")).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/connections through the scope proxy/)).toBeVisible();
    await page.getByRole("row", { name: /Git repository metadata/ }).getByRole("link", { name: "New finding" }).click();
    await expect(page.getByRole("heading", { name: "Git repository metadata is publicly readable" })).toBeVisible();

    // Reusing the invite fails.
    const again = await browser.newContext();
    const a = await again.newPage();
    await a.goto(link);
    await expect(alertIn(a)).toContainText("invalid or has expired");
    await again.close();
    await guest.close();
  });

  test("findings from rule checks, human validation, attack path and a frozen report", async ({ page }) => {
    // The approved technology identification produced rule-made findings.
    await page.goto(`${workspaceUrl}/findings`);
    await expect(page.getByRole("link", { name: "nginx version disclosed in HTTP headers" })).toBeVisible();
    await expect(page.getByRole("link", { name: "PHP version disclosed in HTTP headers" })).toBeVisible();
    await expect(page.locator("main").getByText("Unverified").first()).toBeVisible();

    await page.getByRole("link", { name: "nginx version disclosed in HTTP headers" }).click();
    await expect(page.getByText(/Linked by: rule R1-version-disclosure/)).toBeVisible();
    await page.getByRole("radio", { name: /^Validated/ }).check();
    await page.getByLabel("Why (required, kept with the decision)").fill("Header confirmed in raw evidence");
    await page.getByRole("button", { name: "Record decision" }).click();
    await expect(page.getByText(/Marked validated by Nick Operator/)).toBeVisible();

    // BLACK ICE contradiction flag: a finding marked false positive that newer evidence shows again.
    await page.goto(`${workspaceUrl}/findings`);
    await page.getByRole("link", { name: "PHP version disclosed in HTTP headers" }).click();
    await page.getByRole("radio", { name: /^False positive/ }).check();
    await page.getByLabel("Why (required, kept with the decision)").fill("Thought it was the proxy");
    await page.getByRole("button", { name: "Record decision" }).click();
    await expect(page.getByText(/Marked false positive by Nick Operator/)).toBeVisible();
    await page.goto(`${workspaceUrl}/targets`);
    await page.getByRole("link", { name: "Acme Corporation" }).click();
    await page.getByRole("link", { name: "External reconnaissance" }).click();
    await page.getByLabel("Collector").selectOption("http");
    await page.getByLabel("Target", { exact: true }).fill("www.acme.test");
    await page.getByRole("button", { name: "Request collection" }).click();
    await page.goto(`${workspaceUrl}/recon`);
    await page.getByRole("region").or(page.locator("section")).filter({ hasText: "Awaiting approval" }).first()
      .getByRole("link", { name: "www.acme.test" }).click();
    await page.getByLabel("Reason (recorded with your decision)").fill("Recheck");
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Approve and queue" }).click();
    await expect(page.getByRole("cell", { name: "WordPress", exact: true }).first()).toBeVisible({ timeout: 20_000 });
    await page.goto(`${workspaceUrl}/findings`);
    await expect(page.getByTestId("contradictions")).toContainText("PHP version disclosed in HTTP headers");
    await page.getByTestId("contradictions").getByRole("link", { name: /PHP version disclosed/ }).first().click();
    await expect(page.getByTestId("contradiction")).toBeVisible();

    // A person records a hypothesis: shown as such, never as confirmed.
    await page.goto(`${workspaceUrl}/findings`);
    await page.getByRole("button", { name: "Record a finding" }).click();
    await page.getByLabel("Title").fill("Admin panel may accept default credentials");
    await page.getByRole("combobox", { name: "Severity" }).selectOption("critical");
    await page.getByRole("combobox", { name: "Status" }).selectOption("hypothesis");
    await page.getByRole("button", { name: "Record finding" }).click();
    await expect(page.getByText("Hypothesis: plausible, but not shown by evidence.")).toBeVisible();

    // Attack path built on a validated finding plus a hypothesis stays a hypothesis.
    await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Attack Graph" }).click();
    await expect(page.getByTestId("attack-graph")).toBeVisible();
    await page.getByRole("button", { name: "Propose an attack path" }).click();
    await page.getByLabel("Path title").fill("Fingerprint to admin takeover");
    const pick = async (label: string, text: string) => {
      const select = page.getByLabel(label);
      const value = await select.locator("option", { hasText: text }).getAttribute("value");
      await select.selectOption(value!);
    };
    await pick("Step 1: finding or asset", "nginx version disclosed");
    await page.getByLabel("Step 1: what happens").fill("Version tells the attacker which exploits apply");
    await pick("Step 2: finding or asset", "Admin panel may accept default credentials");
    await page.getByLabel("Step 2: what happens").fill("Log in with vendor defaults");
    await page.getByRole("button", { name: "Save as hypothesis" }).click();
    await expect(page.getByText("Hypothesis — not demonstrated")).toBeVisible();
    await page.getByLabel("Review note").fill("Looks right");
    await page.getByRole("button", { name: "Mark validated" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Mark validated" }).click();
    await expect(alertIn(page)).toContainText("Every finding in the path must be validated first");
    await expect(page.getByText("Hypothesis — not demonstrated")).toBeVisible();

    // Report: frozen, hashed, honest about hypotheses and fixture data.
    await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Reports" }).click();
    await page.getByRole("button", { name: "Generate report" }).click();
    await expect(page.getByRole("heading", { name: /Executive summary/ })).toBeVisible();
    await expect(page.getByText(/TEST-FIXTURE evidence/)).toBeVisible();
    await expect(page.getByText(/attack paths are hypotheses, not demonstrated compromises/)).toBeVisible();
    await expect(page.getByText("Integrity check failed")).toHaveCount(0);
    // Server-side PDF of the same snapshot.
    const pdf = page.waitForEvent("download");
    await page.getByRole("link", { name: "Download PDF" }).click();
    const file = await (await pdf).path();
    expect((await import("node:fs")).readFileSync(file).subarray(0, 5).toString()).toBe("%PDF-");

    // BLACK ICE replay: today's rules over the report's evidence, read-only.
    await page.getByRole("link", { name: "Check against current rules" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Replay against current rules" })).toBeVisible();
    await expect(page.getByText("Today's rules reach the same rule-based findings as the report.")).toBeVisible();
    await page.goBack();
    await expect(page.getByText("Integrity check failed")).toHaveCount(0);

    // BLACK ICE freshness: certificate search has run, so it's up to date.
    await page.goto(`${workspaceUrl}/recon`);
    await expect(page.getByTestId("source-ct")).toContainText("Up to date");

    await page.goto(workspaceUrl);
    await expect(page.getByTestId("kpi-Critical findings")).toContainText("1");
    await expect(page.getByRole("link", { name: "Admin panel may accept default credentials" })).toBeVisible();
  });

  test("agents propose; the gateway decides; AI findings stay hypotheses", async ({ page }) => {
    await page.goto(`${workspaceUrl}/targets`);
    await page.getByRole("link", { name: "Acme Corporation" }).click();
    await page.getByRole("link", { name: "External reconnaissance" }).click();
    await expect(page.getByText(/Agents only propose/)).toBeVisible();

    // Scout: a passive proposal is queued; a low-risk one waits for someone else.
    await page.getByRole("button", { name: "Suggest collections (Scout)" }).click();
    await expect(page.getByText("AI proposal")).toBeVisible();
    await expect(page.getByText("Done", { exact: true })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText("dns · www.acme.test")).toBeVisible();
    await expect(page.getByText("awaiting_approval")).toBeVisible();
    await expect(page.getByText(/Agent's notes \(AI-written, not verified\)/)).toBeVisible();

    // Hunter: a candidate finding citing real evidence, reviewed by Guardian.
    await page.goBack();
    await page.getByRole("button", { name: "Look for findings (Hunter)" }).click();
    await expect(page.getByText("Done", { exact: true }).first()).toBeVisible({ timeout: 20_000 });
    await page.getByRole("link", { name: "Open finding" }).click();
    await expect(page.getByRole("heading", { name: "AI provenance" })).toBeVisible();
    await expect(async () => {
      await page.reload();
      await expect(page.getByText("Guardian: Not enough evidence")).toBeVisible({ timeout: 1_000 });
    }).toPass({ timeout: 20_000 });
    await expect(page.locator("main").getByText("Hypothesis").first()).toBeVisible();
  });

  test("director plans; adversary and analyst write hypotheses, labelled as AI", async ({ page }) => {
    test.setTimeout(90_000); // three agent runs, each through the worker
    await page.goto(`${workspaceUrl}/targets`);
    await page.getByRole("link", { name: "Acme Corporation" }).click();
    await page.getByRole("link", { name: "External reconnaissance" }).click();
    await expect(page.getByText(/Agents only propose/)).toBeVisible();
    const project = page.url();

    // Adversary: an attack path built from recorded findings, recorded as a hypothesis.
    await page.getByRole("button", { name: "Propose attack paths (Adversary)" }).click();
    await page.waitForURL(/\/agents\/[0-9a-f-]{36}$/);
    await expect(page.getByText("Done", { exact: true })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/steps, hypothesis/)).toBeVisible();
    await page.getByRole("link", { name: "Open the attack graph" }).click();
    const card = page.locator("article").filter({ hasText: "Forgotten host to internal foothold" });
    await expect(card.getByText("AI proposal")).toBeVisible();
    await expect(card.getByText("Hypothesis — not demonstrated")).toBeVisible();

    // Analyst: a narrative that is labelled as AI-written, beside counts from the records.
    await page.goto(project);
    await page.getByRole("button", { name: "Summarise the assessment (Analyst)" }).click();
    await page.waitForURL(/\/agents\/[0-9a-f-]{36}$/);
    await expect(page.getByText("Done", { exact: true })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText("Analyst's write-up (AI-written, not verified)")).toBeVisible();
    await expect(page.getByText("Counts from the records when it ran (not from the model)")).toBeVisible();
    await page.goto(project);
    await expect(page.getByTestId("analyst-summary")).toContainText("AI-written, not verified");

    // Director: only creates tasks for the other agents.
    await page.getByLabel("Objective for the Director").fill("Get a picture of the external surface");
    await page.getByRole("button", { name: "Plan it (Director)" }).click();
    await page.waitForURL(/\/agents\/[0-9a-f-]{36}$/);
    await expect(page.getByText("Done", { exact: true }).first()).toBeVisible({ timeout: 20_000 });
    const followUps = page.locator("section").filter({ has: page.getByRole("heading", { name: "Follow-up tasks" }) });
    await expect(followUps.getByText("Scout", { exact: true })).toBeVisible();
    await expect(followUps.getByText("Analyst", { exact: true })).toBeVisible();

    // Overview: every number comes from the task records.
    await page.goto(`${workspaceUrl}/agents`);
    await expect(page.getByRole("heading", { level: 1, name: "AI agents" })).toBeVisible();
    const roster = page.locator("section").filter({ has: page.getByRole("heading", { name: /^Agents · last/ }) });
    for (const name of ["Director", "Investigator", "Adversary", "Analyst", "Guardian"]) {
      await expect(roster.getByRole("cell", { name: new RegExp(`^${name}`) })).toBeVisible();
    }
    await page.goto(workspaceUrl);
    await expect(page.getByRole("link", { name: "All agents" })).toBeVisible();
    await expect(page.getByRole("progressbar", { name: "Agent tasks finished" }).first()).toBeVisible();
  });

  test("war room: waiting decisions, AI proposals to review and the decision log", async ({ page }) => {
    // The header bell counts only what you can decide; your own request waits for someone else.
    await page.goto(workspaceUrl);
    await page.getByRole("link", { name: /waiting for someone else's decision|waiting for your decision/ }).click();
    await expect(page).toHaveURL(/\/war-room$/);
    await expect(page.getByRole("heading", { level: 1, name: "War Room" })).toBeVisible();
    // Single operator (D1): the owner explicitly decides Scout's low-risk proposal themselves.
    const op = page.getByTestId("awaiting-op").filter({ hasText: "www.acme.test" });
    await expect(op.getByText("AI proposal")).toBeVisible();
    await expect(op.getByText(/You requested this/)).toHaveCount(0);
    await expect(op.getByRole("button", { name: "Approve" })).toHaveCount(1);
    // Agent hypotheses wait for a person; the log shows who did what.
    const review = page.locator("section").filter({ has: page.getByRole("heading", { name: /^AI proposals to review/ }) });
    await expect(review.getByText("Hypothesis").first()).toBeVisible();
    const log = page.locator("section").filter({ has: page.getByRole("heading", { name: "Decision log" }) });
    await expect(log.getByText(/started an agent/).first()).toBeVisible();
    await noHorizontalScroll(page);
  });

  test("BLACK OPS: browse and filter playbooks, preflight refuses, a passive playbook runs", async ({ page }) => {
    await page.goto(`${workspaceUrl}/blacksite`);
    await page.getByTestId("blackops-entry").getByRole("link", { name: "Open playbook library" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "BLACK OPS" })).toBeVisible();
    await expect(page.getByTestId("profiles")).toContainText("Off");
    // Profile B test identities: no worker key on this deployment, so nothing can be stored.
    await expect(page.getByTestId("test-identities")).toContainText("needs the worker key");
    const list = page.getByTestId("playbook-list");
    await expect(list.getByRole("listitem")).toHaveCount(8);
    await page.getByTestId("playbook-search").fill("tls");
    await expect(list.getByRole("listitem")).toHaveCount(1);
    await expect(list).toContainText("TLS Configuration Audit");
    await page.getByTestId("playbook-search").fill("");
    await page.getByTestId("playbook-category").selectOption("reconnaissance");
    await expect(list.getByRole("listitem")).toHaveCount(2);
    await list.getByRole("link", { name: /Surface Mapper/ }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Surface Mapper" })).toBeVisible();

    // Out of scope: the preflight shows why, and there is nothing to launch.
    await page.getByTestId("launch-target").fill("evil.test");
    await page.getByTestId("run-preflight").click();
    await expect(page.locator('[data-check="scope"]')).toHaveAttribute("data-status", "fail");
    await expect(page.getByText("Preflight failed")).toBeVisible();
    await expect(page.getByRole("button", { name: "Launch playbook" })).toHaveCount(0);

    await page.getByTestId("launch-target").fill("acme.test");
    await page.getByTestId("run-preflight").click();
    await expect(page.locator('[data-check="scope"]')).toHaveAttribute("data-status", "pass");
    await page.getByRole("button", { name: "Launch playbook" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Launch" }).click();
    await expect(page).toHaveURL(/\/blacksite\/ops\/runs\//);
    await expect(page.getByRole("heading", { level: 1, name: "acme.test" })).toBeVisible();
    await expect(page.locator("main").getByText("Succeeded", { exact: true })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole("row", { name: /^1 Certificate transparency/ })).toContainText("Done");
    await page.goto(`${workspaceUrl}/blacksite/ops`);
    await expect(page.getByRole("row", { name: /Surface Mapper.*acme\.test/ })).toContainText("2/2");
    await noHorizontalScroll(page);
  });

  test("NEXUS: start a workflow; a person starts the step; it waits for approval; cancel", async ({ page }) => {
    await page.goto(`${workspaceUrl}/targets`);
    await page.getByRole("link", { name: "Acme Corporation" }).click();
    await page.getByRole("link", { name: "External reconnaissance" }).click();
    await page.getByRole("combobox", { name: "Workflow", exact: true }).selectOption("exposure-review");
    await page.getByRole("combobox", { name: "Workflow target" }).selectOption("acme.test");
    await page.getByRole("button", { name: "Start workflow" }).click();
    await expect(page).toHaveURL(/\/nexus\/runs\//);
    const assess = page.getByTestId("step-assess");
    await expect(assess).toContainText("Ready to start");
    await expect(page.getByTestId("step-triage")).toContainText("Waiting on earlier steps");

    // Starting the step launches the playbook as this person; its operation awaits approval.
    await assess.getByRole("button", { name: "Start step" }).click();
    await expect(assess).toContainText("In progress");
    await expect(assess.getByRole("link", { name: /Operation/ })).toBeVisible();

    await page.getByRole("button", { name: "Cancel workflow" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Cancel workflow" }).click();
    await expect(page.locator("main").getByText("Cancelled", { exact: true }).first()).toBeVisible();
    await page.goto(`${workspaceUrl}/nexus`);
    await expect(page.getByRole("row", { name: /Exposure review.*acme\.test/ })).toContainText("Cancelled");
    await noHorizontalScroll(page);
  });

  test("mobile: drawer navigation, no horizontal scroll", async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: STATE, viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
    const page = await ctx.newPage();
    await page.goto(workspaceUrl);
    await expect(page.getByTestId("intelligence-graph")).toBeVisible();
    await noHorizontalScroll(page);
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
