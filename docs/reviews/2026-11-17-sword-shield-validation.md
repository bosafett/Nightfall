# SWORD and SHIELD — validation of delivered features (2026-11-17)

Build-time validation by the implementer (AI assistant), **not** an independent review. It checks that every
feature `docs/ROADMAP.md` lists as Delivered works at the current commit, at four levels: API tests against real
Postgres, browser tests against the real API and a production web build, CI on `main`, and production health.

## What ran

| Level | Commit | Result |
|---|---|---|
| API suite (Postgres 16, app role under RLS, fixture collectors, no network) | `993b31a` | All pass (pytest exit 0, ~516 tests; a few skipped where an optional tool isn't installed) |
| BLACKSITE packet suites (`test_blacksite*`, `test_lab`, `test_warpath`, `test_tool_runner`) | `993b31a` | 53 passed |
| Web unit tests, lint, typecheck, production build | `4c2bd3f`+ | 48 passed; clean |
| Browser end to end (Playwright, Chromium; real API + `next build`, fixture collectors and fixture model) | `3092183` | 20 / 20 passed; 21 / 21 with the Intrusion Detection test added here |
| CI on `main`, including the Docker sandbox and lab jobs this environment can't run | `3b8c2c6`, `993b31a`, `3092183` | Success on all three |
| Production (Vercel) | `3092183` | Deploy READY; `/api/health` OK (api, database, ai); no runtime errors in the last 7 days |

## Features

| Area | API tests | Browser test | Result |
|---|---|---|---|
| Core / identity: sign-in, two-factor enrolment and step-up, invites, roles, RLS, audit | `test_auth*`, `test_authz`, `test_db_isolation`, `test_route_security`, `test_access_audit`, `test_audit_export` | sign-in and enrolment; sign out; re-sign-in needs the code; analyst invite and read-only settings | Pass |
| Scope & recon: versioned scopes, passive collectors, approval-gated probes | `test_scopes`, `test_scope_engine`, `test_recon`, `test_probes`, `test_ownership`, `test_ct_retry`, `test_posture` | authorize a scope, refuse out-of-scope, run passive collection | Pass |
| Findings & reports: rule findings, human validation, attack paths, frozen reports | `test_findings`, `test_golden_rules`, `test_paths_reports`, `test_report_pdf`, `test_reviews`, `test_contradictions` | rule findings, validation, attack path, frozen report | Pass |
| Third-party tools: Nuclei in the sandbox | `test_nuclei`, `test_tool_runner`, `test_egress`, `test_safe_http` | — | Pass; the live sandbox is proven by the CI `sandbox` job |
| AI agents (off on hosted) | `test_agents`, `test_agents_5b`, `test_ollama` | agents propose, gateway decides; AI findings stay hypotheses; director plans | Pass (fixture model) |
| BLACK ICE / BLACK OPS / Profile B | `test_blackice`, `test_blackops`, `test_profile_b` | BLACK OPS browse, preflight refuses, passive playbook runs | Pass; Profile B stays off |
| CHRONICLE / BLACK BOX / NEXUS | `test_chronicle`, `test_blackbox`, `test_evidence_pg`, `test_nexus`, `test_approvals` | NEXUS workflow waits for approval, cancel | Pass |
| CONTROL / WATCHTOWER / Overview / War Room | `test_watchtower`, `test_overview`, `test_warroom` | command center; war room decisions and log | Pass |
| WARPATH | `test_warpath` | page, ATT&CK attribution, plans need a lab scope | Pass (execution stays behind BLACKSITE) |
| BLACKSITE | `test_blacksite`, `test_blacksite_ui`, `test_lab`, `test_lab_pack1` | restricted, not-configured state with no execution controls | Pass; independent review outstanding |
| SHIELD v1 — AEGIS monitoring | `test_shield` | authorize monitoring, see it on AEGIS, revoke | Pass |
| SHIELD v2 — incidents | `test_incidents`, `test_warroom` | open from an alert, work it, close with a review | Pass |
| SHIELD v3 phase 1 — sign-in alerts | `test_sign_in_alerts`, `test_auth_audit` | — | Pass (API only; no browser test) |
| SHIELD v3 phase 2 — sensor and GUARD | `test_shield_sensors`, `test_shield_guard`, `test_janus_sensor`, live run (`2026-11-17-shield-phase2-safeguards.md`) | **added:** register a sensor, authorize GUARD, kill switch, allow list, approve and lift a block | Pass |

## Changed in this validation

- `web/tests/e2e/workbench.spec.ts`: an Intrusion Detection browser test. It was the only delivered page with no
  browser coverage.

## Not established here

- **That the SHIELD daily schedule runs in production.** The Vercel cron (`/api/internal/worker/drain`, 04:17 UTC)
  is configured and the route shows traffic, but the log search can't filter by path, so a successful scheduled run
  wasn't confirmed. Owner check: AEGIS Overview shows *last scheduled* within the past day.
- **Signed-in production behaviour.** Checks behind sign-in need the owner's account; only health and error logs
  were checked in production. Owner check: open AEGIS, Alerts, Incidents and Intrusion Detection once.
- **Real network collection.** Every run here used fixture collectors and a fixture model by design; the real
  collectors' network behaviour is covered by `test_safe_http`, `test_egress` and the CI sandbox job, not by a live
  run against a real target.
- **Sign-in alerts in the browser.** Covered by API tests only.
- BLACKSITE and Profile B execution stay off pending review; their gates were tested, not their live runs (see the
  review packets).
