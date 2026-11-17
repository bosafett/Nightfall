# Review packet 1: BLACKSITE (isolated lab)

**Unlocks:** `NIGHTFALL_BLACKSITE_REVIEW_REF` (together with `NIGHTFALL_BLACKSITE_ENABLED=true` on the lab machine).
**Main document:** [2026-11-blacksite-authorization-model.md](../2026-11-blacksite-authorization-model.md), a
detailed draft written by the AI assistant that built the system (findings F1–F8). Verify each finding rather than
trust it. **WARPATH** runs entirely inside BLACKSITE, so this review covers it too, with the additions in §5.

## 0. Status for the independent review (prepared 2026-11-17)

**Review this commit:** `993b31a0cda7764fd0898d2f68b77a1e83f0d3e9` (`main`, 2026-11-17). Record the commit you
actually review in your report.

**Packet suites at that commit:** 53 passed (`test_blacksite` + `test_blacksite_ui` + `test_lab` + `test_warpath` +
`test_tool_runner`; Postgres 16, no network). The self-review ran 49 of these at `194b377`.

**Already done:** an owner self-review, *not independent*:
[2026-11-08-blacksite-self-review.md](../2026-11-08-blacksite-self-review.md). Approved with one condition (R1).
BLACKSITE currently runs under temporary self-review mode, which expires by 2027-01-31. An independent reference in
`NIGHTFALL_BLACKSITE_REVIEW_REF` replaces it.

### Changes since the self-review (`194b377` → `993b31a`) that touch this scope

| Commit | Change | What to check |
|---|---|---|
| `6c1099c` | Console wordmark (inline SVG); owner-only link to the console from the hosted app | The link adds no execution control to the hosted app (B4, B12) |
| `48296df` | Readiness checks for lab tool pack 1, WARPATH and Profile B; no migration | Preflight still refuses without the review reference (B5) |
| `3288084` | **R1 fix:** the lab worker may reach port 5432 only on the database's own addresses, and DNS only on the container's resolver (`infra/tools/egress-lock.sh`) | §3.1 below; whether condition 1 can close |
| `67e5020`, `0593f85`, `3b8c2c6` | SHIELD migrations 0023–0025 (incidents, sign-in alerts, sensors and blocks) | New tables are outside the lab boundary. Checked at `993b31a`: `nightfall_blacksite` and `nightfall_lab_worker` have **no** grants on any of them, and can't execute the new `SECURITY DEFINER` functions (`nf_record_sign_in_alert`, `nf_sensor_authenticate`). Confirm with the query in §3.6 |

The SHIELD v3 phase 2 sensor (`infra/janus-sensor/`) may run on the same host as the lab. It's outside this
packet: it runs on the host, not in the lab network, listens on nothing, and has its own validation record
(`docs/reviews/2026-11-17-shield-phase2-safeguards.md`).

### Earlier findings: state to confirm

| Finding | Stated status | Your task |
|---|---|---|
| F1 (High): lab worker's database role not confined | Fixed (migrations 0010, 0011) | Verify (B9) |
| F2 (Medium): two-person rule counts accounts, not people | Owner decision D1: single operator | Confirm the single-operator rule is enforced as described (§17 of the architecture review) |
| F3 (Medium): authorizing a scope proves intent, not ownership | Closed by proof of control (migration 0017) for Profile B; lab scopes are lab-network only (B7) | Verify for the lab |
| F4 (Medium): lab range configured twice; "private" too broad | Fixed: the worker checks its own routes at start-up | Verify (B8, §3.1) |
| F5 (Low): approvals don't expire | Fixed for lab work: 24 hours | Verify (B11) |
| F6 (Low): the owner can do everything | Accepted | None |
| F7 (Low): audit trail changeable with the database owner's credential | Partly addressed: hash-chained export, plus a check against a kept export | Judge whether it's enough (§4, last question) |
| F8 (Info): parts of the design untested because unbuilt | Information | Note anything still unbuilt |
| R1 (Low): worker firewall limited ports, not destinations | Fixed in `3288084`; seen on the lab machine 2026-11-16; **a lab run through the new firewall not yet seen** | §3.1 |

### What the owner provides

- Read access to the repository (it's public) and this packet.
- A session on the lab machine (in person, screen share or SSH) for the hand checks in §3. The checks don't need
  Neon or Vercel credentials, and the reviewer never needs the owner's password or TOTP secret.
- Someone who didn't build the system and isn't the owner or a second account of the owner (packets README).

## 1. The question

> Can a lab action only run against an authorized lab target, with the required approval, by the owner, and can
> the lab never reach a real system?

**In scope:**
- the BLACKSITE listener (host-only app, loopback only, owner only, fresh two-factor);
- lab scopes;
- the lab worker and its database role;
- lab approvals;
- the probe deck;
- lab playbooks;
- WARPATH's BLACKSITE side.

**Out of scope:** Profile B (packet 3); the wider Nuclei templates (packet 2); the hosted app's general security
(reviewed in `2026-11-05-phase5-6-security-pass.md`).

## 2. Claims, enforcement and evidence

| # | Claim | Enforced in | Test(s) |
|---|---|---|---|
| B1 | BLACKSITE is off unless enabled, and refused on the hosted platform | `api/nightfall/config.py`, `api/nightfall/blacksite/app.py` (`preflight_checks`) | `test_blacksite.py::test_disabled_by_default_fails_closed`, `::test_flag_is_refused_on_the_hosted_platform`, `::test_start_up_checks` |
| B2 | Only loopback peers, the expected Host header and a loopback Origin reach it | `blacksite/app.py` (`HostOnly`, `RequestGuard` origins) | `::test_non_loopback_peers_are_refused`, `::test_foreign_host_header_is_refused`, `::test_mutations_need_the_loopback_origin` |
| B3 | Only the owner, with two-factor in the last 15 minutes, and every access is audited | `core/tenancy/deps.py` (`require`, the `blacksite` branch) | `::test_unauthenticated_and_non_owner_are_refused`, `::test_stale_or_missing_two_factor_needs_a_step_up`, `::test_owner_access_is_audited_and_uses_the_confined_role` |
| B4 | The public app has no BLACKSITE routes and can't create or approve lab work | `main.py` (routers), migration `0013` (`app_no_lab_*` policies), `blacksite/boundary.py` | `::test_public_app_has_no_blacksite_routes`, `::test_hosted_role_cannot_create_or_approve_lab_work`, `::test_hosted_app_refusals_are_audited` |
| B5 | Lab execution needs the recorded review | `blackops/routes.py` (preflight `review` check), `blacksite/boundary.py` | `::test_lab_execution_needs_the_recorded_review` |
| B6 | The BLACKSITE database role sees and writes lab records only | migrations `0013`, `0014`, `0015`, `0022` (restrictive policies) | `::test_blacksite_role_is_confined`, `::test_blacksite_acts_on_lab_work_only` |
| B7 | Lab scopes contain lab-network addresses only | `scope/lab.py`, `NIGHTFALL_LAB_NETWORKS` | `test_lab.py::test_scope_rules_for_lab_and_normal_scopes`, `::test_lab_address_check_refuses_everything_outside` |
| B8 | The lab worker contacts lab addresses only, and refuses a lab network it isn't attached to | `recon/safe_http.py` (`only_networks`), `recon/collectors.py` (`lab_collectors`), `recon/worker.py` (`_lab_network_problem`), `infra/lab/compose.yml` (network has no route out) | `test_lab.py::test_lab_run_end_to_end_and_kept_apart`, `::test_lab_worker_refuses_a_lab_network_it_isnt_attached_to` |
| B9 | The lab worker's database role is confined to lab data (finding F1) | migrations `0010`, `0011` | `test_lab.py::test_lab_worker_role_is_confined`, `::test_lab_role_sees_and_writes_only_lab_data` |
| B10 | Moderate risk only with a lab scope; agents can't propose lab work | migration `0010`/`0020` (`nf_operation_moderate_guard`), `agents/gateway.py` | `test_lab.py::test_moderate_risk_needs_a_lab_scope`, `::test_agents_cannot_propose_lab_operations` |
| B11 | Lab approvals expire after 24 hours | `control/approvals.py`, `recon/worker.py` | `test_lab.py::test_lab_approvals_expire` |
| B12 | The console builds no HTML from strings, and is served with a strict CSP | `blacksite/static/app.js`, `blacksite/app.py` (`UI_HEADERS`) | `test_blacksite_ui.py::*` |

## 3. Things to check by hand

1. **Network isolation of the real lab machine** (the tests can't do this). On the machine, from inside the
   lab worker container:
   - `curl -m 5 https://example.com` must fail;
   - a lab app must be reachable;
   - the host's LAN must not be reachable.

   Compare with `infra/lab/compose.yml` and finding F4: is the lab range narrow, and set the same way in both
   places?

   R1 (`infra/tools/egress-lock.sh`), from inside the worker container:
   - the start-up line shows `ok lab egress: database port 5432 only to <addresses>` and `DNS loopback only`, and
     those addresses are the database host's current ones;
   - port 5432 on an address that isn't the database's (e.g. `1.1.1.1:5432`) is **refused**, not just timed out;
   - one lab run completes through the new firewall (not yet seen at the time of writing).
2. **The listener binds to loopback only** (`NIGHTFALL_BLACKSITE_BIND`). Check that nothing on another machine can
   reach port 8443.
3. **The worker's database credential** is the `nightfall_lab_worker` role (`SELECT current_user`), not the owner's.
4. **The owner account** has two-factor enabled, and the password and TOTP secret aren't shared.
5. **Findings F2–F8** in the main document: confirm their stated status (table in §0).
6. **New tables stay outside the lab roles' reach.** As the database owner:
   ```sql
   SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants
   WHERE grantee IN ('nightfall_blacksite', 'nightfall_lab_worker') ORDER BY 1, 2;
   SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public' AND p.prosecdef
     AND (has_function_privilege('nightfall_blacksite', p.oid, 'EXECUTE')
          OR has_function_privilege('nightfall_lab_worker', p.oid, 'EXECUTE'));
   ```
   At `993b31a` the first returns, for `nightfall_blacksite`: `approvals assets audit_events evidence
   finding_evidence findings operations organizations playbook_runs playbook_settings projects rate_limit_hits
   scope_exclusions scope_targets scopes sessions users warpath_exercises workflow_runs workflow_step_events
   workflow_steps workspace_members workspaces`; for `nightfall_lab_worker`: `approvals asset_relationships assets
   audit_events evidence evidence_blobs finding_evidence findings operations organizations projects
   scope_exclusions scope_targets scopes worker_heartbeats`. Each should be either needed for sign-in (users,
   sessions, workspaces, members, rate limits) or limited to lab rows by the restrictive policies (B6, B9); none
   from SHIELD. The second returns `nf_approval_guard`, `nf_finding_number` and `nf_user_workspace_count`: confirm
   each is intended for these roles.

## 4. Questions to answer in the report

- Can any path (API, database role, worker, console) start lab work without the owner, fresh two-factor, a lab
  scope and an approval younger than 24 hours?
- Can the lab worker, or anything in the lab network, reach the internet, the host's LAN or the hosted database
  other than through its confined role?
- Are the restrictive database policies complete, with no lab table the BLACKSITE or lab roles can read or write
  beyond lab records?
- Is the audit trail sufficient to reconstruct who did what in the lab?

## 5. WARPATH additions

| # | Claim | Enforced in | Test(s) |
|---|---|---|---|
| W1 | Approving an exercise freezes the plan and runs nothing | migration `0022` (`nf_warpath_exercise_guard`), `warpath/routes.py` | `test_warpath.py::test_plans_are_lab_only_honest_and_frozen_once_approved` |
| W2 | Attack steps start only through BLACKSITE, each through the lab preflight and lab approval | `nexus/engine.py` (`start_step` → `launch_run`), `blackops/routes.py` (preflight `profile` check) | `test_warpath.py::test_exercise_end_to_end` |
| W3 | BLACKSITE's role may see and advance only WARPATH runs and lab-project exercises | migration `0022` (`blacksite_workflow_*`, `blacksite_warpath_exercises`) | (review the policies; covered indirectly by `test_exercise_end_to_end`) |
| W4 | A technique tag must be one the playbook performs | `warpath/catalogue.py` (`MAPPING`) | `test_warpath.py::test_catalogue_is_pinned_and_mappings_are_real`, `::test_plans_are_lab_only_honest_and_frozen_once_approved` |

**Run these:**

```bash
cd api && .venv/bin/python -m pytest -q tests/test_blacksite.py tests/test_blacksite_ui.py tests/test_lab.py tests/test_warpath.py tests/test_tool_runner.py
```
