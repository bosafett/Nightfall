# Authorization model review: before BLACKSITE uses the lab

| | |
|---|---|
| **Required by** | Addendum 3 directive. Review §16.1: the gate before BLACKSITE phase 4 (lab). |
| **Status** | **DRAFT, not approved.** Prepared by Claude (the AI assistant that built the system). |
| **Code reviewed** | `main` at `e31642d` (2026-11-05), live at nightfall-two-lovat.vercel.app |
| **Independent sign-off** | **Pending.** See §9. |

> **Why this needs someone else.** The directive asks for an *independent* review. I wrote both the code and
> this draft, so I can't be that reviewer. This draft lays out the model, the threats and what I found, with
> evidence, so that an independent reviewer (someone who didn't build it) can check it, challenge it and sign
> it, or decline to. Any finding below can be wrong. The reviewer should verify each one rather than trust it.

## 1. What is being authorized

BLACKSITE (review §16) is an owner-only workspace for manual, operator-driven probes. This gate covers its
lab phase: **Profile 3, Isolated Lab**. In Profile 3, state-changing requests (POST, PUT, PATCH, DELETE) may be
sent, but only to practice targets on the isolated lab network. The question for the reviewer:

> Does the authorization model guarantee that a probe can only run against an authorized target, with the
> required approvals, by the right person, and that the lab can never reach a real system?

Out of scope: Profile 2 (authorized testing of real targets with active probes). It isn't built and needs its
own review.

## 2. The model as built

### 2.1 Identity

- Passwords are hashed with argon2id. Sessions are server-side, revocable, and have idle and absolute
  timeouts. Sign-in is throttled.
- **MFA (TOTP) is mandatory for owner, admin and operator** (`MFA_REQUIRED_ROLES`). Requests from those
  roles without a verified MFA session are refused with 403 and audited (`api/nightfall/core/tenancy/deps.py`).
  Tests: `test_privileged_roles_need_mfa`, `test_mfa_login_requires_valid_unused_code`.

### 2.2 Roles and permissions (`api/nightfall/core/tenancy/permissions.py`)

| Role | Read | Registry | Propose operations | Approve operations | Authorize scope | Members |
|---|---|---|---|---|---|---|
| Owner, Admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Operator | ✓ | ✓ | ✓ | ✓ | | |
| Analyst | ✓ | ✓ | ✓ | | | |
| Viewer | ✓ | | | | | |

Every route must declare a permission, and an introspection test enforces that.

### 2.3 Tenancy

Every tenant table has row-level security on `workspace_id = nf_current_workspace()`. The API's role
(`nightfall_app`) can't bypass RLS, and start-up refuses to run if any app or worker role could. An id from
another workspace returns 404. Test: `test_cross_workspace_ids_are_not_found`.

### 2.4 Scope authorization

- A scope is versioned. Admins and owners authorize a draft, which needs an authorization reference and at
  least one target. **An authorized version is immutable.** A change is a new version that needs
  re-authorization.
- Every operation pins the scope version it was requested under. At **approval** and again at **execution**,
  the scope must still be the active version, the target must still be in scope and not excluded, and the
  time window must be valid. Otherwise the operation is denied.
  Tests: `test_scope_change_before_approval_denies`, `test_scope_change_after_request_denies_the_job`.

### 2.5 Operation approval (two-person rule)

| Risk class | Rule |
|---|---|
| Passive | Runs if in scope. |
| Low | Needs an approval by someone other than the requester. |
| Moderate | **Lab scopes only** (DB CHECK, migration 0010), and needs an approval. |
| High | Never. DB CHECK `risk_class <> 'high'`. |

- The requester can't approve their own operation. This is enforced in the route and in the database.
  Tests: `test_requester_cannot_approve_their_own`, `test_database_also_blocks_self_approval`.
- The worker re-checks before running that a valid approval exists **for the pinned scope version**.
  Test: `test_worker_refuses_low_risk_without_approval`.
- **Every lab operation needs an approval, including passive ones.**

### 2.6 The lab (Phase 6b, migration 0010)

- **Lab scope contents:** a lab scope may name only IP addresses or ranges inside `NIGHTFALL_LAB_NETWORKS`,
  and no hostnames. Normal scopes can't name lab addresses. This is checked when a target is added, when a
  draft is switched to lab, at authorization, and at run time, where the lab worker's `SafeHttp.only_networks`
  refuses any address outside the lab networks.
- **Disjoint queues:** the restrictive RLS policies limit `nightfall_worker` to `NOT is_lab` operations and
  `nightfall_lab_worker` to `is_lab` operations. The claim queries filter the same way.
- **Network isolation:**
  - The lab machine runs Docker. `lab-net` is an `internal` network, so it has no route out.
  - The practice apps have no published ports.
  - In lab mode, the worker's own process may reach only the lab network, DNS and the database port.
  - Tools may reach only the per-run proxy.
  - CI proves each of these on every push (job `lab`).
- **Agents can't propose lab operations.** Lab evidence is stored as `is_simulation`.
- Tests: `test_scope_rules_for_lab_and_normal_scopes`, `test_lab_run_end_to_end_and_kept_apart`,
  `test_lab_worker_role_is_confined`, `test_lab_address_check_refuses_everything_outside`,
  `test_moderate_risk_needs_a_lab_scope`, `test_agents_cannot_propose_lab_operations`.

### 2.7 AI agents

Agents only propose. Their proposals go through the deterministic Tool Gateway (allowlist, scope, risk class).
Operations they propose carry the human requester's identity, so that person can't approve them. Their
output is a hypothesis until a person decides. No agent's allowlist contains a BLACKSITE probe (§16.7).

### 2.8 Audit

`audit_events` is insert-only for the app and worker roles. Denials are written on a separate connection, so
a failed request still leaves a record.

## 3. What BLACKSITE adds (designed in §16.2–16.5, not built)

1. **Access checks:**
   - feature flag off by default (routes not mounted);
   - a **loopback-only listener**, reached by SSH tunnel;
   - **owner role**;
   - **step-up MFA within the last 15 minutes**.
2. **Targets by asset id only:** no free-form URL, host or IP can be expressed.
3. **Validation and limits:** profile, method, port and protocol are validated against the target's allowed
   lists. Rate, concurrency and daily budget are counted in Postgres.
4. **DNS pinning:** DNS is resolved once in the worker, every IP is re-checked, and the connection goes to
   the pinned IP.
5. **Profile 3:** state-changing methods need an operator confirmation **plus** an approved operation.

## 4. Threat model

| Actor | Wants to | Main controls |
|---|---|---|
| Outside attacker | Use NIGHTFALL to attack someone | MFA, scope, approval, risk classes, no free-form targets |
| Malicious or compromised member account | Run probes alone, or against an unauthorized target | Two-person rule, scope immutability, MFA, audit |
| Compromised lab machine (malware, stolen `lab.env`) | Reach real systems, or reach NIGHTFALL's data | Internal network, worker firewall, lab DB role (**see F1**) |
| Prompt-injected agent | Get a probe run | Agents only propose; gateway; agents can't propose lab runs |
| The owner | Bypass their own controls | Out of scope for technical controls; see F2 and F6 |

## 5. Findings

Severity is the impact if the weakness is used, taking existing controls into account.

### F1 (High): the lab worker's database account isn't confined to lab data. **Verified.**

**What:** `nightfall_lab_worker` sets its own workspace context, like the normal worker. The tenant policies on
`assets`, `asset_relationships`, `findings`, `finding_evidence`, `evidence`, `organizations`, `projects` and
`scopes` only compare `workspace_id` with that context. So anyone holding the lab credential can read, and
partly write, **any workspace's** assets, findings and scopes. The only restrictive policy is on `operations`.

**Evidence:** on 2026-11-05, against the test database, I signed in as `nightfall_lab_worker`, set the context
to an unrelated workspace, and inserted an asset into a non-lab organization. The insert succeeded. The row was
then deleted.

**Why it matters more for the lab:** the lab password is stored in `lab.env` on a home PC that also runs
deliberately vulnerable software. The normal worker's credential only exists inside Vercel.

**Current exposure:** none in production yet. The lab role has no login until `NIGHTFALL_LAB_WORKER_DB_PASSWORD`
is set (live logs show "lab worker role: no login (not configured)").

**Recommendation (required before the lab password is set):** add restrictive policies for
`nightfall_lab_worker` on every table it can touch, limiting it to rows tied to lab work:
- evidence: `operation_id` refers to an `is_lab` operation;
- findings: `project_id` has a lab operation;
- assets and relationships: the asset's organization has a lab project;
- scopes and projects: lab ones only.

Also add a test that the lab role can neither read nor write anything outside lab work.

### F2 (Medium): the two-person rule counts accounts, not people

**What:** "someone other than the requester" means another *account*. One person with two accounts, each with
its own email and authenticator, satisfies it. The live walkthrough does exactly this. For an owner-only
BLACKSITE in a one-person workspace, the second "person" will usually be the same human.

**Recommendation (owner decision):**
- **(a) Accept it for lab-only work.** Lab targets are practice apps the owner controls, and the separation is
  structural. Record the decision here.
- **(b) For Profile 2 later, require a second, real person.** Make this a documented condition of any Profile 2
  review. Software alone can't prove two accounts are two people.

### F3 (Medium): authorizing a scope proves intent, not ownership

**What:** scope authorization records a free-text reference (e.g. "I own this domain"). NIGHTFALL never checks
that the authorizer controls the target. For the lab this doesn't matter: lab scopes are limited to the lab
network by construction.

**Recommendation:** before Profile 2 or any active real-world probing, add ownership verification (a DNS TXT
record or a file under `/.well-known/`) to scope authorization. **Not needed for the lab.**

### F4 (Medium): the lab network range is configured in two places, and "private" is too broad

**What:**
- `NIGHTFALL_LAB_NETWORKS` (API side) decides which addresses lab scopes may name. The lab worker's own setting
  and its firewall come from `infra/lab/compose.yml`.
- Both accept any private range. If either were widened to include a home network such as `192.168.1.0/24`,
  the lab worker could reach the owner's home devices: its uplink network has a route to the LAN, and the
  firewall's lab-network allowance would then cover it.

**Recommendation:**
- At start-up, the lab worker should check that its configured lab networks are exactly the subnet of the
  `lab-net` interface it's attached to, and refuse to run otherwise.
- Document that the two settings must match.

### F5 (Low): approvals don't expire

**What:** an approved operation stays approved until it runs, as long as the scope version and window still
hold. A lab job approved on Monday may run on Friday, when the lab machine next starts.

**Recommendation:** for lab and BLACKSITE operations, expire approvals after a set time (proposed: 24 hours).
After that the job is denied with a reason and must be requested again.

### F6 (Low, accepted): the owner can do everything

**What:** the owner can create members, authorize scopes and approve other members' requests. Technical
controls can't stop a determined owner. The protections are the audit trail, the immutable scope versions and
MFA.

**Recommendation:** accept, and record that here.

### F7 (Low): the audit trail can be changed with the database owner's credential

**What:** `audit_events` is insert-only for the app and worker roles. But the Neon owner credential, which is in
the Vercel environment for migrations, can modify or delete rows.

**Recommendation:** later, export audit events continuously to a separate append-only store (for example a
log drain to storage with object lock). Not blocking for the lab.

### F8 (Info): parts of BLACKSITE's design are untested because they're unbuilt

The loopback listener, the step-up MFA window, asset-id-only targeting, per-target budgets, DNS pinning for
the probe deck, and the operator confirmation for state-changing methods don't exist yet. **Where BLACKSITE
runs needs a decision.** The loopback-only requirement means it can't be on Vercel. The natural host is the lab
machine, serving on `127.0.0.1` only, with its own restricted database role (the same problem as F1). Each of
the §16.10 tests must pass before the lab phase opens.

## 6. Controls verified as working

All of these have automated tests that pass on `main` (`e31642d`). See §2 for the test names.

- MFA required for privileged roles; cross-workspace isolation.
- Scope immutability, plus re-checks at approval and at execution.
- No self-approval (route and database); the worker re-checks the approval.
- No high-risk operations; moderate only in a lab.
- Lab and normal queues are disjoint for **operations** (route, claim query, RLS).
- Lab scopes can only name lab addresses, and the lab worker can only contact them.
- Lab network: no route out, nothing published, worker process firewalled (CI job `lab`).
- Agents can't propose lab runs.

## 7. Conditions before BLACKSITE's lab phase opens

1. **F1 fixed**, with tests, before `NIGHTFALL_LAB_WORKER_DB_PASSWORD` is set.
2. **F4:** the lab worker refuses a lab network that doesn't match its interface.
3. **F5:** approval expiry for lab and BLACKSITE operations.
4. **F2 decision recorded** in §8.
5. BLACKSITE built per §16.2–16.5, including its own confined database role, and every §16.10 test passing.
6. **Independent sign-off** of this document (§9).

## 8. Decisions for the owner

| # | Decision | Recorded answer |
|---|---|---|
| D1 | F2: accept account-based two-person rule for lab-only work? | _pending_ |
| D2 | F5: approval expiry for lab/BLACKSITE operations (proposed 24 h)? | _pending_ |
| D3 | F8: host BLACKSITE on the lab machine, loopback only? | _pending_ |
| D4 | Who performs the independent review? | _pending_ |

## 9. Independent sign-off

The reviewer confirms they did not build NIGHTFALL, read the code at the commit named above, checked each
finding, and agrees that §7's conditions are sufficient, or lists what else is required.

| | |
|---|---|
| Reviewer name | |
| Relationship to the project | |
| Date | |
| Commit reviewed | |
| Decision | ☐ Approved  ☐ Approved with conditions  ☐ Not approved |
| Additional conditions / disagreements | |
