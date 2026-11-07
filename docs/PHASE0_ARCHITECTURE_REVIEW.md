# NIGHTFALL — Phase 0 Architecture Review

> **Renamed:** the product is now **JANUS (JNS.OS)**. This document keeps its original name and history; current
> owner decisions and the roadmap are in §17, which supersedes earlier sections where they disagree.

Status: **Approved 2026-11-04 — all decisions in §11 accepted as proposed.** Nothing has been installed, deployed, or tested against any external system.
Revision 3: adds **Addendum 3 — BLACKSITE** (§16).
Revision 2: incorporates **Addendum A** (local-first AI, open-source integrations, BLACK ICE, offline operation) and the **command-center mockup** (§13–§15).
Date: 2026-11-04 · Spec: NIGHTFALL Engineering Handoff v1.0

---

## 1. Existing repository overview

- **NIGHTFALL repository:** `bosafett/nightfall`, empty at review time. This is a greenfield build. No inherited code, dependencies, auth, or tech debt.
- **Kept separate from `zuse-holding/Charon`** (Selene OS + live consumer product) by decision. No code, database, secrets, or deploy targets are shared.
- **Patterns worth carrying over from Charon (ideas, not code):**
  - Agents can only *propose*; consequences happen in an executor gated by human approval (`propose_action` → `approval_queue`). NIGHTFALL's operation/approval model is the same idea.
  - Tool allowlists per job, enforced structurally *and* at the runtime layer.
  - Idempotent jobs via unique keys.
  - Untrusted-input language in system prompts.
- **Development environment (verified):** Node 22.23, npm 10.9, Python 3.13, Docker 29.9, PostgreSQL 16 client, Redis 7.0. Everything Phase 1 needs is available locally.
- **Existing hosting the owner already uses:** Vercel, Railway, Supabase. **Rev 2:** Addendum A (local-first, offline-capable, Ollama) makes a self-hosted deployment the primary target, so none of these are hard dependencies (§9).

## 2. Recommended project structure

One repository, modular monolith. Two deployables (web, api) plus a worker that shares the api's Python package.

```
nightfall/
├── web/                        # Next.js (App Router) + TypeScript + Tailwind
│   ├── app/                    # routes: command-center, targets, recon, findings, graph, war-room, reports, settings
│   ├── components/ui/          # reusable library: Sidebar, KpiCard, SeverityBadge, StatusDot, DataTable, Modal, ConfirmDialog, EmptyState, Skeleton…
│   ├── lib/api/                # typed client generated from the API's OpenAPI schema
│   └── tests/                  # vitest (unit) + playwright (UI)
├── api/                        # Python 3.13, FastAPI
│   ├── nightfall/
│   │   ├── core/               # shared foundation (reused by GHOSTWIRE/SPECTRE/WARPATH)
│   │   │   ├── identity/       # session verification, current user
│   │   │   ├── tenancy/        # workspaces, memberships, RBAC
│   │   │   ├── audit/          # append-only audit writer
│   │   │   ├── evidence/       # content-addressed evidence store
│   │   │   └── db/             # SQLAlchemy models, session, Alembic migrations
│   │   ├── registry/           # organizations, projects, assets, scopes   (Phase 1/3)
│   │   ├── recon/              # passive collectors                         (Phase 3)
│   │   ├── findings/           # findings + evidence links                  (Phase 4)
│   │   ├── blackice/           # BLACK ICE: normalization, relationships, correlation,
│   │   │                       #   confidence rules, snapshots, replay      (Phase 3/4, §14)
│   │   ├── tools/              # isolated adapters: amass, nuclei, zap      (Phase 3+, §13)
│   │   ├── operations/         # risk classification, approvals, gateway    (Phase 3/6)
│   │   ├── agents/             # provider interface + OllamaProvider, agents, orchestrator (Phase 5)
│   │   ├── reports/            # report assembly                            (Phase 4)
│   │   ├── main.py             # API entrypoint
│   │   └── worker.py           # worker entrypoint (same package)
│   └── tests/                  # pytest: unit, integration (real Postgres), security
├── infra/
│   ├── compose.yml             # dev: postgres (ollama/zap added in their phases)
│   └── compose.prod.yml        # self-hosted deployment (§9)
├── docs/
│   ├── adr/                    # one short ADR per approved decision below
│   └── PHASE0_ARCHITECTURE_REVIEW.md
└── .github/workflows/ci.yml    # lint, typecheck, tests, dependency audit, secret scan
```

Future products become new top-level modules beside `registry/`, `recon/`, and the rest. They sit on top of `core/`, with no new infrastructure. Nothing for them is built now.

## 3. Frontend / backend architecture

**Recommendation: keep the spec's split (Next.js + FastAPI), with all authority in FastAPI.**

- **FastAPI is the only component that touches the database** and the only place where authorization, scope enforcement, and risk classification run. One enforcement boundary, testable with pytest.
- **Next.js is presentation only.** Server components call the API server-side. The browser talks to the API through same-origin rewrites (`/api/*` → FastAPI), so session cookies stay first-party and there is no CORS surface. No database client and no service keys in the web bundle.
- **Typed contract:** Pydantic models → OpenAPI → generated TypeScript types (`openapi-typescript`). One source of truth for shapes.
- **Background work: Postgres-backed queue in MVP, not Redis.** The worker claims rows with `SELECT … FOR UPDATE SKIP LOCKED` from `operations` (approved, executable) and `agent_tasks` (pending). This adds no new infrastructure and gives transactional consistency with approvals: an operation can't run unless its approval committed. Redis is added only if measured throughput needs it. *(Needs approval: this deviates from the spec's "Redis + worker".)*
- **Why not all-TypeScript:** it would be one fewer runtime, but the passive-recon and DNS ecosystem (`dnspython`, CT parsing) and the agent tooling are stronger in Python. The owner already runs Python agents, and the spec proposes Python. The split costs one extra deployable, which is acceptable.

## 4. Proposed database schema

Postgres 16. UUID v4 PKs (`gen_random_uuid()`). `created_at`/`updated_at timestamptz` on mutable tables. FKs everywhere with explicit `ON DELETE` behaviour (mostly `RESTRICT`; evidence and audit are never cascaded away). Alembic migrations.

### 4.1 A naming conflict to resolve first

The spec uses **organizations** for *investigated* organizations (targets). Tenant isolation needs a separate concept for *the customer using NIGHTFALL*. Proposal: **`workspaces`** = tenant, and `organizations` keeps the spec's meaning. Every tenant-owned row carries `workspace_id`.

### 4.2 Tables

Legend: **[spec]** listed in spec · **[+]** addition, with reason · **[P#]** phase that creates it. Migrations create tables only when their phase needs them, so there are no empty tables in Phase 1.

**Identity and tenancy**

| Table | Key columns | Notes |
|---|---|---|
| `users` [spec][P1] | id, email unique, display_name, password_hash (argon2id), totp_secret_enc, mfa_enabled, is_disabled | Rev 2: API owns auth (§5). TOTP secret encrypted with an app key held outside the DB. |
| `sessions` [+][P1] | user_id, token_sha256 unique, created_at, last_seen_at, expires_at, revoked_at, ip, user_agent | Needed for server-side, revocable sessions. Only the token's hash is stored. |
| `workspaces` [+][P1] | id, name, slug unique | Tenant boundary. Needed for isolation. |
| `workspace_members` [+][P1] | workspace_id, user_id, role, unique(workspace_id,user_id) | User ↔ tenant with role. |
| `roles` [spec] | — | **Proposed as a Postgres enum** (`owner, admin, operator, analyst, viewer`), not a table. Permissions live in code where they're unit-tested. A table adds joins with no current requirement. *(Needs approval.)* |

**Target registry**

| Table | Key columns | Notes |
|---|---|---|
| `organizations` [spec][P1] | workspace_id, name, notes | Investigated organizations. |
| `projects` [spec][P1] | workspace_id, organization_id, name, assessment_type, status, started_at, last_activity_at | In 0.1, **project = assessment**. A separate `assessments` table is only needed if one project runs repeated assessments. *(Needs approval.)* |
| `assets` [spec][P3] | workspace_id, organization_id, kind (`domain, subdomain, ip, cidr, url, api, application, cloud_resource`), value_normalized, ownership, source, first_seen, last_seen, unique(workspace_id, kind, value_normalized) | The unique key makes recon idempotent. |
| `scopes` [spec][P3] | workspace_id, project_id, version int, status (`draft, active, superseded`), authorized_by_user_id, authorized_at, authorization_reference, valid_from, valid_until, is_lab bool | **Immutable once active.** A change creates a new version that needs renewed authorization, which also gives scope history. One active version per project (partial unique index). |
| `scope_targets` [+][P3] | scope_id, kind (`domain, wildcard_domain, ip, cidr, url_prefix`), value, allowed_max_risk, allowed_ports int[], allowed_protocols text[], max_rps, daily_probe_budget | Structured inclusions so enforcement is code, not text parsing. Ports, protocols, and budgets added for BLACKSITE (§16). |
| `scope_exclusions` [spec][P3] | scope_id, kind, value, reason | Exclusions always win over inclusions. |
| `asset_relationships` [+][P3] | workspace_id, from_asset_id, to_asset_id, rel_type (`resolves_to, subdomain_of, cname_to, hosts, exposes_api, uses_technology`), status (`observed, hypothesis`), confidence, evidence_id | Needed for the Intelligence Graph. The spec's `attack_paths` only covers finding↔asset paths. |

**Evidence and findings**

| Table | Key columns | Notes |
|---|---|---|
| `evidence` [spec][P3] | workspace_id, project_id, asset_id, kind (`observation, tool_output, document, screenshot, agent_note`), source, collection_method, collected_at, confidence, tool_name, tool_version, input_params jsonb, content_sha256, storage_key, size_bytes, is_simulation bool | Covers the spec's "observation" fields exactly. Blob on a local content-addressed volume (S3-compatible optional), hash in DB, so it's tamper-evident and reproducible. `is_simulation` separates lab results from real-world results (Phase 6 criterion). |
| `findings` [spec][P4] | workspace_id, project_id, asset_id, short_id (e.g. NF-0042), title, description, severity (`critical, high, medium, low, info`), confidence (`low, medium, high`), validation_status (`hypothesis, unverified, validated, false_positive, remediated`), origin (`agent, human, deterministic_check`), discovery_source, impact, remediation, first_observed_at, last_observed_at, validated_by_user_id, validated_at | **CHECK: `validated`/`false_positive`/`remediated` require `validated_by_user_id`.** LLM output can never self-promote to verified. |
| `finding_evidence` [+][P4] | finding_id, evidence_id, relevance note | Many-to-many. Required for "traceable to supporting evidence". |
| `attack_paths` [spec][P4] | workspace_id, project_id, title, status (`hypothesis, validated, rejected`), confidence, proposed_by (agent_id / user_id), reviewed_by_guardian bool | Never "compromised". The UI renders hypotheses dashed. |
| `attack_path_steps` [+][P4] | attack_path_id, ordinal, asset_id?, finding_id?, description, evidence_id? | Ordered steps. Can't be modelled as one row. |

**Operations, approval, agents**

| Table | Key columns | Notes |
|---|---|---|
| `operations` [spec][P3] | workspace_id, project_id, scope_id (version pinned), target_asset_id / target_value, purpose, tool_name, params jsonb, risk_class (`passive, low, moderate, high`), status (`proposed, approved, rejected, running, succeeded, failed, cancelled`), proposed_by_agent_id?, proposed_by_user_id?, idempotency_key unique, result_summary, started_at, finished_at, attempts | **CHECK `risk_class <> 'high'`** (excluded from MVP at DB level). Moderate is only allowed when the pinned scope `is_lab`. Also serves as the job queue. |
| `approvals` [spec][P3] | operation_id unique, approver_user_id NOT NULL, decision (`approved, rejected`), reason, scope_id_at_decision, decided_at | Only humans approve: there is no agent column. Approver ≠ proposing user (CHECK via trigger). Scope change after approval invalidates it (enforced in the gateway: `scope_id_at_decision` must equal the active scope). |
| `agents` [spec][P5] | workspace_id?, key (`director, scout, investigator, hunter, adversary, guardian, analyst`), model, prompt_version, allowed_tools text[], enabled | 7 fixed rows, seeded. |
| `agent_tasks` [spec][P5] | workspace_id, project_id, agent_id, parent_task_id, objective, context jsonb, permitted_tools text[], output_schema, status, result jsonb, error, model, input_tokens, output_tokens, cost_usd, started_at, finished_at, attempts | The spec's task and result objects. Token and cost tracking lives here, with no extra table. |
| `probe_profiles` [+][BLACKSITE P2] | workspace_id, owner_user_id, name, probe_type, params jsonb (validated per probe type), execution_profile | "Save request as a reusable diagnostic profile" (§16). Holds **no target**: the target is chosen and scope-checked at run time. |
| `assessment_snapshots` [+][P4] | workspace_id, project_id, taken_at, ruleset_version, manifest jsonb, manifest_sha256 | Addendum A4 (snapshots and replay). §14. |
| `simulations` [spec][P6] | — | Deferred to Phase 6. Not designed now to avoid speculative schema. |
| `audit_events` [spec][P1] | workspace_id, actor_type (`user, agent, system`), actor_id, action, entity_type, entity_id, data jsonb, ip, user_agent, occurred_at | **Append-only**: app DB role has INSERT/SELECT only. UPDATE/DELETE revoked. |

### 4.3 Isolation, indexing, retention

- **Tenant isolation, two layers:** (1) every API query goes through a repository helper that requires `workspace_id` from the verified membership, and (2) Postgres **RLS** keyed on `current_setting('app.workspace_id')`, set per transaction. A forgotten filter fails closed. Cross-workspace access tests are in the Phase 1 suite.
- **Indexes:** `(workspace_id, …)` leading on every tenant table; findings `(workspace_id, severity, validation_status)`, `(workspace_id, last_observed_at desc)`; operations `(status, created_at)` partial where `status='approved'` for the queue; evidence `(asset_id, collected_at desc)`.
- **Retention (proposal):** audit events and approvals kept for 7 years (legal and accountability record). Evidence blobs are kept for the project's lifetime plus 1 year, then purged with a tombstone row. Agent task context/result payloads after 180 days. Configurable per workspace later. *(Needs approval.)*
- **No secrets in ordinary columns.** Third-party API keys for collectors live in the server's secret store, never in DB rows or agent context.

## 5. Authentication and authorization

**Rev 2: the API owns authentication.** Addendum A requires offline operation, which rules out a cloud identity provider (the earlier Supabase Auth proposal) as a hard dependency.

- **Passwords:** argon2id (`argon2-cffi`).
- **Sessions:** 256-bit random opaque token in an `HttpOnly; Secure; SameSite=Lax` cookie. Only its SHA-256 is stored (`sessions`). Idle timeout 12h, absolute 7d. Revocable, including "sign out everywhere". CSRF: SameSite plus an `Origin` check on every mutating request.
- **MFA:** TOTP (`pyotp`) required for owner/admin/operator, the roles that can approve operations or change scope. Recovery codes are stored hashed.
- **Login throttling:** per-account and per-IP backoff. Lockouts are audited.
- **Password reset works offline:** an owner/admin issues a single-use, 30-minute reset link (hashed token), or the host operator runs `nightfall-admin reset-password`. Email is an optional SMTP adapter, off by default.
- **Bootstrap:** `nightfall-admin create-owner` creates the first owner. Invite-only, with no open sign-up.
- **No secrets in the web bundle:** the browser holds only the session cookie.
- **RBAC matrix (code, unit-tested):**

| Action | owner | admin | operator | analyst | viewer |
|---|---|---|---|---|---|
| Manage members/settings | ✓ | ✓ | | | |
| Create/edit orgs, projects, assets | ✓ | ✓ | ✓ | ✓ | |
| Authorize scope version | ✓ | ✓ | | | |
| Approve/reject operations | ✓ | ✓ | ✓ | | |
| Propose operations, edit findings | ✓ | ✓ | ✓ | ✓ | |
| Validate finding (→ validated/false_positive) | ✓ | ✓ | ✓ | ✓ | |
| Read | ✓ | ✓ | ✓ | ✓ | ✓ |

- **Rate limiting:** per-user and per-IP on auth and mutating endpoints. In-process for the single-host deployment.

## 6. AI integration architecture (rev 2: local-first)

- **AI is optional.** `AI_PROVIDER=ollama|none`. With `none`, agents are disabled and everything else works: registry, recon, BLACK ICE correlation, findings, graph, reports, approvals. The UI shows "AI off", not empty agent panels. If AI goes away, existing assessments stay valid, because LLM output is never the system of record (A6).
- **Provider interface** (`agents/providers/base.py`):
  - `generate(request) -> GenerationResult`
  - Request: messages, JSON schema, optional tools, model, timeout.
  - Result: parsed output, raw text, tokens in/out, latency, model name and digest.
  - Agents depend only on this interface. The provider is chosen by config, so it can change without touching agent code (A6).
- **`OllamaProvider` (first and only provider in 0.1):** plain HTTP via `httpx` to Ollama's chat endpoint, with a JSON-schema `format` for structured output, `tools` where the model supports them, no streaming, and a configurable timeout. Exact request fields are verified against the installed Ollama version at Phase 5. Cloud providers can be added later as optional adapters and are never required. **No LLM API keys anywhere.**
- **Native tool calls are still only requests.** Whether a model emits a native tool call or a tool request inside its JSON result, both go through the same Tool Gateway. Models without tool calling use the JSON path.
- **Degraded operation:**
  - A timeout marks the task `failed` (retryable, attempts counted).
  - If Ollama is unreachable, the orchestrator pauses AI tasks and system status shows "AI unavailable". Deterministic pipelines continue.
- **Usage tracking:** tokens, latency, and model name and digest per task in `agent_tasks`. `cost_usd` stays null for local inference.
- **Choosing the default model:** a benchmark harness runs before anything is selected (A6). It uses fixed fixture tasks per agent and measures:
  - schema-valid output rate
  - p50/p95 latency **on the actual host hardware**
  - accuracy of evidence citations
  - resistance to the injection fixtures

  Results are committed to `docs/benchmarks/`. The default is picked from those results, not up front.
- **Local models are weaker at following instructions and resisting injection than frontier models.** The design doesn't rely on model obedience: allowlist, scope check, risk class, human approval, and the "validated requires a human" constraint are all deterministic code.
- **Ollama has no authentication.** It is bound to the internal container network only and never exposed on a published port.
- **Agents never execute anything.** Tool requests go through the **Tool Gateway** (deterministic code), which checks:
  1. the tool is in that agent's allowlist
  2. the target normalizes and is inside the active scope and not excluded
  3. the tool's fixed risk class
  - **passive** + in scope → enqueued
  - **low** → proposed operation, awaiting human approval
  - **moderate** → rejected unless the scope is a lab, then approval required
  - **high** → rejected
  - Every decision is audited.
- **Director** only creates `agent_tasks`. It has no tools.
- **Guardian** receives the claim plus the raw evidence, not the proposing agent's reasoning. It uses a different prompt and, where the host can serve it, a different model family. Disagreement is stored, not averaged.
- **LLM output** always enters as `hypothesis`/`unverified` (§4.2 CHECK).
- **Prompt injection:** collected content (web pages, DNS TXT records, tool output) is passed only inside delimited, size-capped data blocks and never in system prompts. Adversarial fixtures are in the test suite.

## 7. Security controls (summary)

| Area | Control |
|---|---|
| Identity | API-owned auth: argon2id, hashed revocable server-side sessions, TOTP MFA for privileged roles, login throttling (§5) |
| AuthZ | RBAC in API + workspace RLS in Postgres. Every endpoint has an explicit permission decorator, and an endpoint test asserts none are missing. |
| Scope | Server-side normalization (lowercase, IDNA, trailing dot, CIDR math). Exclusions win. Active collectors also check **resolved IPs**, so in-scope names that CNAME to third-party infrastructure (CDNs, SaaS) aren't touched as if in scope. |
| Egress / SSRF | Worker HTTP client blocks private, link-local, and metadata ranges unless the scope `is_lab`. Timeouts and response size caps. |
| Approval | Humans only. Approver ≠ proposer. Approval pinned to scope version. High risk blocked at the DB. |
| Audit | Append-only table (grants), every mutation and gateway decision logged |
| Secrets | Env/secret manager only. Never in DB, logs, agent context, or web bundle. Gitleaks in CI. |
| Input | Pydantic validation on every request. Parameterized SQL (SQLAlchemy). Output encoding in React. |
| Supply chain | Lockfiles, Dependabot, `pip-audit` + `npm audit` in CI |
| Untrusted content | Treated as data in prompts. HTML never rendered raw in UI (escaped, or sandboxed iframe for screenshots). |
| Tool adapters | Fixed argv built from validated params, never a shell, never model-supplied flags. Pinned versions. Resource and time limits. No DB or LLM credentials. Outputs parsed as untrusted (§13). |
| Network scope | Non-passive tools egress only through a scope-enforcing proxy (§13) |
| Local AI runtime | Ollama on the internal network only. Postgres and Ollama have no internet route. |

## 8. Development dependencies (proposed — none installed)

Each one has a reason. Everything else is deferred until a phase needs it.

**web/**:
- `next`, `react`, `typescript`, `tailwindcss` (spec)
- `openapi-typescript` (typed API contract)
- `@xyflow/react` (React Flow; **Phase 2**)
- dev: `eslint`, `vitest`, `@testing-library/react`, `@playwright/test` (browser already on this machine)

Fonts are self-hosted at build time (`next/font`), with no runtime CDN, so it works offline.

**api/**:
- `fastapi`, `uvicorn`
- `pydantic` v2
- `sqlalchemy` 2 + `alembic` + `psycopg[binary]` 3
- `argon2-cffi` (password hashing)
- `pyotp` (TOTP)
- `cryptography` (encrypting TOTP secrets at rest)
- `httpx` (Ollama client and collectors; no Ollama SDK needed)
- `dnspython` (**Phase 3**)
- dev: `pytest`, `pytest-asyncio`, `ruff`, `mypy`, `pip-audit`

Integration tests run against real Postgres via compose.

**Runtimes and binaries (pinned, in their phase):**
- Ollama (Phase 5)
- Amass (Phase 3)
- Nuclei + a pinned nuclei-templates release (Phase 3–4)
- ZAP container (Phase 4)

**Removed in rev 2:** `@supabase/supabase-js`, `pyjwt` (no external identity provider).

**Not proposed:** Redis (see §3), Celery, Turborepo/Nx, Ollama Python SDK, any cloud LLM SDK.

## 9. Deployment recommendations (rev 2: self-hosted first)

**Primary target:** one host running Docker Compose (`infra/compose.prod.yml`).

| Service | Network | Notes |
|---|---|---|
| caddy | public + frontend | Only published port (443). Automatic TLS, or an internal CA when offline. |
| web | frontend | Next.js standalone build |
| api | frontend + backend | Holds DB credentials. No LLM or collector keys. |
| worker | backend + egress | Same image as api, separate DB role (claims ops/tasks, writes evidence/audit, no access to users/sessions) |
| postgres | backend | Volume. Nightly `pg_dump`. Restore tested. No internet route. |
| ollama | backend | Phase 5. GPU passthrough if available. No published port, no internet route after models are pulled. |
| zap | egress (via scope proxy) | Phase 4. Internal API with API key. |
| evidence volume | — | Content-addressed blobs. Back up together with Postgres. |

- **Routing (found in Phase 1):** Caddy must send `/api/*` straight to the API and overwrite `X-Forwarded-For`, with `NIGHTFALL_FORWARDED_HOPS=1`. The Next.js rewrite proxy passes a client-supplied `X-Forwarded-For` through unchanged, so it must never be the hop the API trusts for client IPs.
- **Cloud hosting is no longer the default.** Vercel can't run Ollama, and Railway has no GPUs. A cloud deployment can come later, but 0.1 doesn't target it.
- **Environments:**
  - dev: the same compose file, plus a dev overlay
  - production: compose on the host
  - Migrations run as a one-shot `migrate` service on each deploy.
- **Host sizing depends on the hardware** (decision 9). CPU-only inference works but will be slow for 7 agents. The benchmark (§6) will quantify this.
- **Offline (A5):** after the initial image and model pulls, everything runs without internet except collectors that need external data. Those report "unavailable/stale" (§14) instead of failing silently.
- **Lab environment:** Phase 6, on an isolated network that never shares credentials with production.

## 10. Phase 1 implementation plan

Goal (spec acceptance): authenticate, create an organization and a project, data persists, navigation works, access control enforced, desktop and mobile. No AI and no tools in Phase 1.

| # | Step | Verified by |
|---|---|---|
| 1 | Repo skeleton, `infra/compose.yml` (Postgres), CI (lint, typecheck, test, `pip-audit`/`npm audit`, gitleaks) | CI green on empty skeleton |
| 2 | API: config, DB session, Alembic baseline. Migrations for `users, sessions, workspaces, workspace_members, organizations, projects, audit_events` + RLS + role grants | Migration up/down test. RLS test: no `app.workspace_id` → 0 rows. Audit table rejects UPDATE/DELETE. |
| 3 | API auth: argon2id, sessions, TOTP, throttling, CSRF origin check, `create-owner`/`reset-password` CLI, permission decorator, audit writer | Unit tests: wrong password, expired/revoked session, missing MFA for privileged role, throttling. Introspection test that every route declares a permission. |
| 4 | API: CRUD for organizations and projects, settings (workspace name, members and invites, roles) | Integration tests incl. **cross-workspace access → 404**, viewer can't mutate, one audit row per mutation |
| 5 | Web: design tokens (§15), app shell, sidebar (8 items; the BLACKSITE slot stays hidden until its own phases, §16; logo, system-status card with real `/health` checks, version), header (tagline, approvals bell, user menu). Sections not built yet show "Arrives in phase N", with no fake data. | Playwright: navigation; mobile drawer at 390px; colour-contrast check on tokens |
| 6 | Web: sign-in, MFA enrolment and challenge, sign-out, accept-invite, reset via link | Playwright: unauthenticated redirect, sign-in incl. TOTP |
| 7 | Web: organizations and projects pages (list, create, edit), empty/loading/error states | Playwright: create org → create project → reload → persists |
| 8 | Security pass on the diff (authz bypass, tenant leak, session handling, secret exposure) + Phase 1 report per spec §13 | Report with actual test output |

Stops after step 8 for approval (spec §12.5).

## 10a. Phase 3 delivery note (added during Phase 3)

Phase 3 shipped in two parts so the scope engine could be reviewed on its own:
- **3a (done):** assets, versioned scopes and exclusions with authorization, scope engine, operations queue and
  worker, passive collectors (certificate transparency, DNS), content-addressed evidence, discovery history.
- **3b (done):** approval workflow for operations above passive (operator/admin/owner, never the requester,
  enforced in the API and by a database trigger, tied to the scope version, final once decided); technology
  identification as a LOW-risk collector through a scope-enforcing HTTP client (resolve once, refuse private,
  metadata, CGNAT and scope-excluded addresses, connect to the checked IP with the hostname as SNI/Host, GET only,
  no redirects followed, capped body, honest User-Agent); deterministic, versioned fingerprint rules.
- **Moved out of Phase 3, with reasons:**
  - *Amass.* v5 (5.1.3, verified) runs `enum` against a separate long-lived Amass engine service with its own
    asset database ("The Amass engine did not respond" without one). That is a new deployable, not an adapter;
    it belongs with the tools container in Phase 4. Certificate transparency + DNS already cover passive
    subdomain discovery.
  - *Egress proxy for third-party binaries.* Only needed once an external tool (Nuclei, ZAP) contacts targets.
    In-process probes already go through the scope-enforcing client. Built with the tools container in Phase 4,
    before Nuclei or ZAP can run.

## 10b. Phase 4 delivery note (added during Phase 4)

- **4a (done):** findings (per-workspace refs NF-0001…), evidence links with provenance (rule or person),
  BLACK ICE finding rules R1–R5 (version disclosure, untrusted certificate, no HTTPS, certificate expired /
  expiring), human status decisions with required notes (DB-enforced attribution), attack paths that can only be
  validated when every finding in them is validated, project attack graph (filters, collapse, evidence per edge),
  Command Center findings panels without a blended score, and reports frozen as insert-only, SHA-256-hashed
  snapshots that list hypotheses, unverified findings and test-fixture evidence under Limitations. PDF via the
  browser's print dialog; server-side PDF later.
- **4b (done):** the tool sandbox and Nuclei.
  - *Egress proxy* (`nightfall/tools/egress.py`): per-run credential, port allowlist, host check against the
    operation target and pinned scope, resolve once and connect to the checked address (private, metadata, CGNAT
    and excluded addresses refused), plain HTTP limited to bodyless GET/HEAD with one request per connection,
    connection/byte/time caps, every decision logged into the evidence. CONNECT tunnels are enforced at the TCP
    destination; TLS isn't intercepted.
  - *Runner and sandbox* (`nightfall/tools/runner.py`, `infra/tools/`): argv only, empty environment, own process
    group, rlimits, capped output. The tool user may reach only the proxy port (nftables rule installed at
    container start). The worker keeps CAP_SETUID/SETGID only, under no_new_privs, and the tool process gets
    none. Setuid bits are stripped from the image, which is pinned by digest. A live run first verifies the
    lock: the tool user must fail to reach a loopback canary and fail to change uid. Verified in the built
    image: the tool process has no capabilities, connections to the internet, DNS and Postgres are all refused,
    and without NET_ADMIN the container doesn't start.
  - *Nuclei* v3.11.1 (`nightfall/tools/nuclei/`): only NIGHTFALL-authored, hash-pinned, GET-only HTTP templates
    run (git metadata, directory listing, Apache server-status, missing HSTS). The upstream nuclei-templates
    aren't used yet; adding any of them means reviewing and pinning each one. Flags: `-ni -duc -dr -or -ot -pt http`,
    honest User-Agent, low rate. Output is parsed as untrusted: only catalog ids matched on the target host are
    kept. Finding rule R6 takes its wording and severity from the catalog. LOW risk: approval required.
  - **Moved to 4c, with reasons.** *ZAP* is a long-running JVM daemon driven through its own API. Its spider
    needs a context/scope model and its own upstream-proxy settings, so it is a separate adapter on top of this
    sandbox and proxy. *Amass* v5 needs the separate engine service (see 10a). Both reuse the proxy and the lock
    unchanged.

## 10c. Hosting and Phase 5 delivery notes (added 2026-11-05)

- **Hosting changed by the owner's decision: Vercel + Neon** (decision 9 revised). Next.js and the FastAPI backend
  run as Vercel Services on one domain. The web service reaches the API through a private binding. Neon provides
  Postgres. Adaptations (`api/nightfall/serverless.py`):
  - API and worker database roles are unchanged. Their passwords are derived from the owner password with HMAC,
    roles and migrations run at cold start under an advisory lock, and start-up refuses if a role could bypass RLS.
  - Evidence content lives in Postgres (migration 0006): RLS-scoped through the evidence rows, insert-only.
  - Rate limits are shared through Postgres (migration 0007, keys hashed).
  - There is no worker loop. Jobs run after a request or approval, when an open operation page nudges the queue,
    and from a daily cron.
  - *Weaker than self-hosting:* Neon's owner credentials are in the platform environment, and the tool sandbox
    can't run, so Nuclei is refused. `render.yaml` and `infra/render/` remain as a tested alternative.
- **AI provider changed by the owner's decision (§6, Addendum A local-first):** hosted Claude through the
  official Anthropic SDK (`NIGHTFALL_AI_PROVIDER=anthropic`, `ANTHROPIC_API_KEY`), default model `claude-opus-5-5`.
  Assessment data in the agents' data blocks is sent to the provider. `none` remains the default, and
  Ollama can be added behind the same `Provider` interface.
- **5a (done):** provider interface (structured outputs validated against each agent's schema, server-side refusal
  fallback), `agent_tasks` (migration 0008), deterministic Tool Gateway, and three agents:
  - *Scout:* proposes collections. Each one is checked against the allowlist, scope, exclusions and risk class:
    passive is queued, low waits for an explicit approval (see §17, D1), and anything else is refused and audited.
  - *Hunter:* proposes findings. They are recorded only as `hypothesis` / low confidence, and only with evidence
    the agent was shown from this project.
  - *Guardian:* reviews each Hunter finding against the cited raw evidence, without Hunter's reasoning. The verdict
    is stored as advice and never changes status.
  - Agents are defined in code (`nightfall/agents/registry.py`, prompt version on every task) instead of an
    `agents` table.
  - Collected content goes only into neutralized `<data>` blocks. Injection fixtures are in the tests.
- **5b (done):** the remaining four agents. Same rule as 5a: they propose, the gateway decides, and their
  output is labelled AI output and enters as a hypothesis.
  - *Director:* creates `agent_tasks` only, for Scout, Investigator, Hunter, Adversary or Analyst. It can't
    assign work to itself or Guardian, creates at most 5 tasks, and never duplicates a run that is open.
    Its objective reaches the next agent inside a `<data source="director_objective">` block, not as that
    agent's task line, because another model wrote it.
  - *Investigator:* explains one asset (`agent_tasks.subject_asset_id`, migration 0009). Relationships it
    proposes need both assets known in the organization and evidence it was shown. They are stored as
    `hypothesis` with low confidence and a rule `agent:investigator@…`. A CHECK stops an agent row from
    claiming `observed`. A collector that later observes the same relationship promotes it under its own
    rule and evidence, and keeps the proposing task linked.
  - *Adversary:* proposes attack paths. Every step must name a finding it was shown or a known asset;
    every path needs at least one finding and 2 to 8 steps; at most 3 paths per run. False-positive and
    remediated findings are never shown. Paths are stored as `hypothesis` with low confidence, guarded by a
    CHECK. The Phase 4 rule still applies: a path can be validated only by a person, and only once every
    finding in it is validated.
  - *Analyst:* narrative summary kept on the task and shown as "AI-written, not verified". It isn't part
    of the frozen report, which stays template-built. The counts beside it are computed from the records.
    Key risks must be findings it was shown, and their status is read from the record.
  - Workspace agents page (`/w/{ws}/agents`): roster with 30-day usage counted from `agent_tasks`, plus
    recent tasks. The Command Center "Agent activity" panel (placeholder until Phase 5) now shows real
    counts. The sidebar keeps its eight sections.
  - Benchmark harness: `nightfall/agents/bench.py`, method in `docs/benchmarks/README.md`. 11 fixed
    cases, 4 of them injection cases. **No real-model results yet**, because no API key is available in
    development, so the default model is still unmeasured.

## 10d. Phase 6 delivery note (added 2026-11-05)

- **6a (done): War Room** (`GET /war-room`, `/w/{ws}/war-room`). One screen for everything waiting on a person, all
  read from stored records:
  - *Awaiting a decision:* operations that need approval. Approve and reject work inline and use the existing
    routes, which re-check role, self-approval and the scope. The screen says why you can't decide: you
    requested it, or your role doesn't allow it.
  - *In flight:* collections and agent tasks that are queued or running. It refreshes on its own.
  - *AI proposals to review:* agent findings, attack paths and relationships still marked hypothesis, with exact
    counts and the Guardian verdict.
  - *Decision log:* from `audit_events`, limited to an allowlist of decision actions and data fields. IPs and user
    agents are never shown.
- **Shell items from the Phase 1 plan, now built:**
  - *Header approvals bell:* the count is only operations you may decide on. It links to the War Room.
  - *Assessment completion on the Command Center:* finished agent tasks out of all agent tasks for that
    assessment (§15 mockup review), hidden when an assessment has none.
- **Security pass on Phases 5a–6a:** `docs/reviews/2026-11-05-phase5-6-security-pass.md`. One fix: the hourly
  agent limit now also bounds tasks the Director creates.
- **6b (built; runs on the owner's Windows machine): isolated lab** (§16.5). Hosting decision: lab worker on the
  owner's home computer with Docker Desktop. It connects outward to Neon only and opens no ports.
  - *Lab scopes* (`scopes.is_lab`, migration 0010): only IP addresses or ranges inside `NIGHTFALL_LAB_NETWORKS`
    (default `172.30.99.0/24`), and no hostnames, because the API can't check what a lab name resolves to.
    Normal scopes can't name lab addresses. Checked when a target is added, when a draft is switched, at
    authorization, and at run time by the lab worker (`SafeHttp.only_networks`).
  - *Operations* copy `is_lab` from their scope. Every lab run needs an explicit approval (§17: by the owner under the single-operator policy, and only through BLACKSITE). Moderate risk is
    allowed only in a lab (DB CHECK), but no moderate tool is registered yet. Agents can't propose lab runs.
  - *Two workers, disjoint queues:* the restrictive RLS policy limits `nightfall_worker` to `NOT is_lab` and
    `nightfall_lab_worker` to `is_lab`, and the claim queries filter the same way. The lab role has no access to
    agent tasks, attack paths, users or sessions, and can add evidence content but not read it. Its login is
    enabled only when `NIGHTFALL_LAB_WORKER_DB_PASSWORD` is set.
  - *Network:*
    - `lab-net` is a Docker `internal` network with no route out. Practice apps (OWASP Juice Shop, MIT) live
      only there, with no published ports.
    - In lab mode, `egress-lock.sh` also limits the worker's own process to the lab network, DNS and the
      database port.
    - Tools still reach only the per-run proxy.
    - CI proves the app answers inside the lab, the lab has no route out, nothing is published, and the
      worker process can't reach the internet.
  - *Results:* lab evidence is `is_simulation`, and lab scopes, runs and reports are labelled "LAB · ISOLATED"
    in text.
  - *Not yet:*
    - moderate-risk tool packs (full Nuclei template set, ZAP active scan), each needing its own review;
    - more practice apps, each after a license review;
    - BLACKSITE, still gated on the independent authorization-model review (§16.1).
  - Setup guide: `infra/lab/README.md`.

## 11. Decisions requiring human approval

**All approved as proposed (2026-11-04).**

1. **Repository visibility:** *superseded 2026-11-06: the repository stays public (owner decision, §17).* `bosafett/nightfall` is currently **public**. Recommend private before Phase 1, because scope definitions, lab configs, and client names will follow. Also confirm that the first commit goes to `main`.
2. **Tenant naming:** `workspaces` = tenant, `organizations` = investigated targets (§4.1).
3. **Auth (rev 2):** API-owned sessions + argon2id + TOTP, invite-only, offline password reset (§5). This replaces Supabase Auth.
4. **Queue:** Postgres-backed in MVP. Redis deferred (§3).
5. **Roles:** enum + code permissions instead of a `roles` table (§4.2).
6. **Project = assessment** in 0.1 (§4.2).
7. **Retention periods** (§4.3).
8. **Technology identification = low risk** (approval needed), not passive. It sends HTTP requests to the target.
9. **Deployment (rev 2):** self-hosted Docker Compose on one host (§9). **What hardware?** GPU model/VRAM, RAM, CPU. This decides which local models are viable. Not needed until Phase 5.
10. **Tool risk classes** for Amass, Nuclei, and ZAP (§13 table). Note: Nuclei and ZAP are "high priority" in Addendum A, but most of what they do is active testing, which spec §8.2 restricts to the lab. In 0.1, real targets get only their low-risk subsets.
11. **Mockup deviations** (§15): drop ETA and decorative imagery, relationship graph instead of a world map, categorical confidence instead of "87%", no purple.
12. **BLACKSITE** (§16): Postgres queue instead of Redis, loopback-only listener reached via SSH tunnel, step-up MFA, scheduling after main Phase 3, and the header/redirect rules.

## 12. Blockers

- ~~**Repository visibility:**~~ not a blocker: the owner decided to keep it public (§17).
- **Logo:** received as `brand/nightfall-mark.svg`.
- **Host hardware** (decision 9): needed by Phase 5 only.
- Nothing else blocks Phase 1.

## 13. Addendum A — open-source tool integrations

**Adapter contract** (`api/nightfall/tools/<tool>/`):
- `build_invocation(params, scope) -> argv`: arguments are built from validated, enum-typed parameters and passed as an argv list, never through a shell. No model-supplied flags or free text ever reaches a command line.
- `parse(raw) -> list[EvidenceDraft]`: treats output as untrusted. Page titles, banners, and headers are attacker-controlled.
- `version()`: recorded on every evidence row.

**Execution:**
- Tools run inside the worker's tools image with pinned binaries, a read-only filesystem, CPU/memory/time limits, an output size cap, and no DB or LLM credentials.
- Raw output is stored as evidence (sha256, tool version, argv).
- Nothing is vendored into the repo. Images are pinned by digest.

**Scope at the network layer (proposed Phase 3 component, built before any non-passive tool ships):**
- Tools follow redirects, crawl links, and resolve CNAMEs to third-party infrastructure, so a tool's own scope flags are not a guarantee.
- Non-passive tools egress only through a worker-local forward proxy. It allows a destination only if its hostname *and* resolved IP are in the operation's pinned scope, and refuses and logs everything else.
- Nuclei and ZAP both support an upstream proxy.

| Tool | License* | Use in NIGHTFALL | Proposed risk class in 0.1 | Phase |
|---|---|---|---|---|
| OWASP Amass | Apache-2.0 | Asset discovery from passive sources (CT, DNS datasets, archives) | Passive enumeration only = **passive**. Active modes (brute force, zone transfer, port probing) not enabled in 0.1. | 3 |
| ProjectDiscovery Nuclei + templates | MIT | Template-based detection | Curated, pinned allowlist of non-intrusive templates (tech detection, TLS, exposed metadata) = **low** (approval). All other templates = **moderate** (lab only). `code`/`headless`/`javascript`/`file` templates and `intrusive`/`dos`/`fuzz` tags disabled. Template updates pinned and reviewed, never auto-pulled. | 3–4 |
| OWASP ZAP | Apache-2.0 | Web application testing | Spider + passive rules (baseline) = **low** (approval, rate-limited, in-scope context). Active scan = **moderate** (lab only). | 4 |
| MITRE CALDERA | Apache-2.0 | Adversary emulation | Deploys agents (implants) onto hosts → **lab only, ever** | 6+ |
| NVIDIA garak | Apache-2.0 | LLM vulnerability scanning | Needs its own scope type ("AI endpoint") and rate limits | Future |
| Microsoft PyRIT | MIT | AI red-team orchestration | As garak | Future |

\*Licenses as currently understood. Verify the LICENSE file, release cadence, open security advisories, and transitive dependencies at adoption, with one ADR per tool. Amass's CLI and storage model changed substantially across major versions, so the adapter targets the version pinned at Phase 3.

## 14. Addendum A — BLACK ICE (correlation subsystem)

Module: `api/nightfall/blackice/`. Deterministic rules are authoritative. AI may only suggest.

- **Normalization:** every adapter's evidence drafts become canonical observations (asset kind + normalized value + attributes). This shares normalization code with scope enforcement, so "in scope" and "same asset" can't disagree.
- **Relationship mapping:** writes `asset_relationships`, each tagged with the producing `rule_id`.
- **Finding correlation:** rule-based dedup and merge. Same asset + same check/CVE → one finding, with the new evidence linked and `last_observed_at` updated. This is also what makes re-runs idempotent.
- **Confidence (transparent, categorical).** Every derived value stores `rule_id` + `ruleset_version`, and the UI shows the rule. Initial rules (proposal):
  - **high:** authoritative observation (live DNS answer, CT log entry, tool detection with matching raw evidence), or ≥2 independent sources
  - **medium:** a single non-authoritative source (third-party dataset)
  - **low:** inference only, including every LLM-originated claim

  No percentages unless backed by measured calibration. AI-suggested correlations enter as `hypothesis` (origin = agent) and never change the confidence of deterministic records.
- **Snapshots:** `assessment_snapshots` holds a manifest of entity ids + content hashes and the ruleset version. A snapshot is taken on every report and on demand, and each report cites its snapshot, so reports are reproducible.
- **Replay:** re-runs a ruleset (current or historical) over the evidence as of a snapshot and produces a diff. It never mutates the snapshot. Rules are versioned code, with golden-file tests per rule and for replay.
- **Freshness (A5):** per-source "last successful collection" is derived from the latest successful collector operation, with no extra table. The UI shows "updated N ago", "stale", or "unavailable". Sources that need credentials are optional and show "not configured".

### 14.1 BLACK ICE delivery status (2026-11-05)

- **Built in Phases 3–4:** normalization shared with scope, relationship mapping with `rule_id`, finding rules
  R1–R6 (`findings/2026.11-2`), dedup per asset + check, snapshots on every report.
- **Freshness (A5):** built. `GET /sources`, derived from `operations` with no extra table. Per source the
  state is `fresh`, `stale` (no success in 7 days), `failing` (the latest finished run failed, with its error),
  `never_run` or `unavailable` (e.g. Nuclei on serverless hosting). Lab runs are excluded. The panel is on the
  Reconnaissance page.
- **Replay:** built. `GET /reports/{id}/replay` is read-only. It re-runs the **current** rules over the
  observations stored on every evidence record collected up to the snapshot, with the clock set to the
  snapshot's time. Results are compared against the snapshot's rule-made findings by asset + check id (older
  snapshots by asset + rule + title) and grouped as unchanged, changed, new and no longer found. Snapshots now
  record `check_id`. *Limit:* only the current ruleset can be replayed, because older rule versions aren't kept
  in code. The page shows both ruleset versions.
- **Golden files:** built. `tests/golden/finding_rules/` has one case per rule plus clean and DNS-only cases.
  Any output change fails until the files are regenerated on purpose (`NIGHTFALL_UPDATE_GOLDEN=1`) and
  reviewed.
- **"≥2 independent sources → high" / "medium" confidence:** not built, by design. Every current source is
  authoritative (live DNS answers, CT logs, tool detections with raw evidence), so rule-made records are high.
  The rule becomes meaningful when third-party datasets are added, and should come with them.

## 15. Mockup review (command center)

**Keep:**
- layout: sidebar; header with tagline; KPI row; assessments + graph row; findings / agents / risk row
- charcoal and crimson palette
- text-labelled severity pills
- crimson "New project" primary button
- notifications bell (= pending approvals)
- system-status card
- version tag

**Change (spec, honesty, or accessibility):**

| Mockup element | Issue | Proposal |
|---|---|---|
| "+1 vs last week", "+18%", "+33%" | Must come from data | Computed from timestamps over the selected 1h/24h/7d/30d window. Hidden when there's no prior-period data. |
| "ETA: 1h" | No honest way to compute | Drop. Show started and last-activity time (spec fields). |
| Completion % | "Only when meaningful" | Completed ÷ total agent tasks for the assessment. Hidden with no tasks. |
| Assessment thumbnails (globe, skyline, brain) | Decorative imagery | Assessment-type icon |
| "Planning" pill and Adversary icon are **purple** | Purple is excluded for colour-vision accessibility (same constraint as the Selene OS dashboard) | Planning = gray. Adversary = crimson outline. |
| Intelligence graph drawn on a world map | Geography isn't the relationship data the spec asks for, and it needs a licensed, offline GeoIP DB | React Flow relationship graph (org → domain → subdomain → API → finding), with hypotheses dashed. Geo view optional later. |
| "Confidence: 87%" | False precision | Categorical confidence plus the rule behind it (§14) |
| System-status sparkline | Decorative chart | Real checks: API, DB, worker heartbeat, Ollama, data-source freshness |
| "Low" is blue, there's no "Info" | Spec maps blue to informational | Low = blue, Info = gray, always with text labels |
| Risk donut | Crimson vs orange is hard to tell apart with red–green colour blindness | Fixed segment order (critical→low) and labelled counts in the legend (as drawn). Never meaning by colour alone. |
| KPI "Critical findings 2" vs donut "Critical 7" | Inconsistent | Both = open findings (excluding false positive/remediated). Same definition, same number. |
| Condensed display font | Must work offline | Self-hosted via `next/font`. Tabular numerals for all numbers. |

**Draft tokens** (sampled from the mockup, contrast-checked in Phase 1 step 5):

| Token | Hex | Token | Hex |
|---|---|---|---|
| bg | `#0A0A0C` | crimson (primary/critical) | `#E5192E` |
| surface | `#121216` | orange (high) | `#FF7A1A` |
| border | `#24242A` | yellow (medium) | `#FFC21A` |
| text | `#E8E8EC` | blue (low/intel) | `#2F7BFF` |
| muted | `#9A9AA3` | green (healthy/validated) | `#22C55E` |
| gray (info/neutral) | `#6B6B75` | | |

## 16. Addendum 3 — BLACKSITE (manual operations and active probing)

**Fit:** BLACKSITE needs **no parallel system.** Every probe is an `operations` row:
- It is scope-checked by the same gateway and executed by a worker.
- Its output is stored as `evidence` and correlated by BLACK ICE.
- It is recorded in `audit_events`.

Probe history is a filtered view of `operations`. The only new storage:
- `probe_profiles` (saved requests)
- port, protocol, rate, and budget columns on `scope_targets` (§4.2)

### 16.1 Where it sits in the roadmap

It depends on the scope engine, evidence, and BLACK ICE, so it can't come earlier.

| BLACKSITE phase | Runs after main phase | Gate |
|---|---|---|
| 1 Restricted workspace | 3 (scope engine) | — |
| 2 Manual diagnostics | 3 | — |
| 3 Evidence + BLACK ICE | 4 | — |
| 4 Lab | 6 (lab environment) | **Independent review of the authorization model** (Addendum 3 directive), recorded as a document in `docs/reviews/` |

### 16.2 Access (MVP)

Four checks, all of which must pass:
1. **Feature flag** `BLACKSITE_ENABLED=false` by default. When off, the routes aren't mounted at all, so they 404.
2. **Loopback-only listener:** BLACKSITE endpoints are served on a second API port bound to `127.0.0.1`. Caddy has no route to them, so they are not reachable from the network. The operator reaches them with an SSH tunnel to the host. This is "localhost-only, no public route" enforced by the network, not by a header check.
3. **Owner role.**
4. **Step-up MFA:** a fresh TOTP challenge within the last 15 minutes.

Every request is audited, **including denials** (§8 of the addendum).

### 16.3 Execution path

Server-side, in the order the addendum gives:

1. Resolve the asset from the registry by **asset id**. The API accepts no free-form URL, host, or IP, so unregistered destinations can't even be expressed.
2. Load the active scope version and the target entry. Exclusions win.
3. Validate probe type, method, parameters, port, and protocol against the execution profile and the target's allowed lists.
4. Check rate (`max_rps`), concurrency (at most 2 per target), and daily budget. Counted in Postgres under an advisory lock, so no Redis is needed.
5. Write the `operations` row and an audit event, then enqueue. A worker is woken via Postgres `LISTEN/NOTIFY` for sub-second pickup.
6. **In the worker**, resolve DNS once and re-check every resolved IP against the scope and against blocked ranges: private, loopback, link-local, metadata (`169.254.169.254`, `fd00:ec2::254`), and CGNAT. Then **connect to that pinned IP**, sending the registered hostname as SNI/Host. Pinning defeats DNS rebinding, because the IP checked is the IP used.
7. Store request and response metadata, body (size-capped), a TLS summary, timing, and a sha256 as evidence. Update the operation and write an audit event.

### 16.4 Bounds per probe type (Profile 1 — Diagnostic)

| Probe | Bounds |
|---|---|
| HTTP | Only GET, HEAD, OPTIONS. **Redirects are never followed automatically.** A 3xx is returned with its `Location`, and following it is a *new* probe that must pass scope. Custom headers allowed except `Host` (locked to the target, so virtual-host scope bypass isn't possible) and hop-by-hop headers. `Authorization`/`Cookie` values are **redacted in stored evidence**. 10 s timeout, 2 MiB response cap, body shown as escaped text and never rendered as HTML. |
| DNS | A, AAAA, CNAME, MX, TXT, NS, CAA for registered names only. CNAME targets outside scope are *shown* but not probed further. |
| TCP connect | Only ports in the target's `allowed_ports`, at most 10 per probe. Connect, then close. No banner payloads, no ranges, no sweeps. |
| TLS | Handshake to an allowed port. Reports chain, validity, SANs, protocol, and cipher. Validation result is reported separately from inspection, so an invalid certificate is a result, not an error. |
| Service ID / availability / timing | Built from the HTTP + TLS + TCP primitives above. No separate scanner. |

### 16.5 Profile 3 — Isolated Lab

- **Lab assets live only in a lab scope** (`scopes.is_lab`). A lab scope may contain only targets whose resolved addresses fall within the host's configured **lab CIDRs**. This is checked at registration *and* again at execution, so lab permissions can't authorize an external target (Definition of Done item 9).
- **Separate lab worker container** on a `lab-net` Docker network with **no internet route** and no production credentials. Lab operations are routed only to that worker. The normal worker refuses `is_lab` operations, and the lab worker refuses everything else.
- **State-changing methods** (POST, PUT, PATCH, DELETE) exist only in Profile 3. Each needs an operator confirmation plus an approved test case, i.e. an approved `operations` row (§4.2 approvals).
- **Lab applications:** intentionally vulnerable training apps (choice deferred to BLACKSITE phase 4, with a license review) run as containers on `lab-net`.
- **Profile 2** (authorized assessment on real targets) is not built, per the addendum. It waits for the independent review.

### 16.6 Evidence, history, replay

- **Evidence:** every probe produces evidence with all addendum §2D fields. Operator identity is `actor`. Notes are an editable annotation; the raw capture stays immutable and hashed.
- **Screenshots** need a headless browser, which is a new active capability, so they are **deferred**. Operator-uploaded attachments are supported.
- **"Submit to BLACK ICE"** runs normalization and correlation on that evidence. It can attach to an existing finding or create one as `unverified`; the operator, as a human, can then validate it.
- **Compare:** structured diff of status, headers, TLS fields, and body hash/text between any two probes of the same target.
- **Replay:** creates a **new** operation with copied parameters and runs steps 1–7 again in full. Earlier approval is not reused.

### 16.7 Agents

- No agent's allowlist contains any BLACKSITE probe, and a gateway test enforces this.
- Agents may output a `probe_recommendation` (type, params, rationale, evidence refs). It appears in the Probe Deck as a suggestion the operator can load, and nothing runs until the operator executes it.

### 16.8 UI

- Nav item "BLACKSITE" between War Room and Reports, **rendered only** when the flag is on, the user is the owner, and the page is reached via the loopback listener.
- **Persistent header strip:** target, scope version, authorization status, execution profile. Lab is shown in its own colour-plus-text label (e.g. "LAB · ISOLATED"), never colour alone.
- **Panes:** target console | request composer | response (monospace, tabular) | history and evidence. Denied operations appear in history with the reason.

### 16.9 Conflicts with earlier decisions, resolved here

- **Queue: Addendum 3 lists Redis.** Postgres `LISTEN/NOTIFY` + `SKIP LOCKED` already meets interactive latency for a single operator, and keeps rate and budget counters transactional. I recommend keeping Postgres and adding Redis only if measurements show a need (decision 12).
- **New dependencies:** none. Uses `httpx` (custom transport for IP pinning, verified at implementation), `dnspython`, the stdlib `ssl`/`socket`, and `cryptography` for certificate parsing.

### 16.10 Tests (in addition to §11 of the spec)

Each of these is a required test, run against a local test server:
- **Scope bypass attempts:**
  - unregistered host
  - excluded subdomain
  - redirect to out-of-scope host
  - in-scope name resolving to a private IP, to `169.254.169.254`, or to an out-of-scope public IP
  - DNS rebinding (first resolution in scope, second out)
  - `Host` header override
  - IPv6 and decimal/octal IP encodings
  - port not in the allowed list
  - lab target registered in a non-lab scope, and the reverse
- **Access:**
  - non-owner
  - owner without a fresh MFA challenge
  - flag off
  - request via the public listener
- **Budget and rate exhaustion.**
- **Every denial produces an audit event.**

## 17. JANUS decisions and roadmap (2026-11-06)

Owner decisions, final. Where earlier sections disagree, this section wins.

| # | Decision | Effect |
|---|---|---|
| D1 | **Single-operator authorization.** One operator, the owner. No second person or second account is required. | `workspaces.approval_policy` = `single_operator` (default) or `two_person`. Under `single_operator` only a workspace **owner** may approve their own request; others never may. Approvals, rejections, playbook launches and scope authorization need two-factor verified in the last 15 minutes. Every approval records the authenticated approver. Two accounts held by one person are never presented as independent authorization. `two_person` stays available for later. |
| D3 | **BLACKSITE runs on the lab machine, host-only.** Remote administration through an authenticated SSH tunnel. Nothing public. The hosted (Vercel) app must not become an execution gateway into the lab. | `nightfall-blacksite` listener (separate app, loopback only, peer and `Host` checks, feature flag off by default, refused on the hosted platform). Lab operations and lab playbook runs are created, approved and cancelled only through it; the hosted app's database role can read lab records but not act on them. See `docs/blacksite-deployment.md`. |
| D4 | **Independent review** of sensitive security functionality, by someone other than its implementer (person or agent). Tests and self-review are not sign-off. | BLACKSITE refuses lab execution until `NIGHTFALL_BLACKSITE_REVIEW_REF` is set. The software can't verify a review happened; the reference is the owner's attestation and should name a signed document in `docs/reviews/`. |
| — | **Repository stays public.** Vercel free tier stays; no hosting migration or paid services. | §11.1 and §12 superseded. No paid AI calls during development. |
| — | **Rename to JANUS / JNS.OS**, display level. | Product name in UI, reports, API title, User-Agent and docs. Internal identifiers unchanged (package, `NIGHTFALL_*` variables, `nightfall_*` roles, cookie name), so deployments keep working. Agent prompt text now says JANUS too (prompt version `agents/2026.11-3`, 2026-11-07). |

**Lab boundary (recommended and adopted for D3).** The lab worker already pulls jobs from the database; previously the
hosted app could create and approve those jobs, which made it a gateway into the lab. Now only BLACKSITE can (API
check plus restrictive database policies, migration 0013). Consequence: lab collections and lab playbook runs can no
longer be started or approved from the hosted UI; it shows them read-only.

### 17.1 Phase 1 (BLACKSITE security foundation) status

| Item | Implemented | Unit / integration tested | Security tested | Independently reviewed | Deployed |
|---|---|---|---|---|---|
| Feature flag, off by default, fails closed | ✓ | ✓ | ✓ (`tests/test_blacksite.py`) | ✗ | ✗ |
| Host-only listener (loopback bind, peer + Host check, no forwarded headers) | ✓ | ✓ | ✓ | ✗ | ✗ |
| SSH tunnel for remote administration | documented | — | — | ✗ | ✗ |
| Owner only + two-factor within 15 minutes, server-side; step-up endpoint | ✓ | ✓ | ✓ | ✗ | ✗ (hosted app: on next deploy) |
| Session revocation (`/auth/logout`, `/auth/logout-all`) | ✓ (existing) | ✓ | ✓ | ✗ | ✓ (existing) |
| Confined database role `nightfall_blacksite` | ✓ | ✓ | ✓ | ✗ | ✗ |
| Lab boundary for the hosted app | ✓ | ✓ | ✓ | ✗ | ✗ |
| Audit: access, refusals (network, role, two-factor, boundary, review), approvals, operations | ✓ | ✓ | ✓ | ✗ | ✗ |
| Review gate (D4) | ✓ | ✓ | ✓ | ✗ | ✗ |

Nothing is deployed until the owner approves a push and a Vercel redeploy, and BLACKSITE stays off until the
independent review is recorded.

### 17.2 Phase 2 (BLACKSITE probe deck) status

Lab only (profile C): under D3 BLACKSITE acts on lab work only, so probing real targets from it would need a new
owner decision and its own review. Operator console served by the listener at `/` (added after Phase 2: vanilla
JS, strict CSP, text-only rendering; tests in `tests/test_blacksite_ui.py`, plus a manual browser check).

| Item | Implemented | Tested | Independently reviewed | Deployed |
|---|---|---|---|---|
| Probes addressed by registered asset id only (lab assets visible to the BLACKSITE role) | ✓ | ✓ | ✗ | ✗ |
| HTTP (GET/HEAD/OPTIONS low risk; POST/PUT/PATCH/DELETE moderate, lab only, explicit confirmation), TCP connect, TLS handshake | ✓ | ✓ | ✗ | ✗ |
| Per-target allowed ports (≤10), max requests/second and daily budget on scope entries (immutable once authorized); counted under an advisory lock | ✓ | ✓ | ✗ | ✗ |
| At most one probe pending per target (stricter than the designed two) | ✓ | ✓ | ✗ | ✗ |
| Host/User-Agent fixed, hop-by-hop and forwarding headers refused, redirects recorded not followed, Authorization/Cookie/Set-Cookie redacted in evidence | ✓ | ✓ | ✗ | ✗ |
| Lab worker re-checks spec and ports from the pinned scope; only lab addresses reachable | ✓ | ✓ | ✗ | ✗ |
| History, replay (new operation, new approval), structured compare | ✓ | ✓ | ✗ | ✗ |
| Every refusal audited (`probe.denied`) | ✓ | ✓ | ✗ | ✗ |

Known limits: operation params (not evidence) keep the header values the operator sent, readable through the database;
DNS probes (meaningless in a hostname-free lab) are not built.

### 17.3 Roadmap

1. **Now:** owner review of this change; independent review of the BLACKSITE authorization model and of Phase 1
   (`docs/reviews/2026-11-blacksite-authorization-model.md` §9); record the reference.
2. ~~**Phase 2 — BLACKSITE probe deck**~~ built (§17.2), lab only, with the operator console and "Submit to BLACK
   ICE" (migration 0015: BLACK ICE's rules over a finished HTTP or TLS probe; findings start unverified and
   correlate with existing ones). 0015 also fixes finding numbering for confined roles (lab worker, BLACKSITE),
   which could reuse a number taken in a project they can't see.
3. **BLACK OPS remainder:** Profile B design and review; playbooks 6–11 after validation.
4. **Tools:** ZAP baseline (low risk), Amass engine, moderate-risk lab packs, each with its own review.
5. **Platform:** local AI provider (no paid calls), audit export to append-only storage (F7), server-side PDF.

### 17.4 Addendum 5 (SWORD / SHIELD / JANUS CORE) status

Addendum 5 is architectural guidance; it's built in small phases on top of what exists, never as parallel systems.

- **Phase A — navigation (done).** The sidebar is grouped as Command Center, SWORD, SHIELD, JANUS CORE and SYSTEM
  (`web/lib/nav.ts`). Existing pages were regrouped, not duplicated. Modules without a page are text labels tagged
  "Planned" (BLACK ICE is tagged "In Findings"), never links.
- **Phase B — CONTROL, WATCHTOWER, audit log (done, no migration).**
  - CONTROL: `nightfall/control/approvals.py` is the one approval-lifetime rule. Every approval now expires (lab 24 h,
    live 72 h); the worker refuses older work, which must be approved again. Route-level checks stay where they are
    (`core/tenancy/deps.py`, `blacksite/boundary.py`, the scope evaluator); moving them is a later, reviewed change.
  - WATCHTOWER: `GET /api/workspaces/{ws}/watchtower` (owner and admin, new `audit.read` permission) reports the worker
    and lab worker heartbeats, whether this deployment can write audit events, and failed work in the last 24 h. Lab
    workers heartbeat as `lab:<host>:<pid>`; `/api/health` stays public and no longer counts a lab heartbeat as the
    hosted worker. The sidebar shows the lab line to owners and admins.
  - Audit log: `GET /api/workspaces/{ws}/audit` (owner and admin), paged, filterable by category, workspace-confined by
    row-level security, secret-looking fields redacted. Page: SYSTEM → Audit Log.
- **ATLAS v0 — asset status and history (done, migration 0016).**
  - `assets.status`: unverified (every new asset), verified (a person confirmed it belongs to the organization) or
    retired. Trigger `nf_asset_guard` allows a change only from the app role with a signed-in user; collectors, the
    lab worker and BLACKSITE get an error even if they set `app.user_id`.
  - `asset_history`: the trigger `nf_asset_history` writes it on creation and on every change of status, ownership or
    notes, whichever role makes the change, recording the user (if any) and the database role. No role may update,
    delete or insert into it directly. Existing assets got a backfilled "created" row (`recorded_by = 'migration'`).
  - "Monitored" isn't a status: nothing monitors assets yet (that's AEGIS), and the label would imply it does.
  - UI: a status badge and filter on the asset list, a status field on the asset form, and a History panel on each asset.
    ATLAS stays a label in the sidebar ("In Targets").
- **BLACK BOX v0: evidence integrity and retention (done, no migration).**
  - `GET /api/workspaces/{ws}/blackbox` (owner and admin, `audit.read`) is the evidence inventory: count, size, kinds,
    simulated items, oldest and newest, counts older than 90 and 365 days, and the last verification run.
  - `POST /api/workspaces/{ws}/blackbox/verify` re-reads stored content (file or Postgres backend, under row-level
    security) and reports each record whose content is missing or whose hash or size doesn't match.
  - It runs in batches of 200 so it fits one serverless request. The page calls it batch by batch until the workspace
    is done. Each batch is an audit event (`blackbox.verified`) with the run's running totals, computed on the server
    from earlier events in the same run, and each failure is also logged as `evidence.integrity_failed`.
  - It runs only when a person asks; there is no schedule.
  - Retention is reported, not enforced: the policy is "keep indefinitely" and nothing deletes evidence. Deleting it
    needs a reviewed retention policy and an owner decision.
  - Page: JANUS CORE → BLACK BOX, the first JANUS CORE entry that links to a page.
- **BLACK ICE contradiction flags (done, no migration).**
  - `GET /api/workspaces/{ws}/contradictions` (any member, optional `project_id`) lists rule-made findings whose
    status disagrees with newer evidence; each finding's detail carries the same flag as `contradiction`.
  - `not_reproduced`: an unverified or validated finding whose asset was checked again by the same tool after the
    evidence behind it, and the current rules don't find the condition in the newer evidence.
  - `seen_after_false_positive`: a finding marked a false positive that the rules observed again afterwards.
    Remediated findings aren't flagged, because ingest already reopens them.
  - Only comparable evidence counts: the latest record from the same tool, on the same asset and project, with the
    same simulation flag (lab and real results never contradict each other). The finding's own evidence must still
    produce the check under the current rules. Header checks need an HTTPS response in the newer audit, and cookie
    checks need the same cookie.
  - Read-only and computed on request: a flag never changes a finding. A person reviews it and sets the status.
  - UI: a "Contradicted by newer evidence" panel on Findings and a notice on the finding page. BLACK ICE stays a label
    in the sidebar.
- **SWORD: agent prompt rename (done).** The agents' ground rules name JANUS instead of NIGHTFALL; the prompt
  version is now `agents/2026.11-3`, so tasks show which wording they ran with. No benchmark was re-run.
- **SWORD: audit export with a hash chain (F7, partly addressed; no migration).**
  - `POST /api/workspaces/{ws}/audit/export` (owner and admin, paged with the returned cursor) returns every audit
    event of the workspace, oldest first. Each record carries `hash = sha256(previous hash + canonical record)`,
    starting from a per-workspace genesis value. The page downloads it as NDJSON (SYSTEM → Audit Log → Export).
  - `POST …/audit/export/check` takes the last record of a kept export and recomputes the chain from the start. It
    reports `missing` (that event was deleted), `position` (earlier events were added or removed) or `hash` (an
    earlier event was changed). Exports and checks are audit events.
  - This **detects** changes made with the owner credential, as long as the owner keeps the file outside this
    system. It doesn't **prevent** them: that still needs append-only storage outside the database (an external
    service, so an owner decision). Limits: redacted fields aren't covered, sign-in events without a workspace aren't
    included, and events from the last five minutes wait for the next export.
- **Local AI provider: Ollama (done, no migration).**
  - `NIGHTFALL_AI_PROVIDER=ollama` with `NIGHTFALL_AI_MODEL` (required, e.g. `qwen3:14b`) and `NIGHTFALL_OLLAMA_URL`
    (default `http://127.0.0.1:11434`). No paid calls. AI stays off (`none`) by default and on Vercel.
  - The endpoint must be loopback, a private address or a single-label host name (a compose service), and the
    client ignores proxy settings from the environment, so assessment data stays on the owner's machines. The
    hosted platform (on-demand worker) refuses this setting, because it can't reach a local model.
  - The agent's output schema is sent as Ollama's `format`, with temperature 0. An answer that doesn't validate
    against the schema, or was cut off, is rejected whole; nothing is repaired or partly applied. The gateway's
    checks and the "only a person can verify" rule are unchanged.
  - The Agents page shows "Local model (Ollama): <model>". No model was run and no benchmark was done here:
    which local model is good enough for each agent needs measuring later, when benchmarks are allowed.
- **AI provider decision (owner, 2026-11-07):** the deployment will use the Anthropic API
  (`NIGHTFALL_AI_PROVIDER=anthropic`); the owner adds `ANTHROPIC_API_KEY` in Vercel. Until then AI stays off. Ollama
  remains available for self-hosted workers but isn't required. Agent benchmarks are still not run in this phase.
- **SWORD: ZAP baseline:** skipped for now by the owner (2026-11-07). It needs owner decisions on where the ZAP daemon runs (it can't run on Vercel) and its own tool review before it may contact targets.
- **Next:** SHIELD/AEGIS monitoring needs an owner decision on recurring execution first (it would be the first
  unattended activity against targets, and the hosted free tier has no background runner).
