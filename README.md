# JANUS (JNS.OS)

Single-operator security operations platform by Digital Raccoon Engineering (DRE), part of Zuse Holdings.
Formerly NIGHTFALL: the product name changed, internal names did not. The `nightfall` Python package, the
`NIGHTFALL_*` environment variables, the `nightfall_*` database roles and the repository name stay as they are, so
the running Vercel/Neon deployment and the lab's `lab.env` keep working.

Use is limited to targets you are explicitly authorized to assess.

**Status:** original Phases 1–6, BLACK ICE and BLACK OPS (first five playbooks) are delivered. JANUS Phase 1, the
BLACKSITE security foundation, is implemented and tested but **not independently reviewed or deployed**. See
[`docs/PHASE0_ARCHITECTURE_REVIEW.md`](docs/PHASE0_ARCHITECTURE_REVIEW.md) §17 for the owner decisions (D1, D3, D4)
and the roadmap, and [`docs/blacksite-deployment.md`](docs/blacksite-deployment.md) for BLACKSITE.

## Layout

| Path | What |
|---|---|
| `api/` | FastAPI + SQLAlchemy + Alembic (Python 3.13). The only component that touches the database. |
| `web/` | Next.js (App Router) + Tailwind. Presentation only; proxies `/api/*` to the API. |
| `infra/` | Local Postgres (compose) and role/database setup scripts. |
| `brand/` | Logo source. |

## Local development

Requires Python 3.13, Node 22 and Postgres 16 (local install, or `docker compose -f infra/compose.yml up -d`).

```sh
# 1. Roles + databases (local cluster; compose does this automatically for `nightfall`)
PSQL="psql" sudo -u postgres -E infra/postgres/setup-databases.sh nightfall nightfall_test

# 2. API
cd api
python3 -m venv .venv && .venv/bin/pip install -r requirements.lock && .venv/bin/pip install --no-deps -e .
set -a; . ./.env.example; set +a          # then set NIGHTFALL_SECRET_KEY
.venv/bin/alembic upgrade head
.venv/bin/nightfall-admin create-owner --email you@example.com --name "Your Name" \
  --workspace-name "DRE" --workspace-slug dre
.venv/bin/uvicorn nightfall.asgi:app --port 8000
.venv/bin/nightfall-worker                 # separate terminal: runs queued collection jobs

# 3. Web (second terminal)
cd web && npm ci && npm run dev           # http://localhost:3000
```

First sign-in as owner asks you to set up two-factor (any TOTP authenticator app).

### Admin CLI (host operator only)

```sh
nightfall-admin create-owner   --email E --name N --workspace-name W --workspace-slug S
nightfall-admin reset-password --email E   # sets a new password, signs out all sessions
nightfall-admin reset-mfa      --email E   # removes two-factor; re-enrol at next sign-in
```

It connects with `NIGHTFALL_MIGRATION_DATABASE_URL` (schema owner), so only someone with access to the host can run it.

## Checks

```sh
cd api && .venv/bin/ruff check nightfall migrations tests && .venv/bin/mypy && .venv/bin/pytest
cd web && npm run lint && npm run typecheck && npm test && npm run test:e2e
```

`npm run test:e2e` starts the API and a production web build against the `nightfall_e2e` database
(created by `setup-databases.sh nightfall_e2e`).

After changing API schemas: `cd api && .venv/bin/python -m nightfall.export_openapi > openapi.json && cd ../web && npm run gen:api`.
CI fails if either generated file is stale.

## Security model (Phase 1)

- Postgres row-level security isolates workspaces; the API connects as `nightfall_app` (no superuser, no `BYPASSRLS`).
- Audit log is append-only for the API role; denials and failed sign-ins are recorded.
- Sessions are opaque random tokens; only their SHA-256 is stored. `HttpOnly`, `Secure`, `SameSite=Lax`.
- Mutating requests must carry the configured `Origin`.
- `NIGHTFALL_FORWARDED_HOPS` stays `0` unless a proxy that *sets* `X-Forwarded-For` (e.g. Caddy routing `/api/*`
  directly to the API) sits in front. The Next.js rewrite proxy forwards client-supplied values unchanged.
- Owner, admin and operator roles must use two-factor.

## Scope and collection (Phase 3)

- Each project has versioned scopes: a draft is edited, then authorized by an admin or owner with a written
  reference. Authorized versions can't change (database triggers); changing scope means a new version.
- Scope entries: exact host, domain and all subdomains, IP, CIDR. Exclusions always win. Hostnames and IPs are
  normalized the same way everywhere (case, trailing dot, punycode, strict IP notation).
- Collection requests are refused unless the target is inside the active, in-window scope; refusals are audited.
  The worker re-checks scope when it runs a job and refuses it if the scope changed in between.
- Collectors are passive: certificate-transparency search (contacts crt.sh only) and DNS lookups. Discovered names
  outside scope stay in the raw evidence and are never registered as assets.
- Anything above passive (technology identification) waits for approval by an operator, admin or owner who
  didn't request it; the approval is tied to the scope version. Probes resolve the host once, refuse private,
  metadata and scope-excluded addresses, connect to the checked address, never follow redirects, and send at most
  three GET requests.
- Findings from rule checks start unverified. Only a person can mark one validated, false positive or remediated,
  with a note (enforced by the database). Attack paths stay hypotheses until every finding in them is validated.
- Reports are frozen snapshots with a SHA-256; later changes never alter an existing report, and tampering shows.
- Raw collector output is stored once, content-addressed by SHA-256, and verified on every download.

## Third-party tools (Phase 4b)

- Tools run in the worker image (`infra/tools/Dockerfile`, images pinned by digest) as a separate user whose only
  network destination is a per-run egress proxy on `127.0.0.1:3128`. A kernel firewall rule
  (`infra/tools/egress-lock.sh`) enforces this. The worker keeps only the capabilities needed to start tools as that
  user, and the tool process gets none.
- The proxy needs a per-run credential, and it allows only the operation's target, re-checked against the pinned
  scope. It resolves the name once, refuses private, metadata, CGNAT and scope-excluded addresses, and connects to the
  address it checked. Plain HTTP: GET/HEAD without bodies, one request per connection. Every decision is logged and
  stored with the tool's evidence.
- Nuclei runs only NIGHTFALL's own reviewed, GET-only templates (`api/nightfall/tools/nuclei/templates`), each
  pinned by SHA-256. Out-of-band callbacks, update checks and redirects are off. Matches become unverified findings,
  worded from the reviewed catalog rather than from tool output.
- Live tool runs refuse to start unless the worker verifies the lock first. `nightfall-worker --check` reports
  sandbox, template and binary status.
- Local development without the image: set `NIGHTFALL_NUCLEI_BIN`. Tool runs then refuse, because the sandbox
  isn't active. Use `NIGHTFALL_COLLECTOR_MODE=fixture` for canned results.
- Tests: `NIGHTFALL_TEST_NUCLEI_BIN=/path/to/nuclei pytest` adds a real-binary test through the proxy.
  `tests_sandbox/` runs under the real lock: see CI job `sandbox`, or
  `sudo ../infra/tools/egress-lock.sh .venv/bin/python -m pytest tests_sandbox`.

## Deploying on Render (free tier)

`render.yaml` describes a trial deployment: one free Docker web service (`infra/render/Dockerfile`) and one free
Postgres. The web server is the only public listener; the API, with the worker embedded, listens on
`127.0.0.1:8000` inside the container. Evidence content is stored in Postgres, under the same row-level security as
evidence rows.

At start-up, `infra/render/start.sh`:
- creates the API and worker database roles with generated passwords (needs `CREATEROLE`, not superuser) and
  refuses to start if either role could bypass row-level security;
- runs migrations;
- creates the first owner once, from `NIGHTFALL_BOOTSTRAP_OWNER_EMAIL` and `NIGHTFALL_ADMIN_PASSWORD`;
- removes the schema-owner credentials from the environment before starting the servers.

Limits: the free database expires after 30 days, the service sleeps when idle, and Nuclei runs are refused because
the tool sandbox needs `NET_ADMIN`. CI job `render-image` builds the image and starts it against a non-superuser
database user.

## AI agents (Phase 5)

Off by default (`NIGHTFALL_AI_PROVIDER=none`). To turn them on, set `NIGHTFALL_AI_PROVIDER=anthropic` and
`ANTHROPIC_API_KEY`; the model is `NIGHTFALL_AI_MODEL` (default `claude-opus-5-5`). Project data in the agents'
prompts is then sent to Anthropic.

- The agents:
  - Director splits an objective into tasks for the other agents.
  - Scout proposes collections.
  - Investigator explains an asset and proposes relationships.
  - Hunter proposes findings.
  - Guardian reviews each Hunter finding against its evidence.
  - Adversary proposes attack paths from recorded findings.
  - Analyst writes a labelled summary beside counts taken from the records.
- Agents are started from a project page. `/w/{ws}/agents` shows each agent's usage and recent tasks.
- Agents never run anything. The Tool Gateway (`api/nightfall/agents/gateway.py`) checks every proposal against
  the allowlist, scope and risk class. Low-risk collections still need an explicit human approval
  them, and agent findings are always hypotheses until a person decides.
- Collected content is passed only inside delimited, size-capped data blocks, never in system prompts.
- Every task records its model, prompt version, tokens and latency.
- Tests and e2e use `NIGHTFALL_AI_PROVIDER=fixture`: deterministic, labelled answers, allowed only with fixture
  collectors.
- Benchmark: `cd api && .venv/bin/python -m nightfall.agents.bench --provider anthropic` (costs money; see
  `docs/benchmarks/README.md`).

## BLACK OPS playbooks (Addendum 4)

Reviewed, versioned assessment playbooks inside BLACKSITE (`/w/{ws}/blacksite/ops`, owner only). A playbook isn't a
second execution path. Launching one writes an ordinary operation for each step, and every step then goes through
the same scope checks, approvals, worker re-checks and BLACK ICE ingest as any other collection.

- **Definitions are code** (`api/nightfall/blackops/catalog.py`): each step is a registered collector, and nothing
  else (no commands, scripts, URLs or parameters) can be expressed. Each definition is fingerprinted (SHA-256), and
  the fingerprints are pinned in `api/tests/golden/playbooks.json`, so changing one requires a version bump. A run
  records the version and hash it was launched with.
- **Flow:** preflight, then propose, approve, execute, verify, capture.
  - Preflight checks: enabled, your authorization, target in the active scope, execution profile, target type, tool
    availability, hourly budget, overlapping work.
  - Launch runs the preflight again on the server and is refused, with an audit event, if any check fails or the
    definition changed in between.
  - Approval is required above passive and for every lab run: an explicit decision with a two-factor check from
    the last 15 minutes. Under the single-operator policy (D1) the owner approves their own runs; under the
    two-person policy someone else must.
- **Profiles:**
  - A, live assessment: passive and read-only steps on authorized targets.
  - C, isolated lab: lab scopes only, run by the lab worker.
  - B, controlled validation: **not built**. It needs designated test identities, target-ownership verification and
    its own independent review.
- **Initial playbooks:** Surface Mapper, Service Fingerprinter, Web Exposure Audit, TLS Configuration Audit, HTTP
  Security Assessment. The last two use new low-risk collectors:
  - `tls`: one TLS handshake per protocol version plus one with certificate validation. No HTTP is sent.
  - `headers`: GET / over HTTPS and over HTTP. Cookie values and response bodies are never stored.
  - Their results feed BLACK ICE rules R7–R16, which reuse the existing check ids so that matching findings correlate.
- **Database:** `playbook_runs` is insert-only, and its profile must match its scope. An operation can join a run only
  when it is inserted, and only with that run's project, scope, target, requester and lab flag (trigger, migration
  0012).
- **Not yet built:** the BLACKSITE probe deck's loopback-only listener and step-up MFA (review §16.2). Lab
  exploitation and simulation playbooks (Addendum 4 §10, items 6–11) wait for validation and a security review.

## BLACKSITE security foundation (JANUS Phase 1)

- **Single operator (D1).** Each workspace has an approval policy. The default, `single_operator`, lets the workspace
  owner explicitly approve their own requests; nobody else may approve their own. `two_person` (the earlier rule) is
  kept for later. Both are enforced by the API and by a database trigger. Approving or rejecting an operation or
  run, launching a playbook and authorizing a scope need two-factor verified in the last 15 minutes
  (`POST /api/auth/mfa/verify` renews it; the web app prompts for the code).
- **Host-only BLACKSITE (D3).** `nightfall-blacksite` is a separate listener for the lab machine. It is off unless
  `NIGHTFALL_BLACKSITE_ENABLED=true`, refuses to start on the hosted platform, binds `127.0.0.1`, checks every
  request's socket peer and `Host`, and is reached through an SSH tunnel. It connects as `nightfall_blacksite`,
  a database role confined to lab records that can add audit events but never change them. Every workspace
  request needs the owner, fresh two-factor, and is audited.
- **Lab boundary.** Lab operations and lab playbook runs are created, approved and cancelled only through BLACKSITE.
  The hosted app (Vercel) can still read lab results; the database refuses it anything more.
- **Probe deck (Phase 2, lab only).** `POST /api/workspaces/{ws}/blacksite/probes` on the BLACKSITE listener:
  HTTP, TCP-connect or TLS probes against a registered lab asset, within the scope entry's allowed ports, rate and
  daily budget; replay and compare. State-changing HTTP methods are moderate risk, lab only, and need an explicit
  confirmation. The operator console is at `http://127.0.0.1:8443/` through the tunnel. See
  `docs/blacksite-deployment.md`.
- **Review gate (D4).** BLACKSITE refuses lab execution until `NIGHTFALL_BLACKSITE_REVIEW_REF` names the recorded
  independent review. That is an attestation by the operator, not proof a review happened; tests and self-review
  don't count.
