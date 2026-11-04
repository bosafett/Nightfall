# NIGHTFALL

Adversarial intelligence workbench by Digital Raccoon Engineering (DRE).

Use is limited to targets you are explicitly authorized to assess.

**Status:** Phase 2 (Command Center) on top of Phase 1 — sign-in with two-factor, workspaces and roles,
organizations and projects, audit log, app shell, Command Center with live counts and the intelligence graph. See
[`docs/PHASE0_ARCHITECTURE_REVIEW.md`](docs/PHASE0_ARCHITECTURE_REVIEW.md) for the approved architecture and roadmap.

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
