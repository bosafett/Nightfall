# BLACKSITE deployment (JANUS Phase 1)

BLACKSITE is the host-only control point for lab work. It runs on the lab machine, never on Vercel. Owner decisions
D1 (single operator), D3 (host-only) and D4 (independent review) are in `docs/PHASE0_ARCHITECTURE_REVIEW.md` §17.

> **Not enabled yet.** Phase 1 is implemented and tested, but not independently reviewed or deployed. Leave
> `NIGHTFALL_BLACKSITE_ENABLED` unset until the review in `docs/reviews/2026-11-blacksite-authorization-model.md` §9 is
> signed by someone who didn't build it.

## Network architecture

```
 Operator's laptop                       Lab machine (home)                          Neon (Postgres)
 ┌──────────────┐  ssh -L 8443:127.0.0.1:8443  ┌───────────────────────────┐  TLS, outbound only  ┌──────────┐
 │ browser/curl │ ───────────────────────────▶ │ nightfall-blacksite        │ ───────────────────▶ │ database │
 │ 127.0.0.1:8443│   (key-based SSH, no other   │  bound to 127.0.0.1:8443   │  role                │          │
 └──────────────┘    ports exposed)            │  as nightfall_blacksite    │  nightfall_blacksite │          │
                                               │ lab-worker (lab-net only)  │ ───────────────────▶ │          │
                                               └───────────────────────────┘                      └──────────┘
 Vercel (public app): reads lab results from the database; can't create, approve or cancel lab work.
```

What each layer enforces:

| Layer | Control | Where |
|---|---|---|
| Flag | `NIGHTFALL_BLACKSITE_ENABLED=true` required; refused together with `NIGHTFALL_ON_DEMAND_WORKER` (hosted). Disabled = every request answers 404. | `config.py`, `blacksite/app.py` |
| Network | Binds `127.0.0.1`. Each request's **socket** peer must be in `NIGHTFALL_BLACKSITE_ALLOWED_PEERS` (default loopback) and `Host` must be `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>`. Proxy headers are off; `X-Forwarded-For` and `Forwarded` are ignored. Mutations need the loopback `Origin`. | `blacksite/app.py` |
| Identity | Signed-in **owner**, two-factor verified in the last 15 minutes (server-side session time), on every workspace route. Renew with `POST /api/auth/mfa/verify`. | `core/tenancy/deps.py` |
| Database | Role `nightfall_blacksite`: lab records only, audit insert-only, no evidence content, invites, agent tasks or membership changes. Start-up refuses any other role, or one that is superuser or bypasses RLS. | migration 0013 |
| Review | Lab execution (request, approve, launch) refused until `NIGHTFALL_BLACKSITE_REVIEW_REF` is set. | `blacksite/boundary.py` |
| Audit | `blacksite.access` per allowed request (fails the request if it can't be written), `blacksite.network_denied`, `authz.denied` with reason, `auth.mfa_failed`, `auth.mfa_step_up`, approvals, operation lifecycle, logouts. | `audit_events` |

## Provisioning

1. **Database role.** Migration 0013 creates `nightfall_blacksite` without login. To enable login, add
   `NIGHTFALL_BLACKSITE_DB_PASSWORD` (random, at least 24 characters, e.g. `openssl rand -base64 33`) to the
   Vercel project's environment and redeploy. Bootstrap then sets the password and refuses to start if the role
   could bypass row-level security. Locally, `infra/postgres/init.sql` creates it with a dev password.
2. **Lab machine.** Install the API (same steps as `README.md` → Local development, Python 3.13) and set:

   ```bash
   NIGHTFALL_DATABASE_URL=postgresql://nightfall_blacksite:<password>@<neon-host>/neondb?sslmode=require
   NIGHTFALL_SECRET_KEY=<same value as the hosted app>
   NIGHTFALL_PUBLIC_ORIGIN=http://127.0.0.1:8443
   NIGHTFALL_COOKIE_SECURE=false
   NIGHTFALL_BLACKSITE_ENABLED=true
   NIGHTFALL_BLACKSITE_PORT=8443
   # NIGHTFALL_BLACKSITE_REVIEW_REF=docs/reviews/<signed review> (only after sign-off)
   ```

   The secret key must match the hosted app's so two-factor secrets decrypt. Never put the owner (migration)
   credentials on the lab machine.
3. **Start:** `nightfall-blacksite`. It prints `BLACKSITE REFUSED TO START: …` and exits if any check fails.
4. **SSH.** Enable the lab machine's SSH server with key authentication only (no passwords), don't forward port
   8443 on the router, and keep the firewall closed to everything but SSH (or reach SSH through your VPN only).

**Container option.** If you run it in Docker instead, bind inside the container with
`NIGHTFALL_BLACKSITE_BIND=0.0.0.0`, publish the port to the host's loopback only (`127.0.0.1:8443:8443`), and set
`NIGHTFALL_BLACKSITE_ALLOWED_PEERS` to the address Docker shows as the peer (the refusal log names it). Start-up
refuses a non-loopback bind without an explicit peer list. The native setup above is simpler and is the tested one.

## Using it

```bash
ssh -N -L 8443:127.0.0.1:8443 you@lab-machine
```

Then sign in at `http://127.0.0.1:8443/api/auth/login` (email, password, authenticator code) and check
`GET /api/workspaces/<ws>/blacksite/status`. BLACKSITE is API only for now.

### Probe deck (Phase 2, lab only)

Register the lab address as an asset in the project's organization (hosted app, Target Registry), and give the lab
scope's target entry its probe bounds when you add it (`allowed_ports`, `max_rps`, `daily_budget`; defaults 80/443,
1 per second, 200 a day). Then, through the tunnel:

```bash
curl -s -b jar -c jar -H 'Origin: http://127.0.0.1:8443' -H 'Content-Type: application/json' \
  http://127.0.0.1:8443/api/workspaces/<ws>/blacksite/probes \
  -d '{"project_id":"<project>","asset_id":"<asset>","approve":true,
       "spec":{"type":"http","scheme":"http","method":"GET","path":"/"}}'
```

- `type`: `http` (method, path, port, headers, body), `tcp` (`ports`, at most 10) or `tls` (`port`).
- `approve: true` approves it in the same request (single operator). POST, PUT, PATCH and DELETE also need
  `"confirm_state_change": true`.
- History: `GET …/blacksite/probes`; replay: `POST …/blacksite/probes/<id>/replay`; compare:
  `GET …/blacksite/probes/compare?a=<id>&b=<id>`. Results are in the operation's evidence.

## Rotation

- **Database password:** set a new `NIGHTFALL_BLACKSITE_DB_PASSWORD` in Vercel, redeploy (bootstrap updates the role),
  then update `NIGHTFALL_DATABASE_URL` on the lab machine and restart `nightfall-blacksite`.
- **Sessions:** `POST /api/auth/logout-all` (hosted app or BLACKSITE) revokes every session of your account.
- **Two-factor:** `nightfall-admin reset-mfa --email …` on a host with the migration credential, then re-enrol.

## Recovery and shutdown

- **Turn BLACKSITE off:** stop the process and unset `NIGHTFALL_BLACKSITE_ENABLED`. To remove database access as well,
  delete `NIGHTFALL_BLACKSITE_DB_PASSWORD` from Vercel and redeploy (the role becomes NOLOGIN).
- **Suspected compromise of the lab machine:** do both of the above, run `logout-all`, rotate the hosted app's
  `NIGHTFALL_SECRET_KEY` only if you believe it leaked (that forces everyone to re-enrol two-factor), and review
  `audit_events` for `blacksite.*` and `authz.denied` entries.
- **Lab work stuck awaiting approval:** cancel it from BLACKSITE (`POST …/operations/<id>/cancel` or
  `…/blackops/runs/<id>/cancel`). The hosted app can't, by design.
