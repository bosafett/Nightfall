# Self-hosted Profile B worker: Windows setup

Profile B (controlled validation) logs in to, and sends inert input to, **real applications you've proven you
control**, using designated test accounts. You request and approve runs in JANUS as usual. They **execute only on
this worker**, on your machine:

- It alone holds the private key that opens the sealed test credentials. JANUS (Vercel) can store a credential but
  never read it back.
- It alone picks up Profile B jobs. The hosted worker never does, and would refuse one if it did.
- Immediately before sending anything, it checks every gate again: the switch and review, fresh proof of control,
  active test identities for the target, and the approval's age.

It can run on the same machine as the lab, but it's separate from the lab: it reaches the internet, the lab worker
doesn't. Nothing is published; it only connects outward.

## What you need

- Docker Desktop (already installed for the lab), and this repository's `main`.
- A Python environment with `nightfall-admin`. The BLACKSITE setup's `api\.venv-blacksite` has it.

## One-time setup (about 15 minutes)

1. **Make the key pair.** In PowerShell, from the repository folder:
   ```powershell
   .\api\.venv-blacksite\Scripts\nightfall-admin.exe profile-b-keygen
   ```
   It prints a public key and a private key. Keep both for the next steps. **The private key never goes into
   Vercel**; JANUS refuses to start if it finds it there.
2. **Set the worker's database password.** Generate a password with the same PowerShell one-liner as the lab
   (`infra/lab/README.md`, step 3). In Vercel → Settings → Environment Variables, add it as
   `NIGHTFALL_WORKER_DB_PASSWORD` (Production). The hosted worker uses it too, from the next production start.
3. **Add the Profile B settings to Vercel** (Production):

   | Variable | Value |
   |---|---|
   | `NIGHTFALL_PROFILE_B_PUBLIC_KEY` | the public key from step 1 |
   | `NIGHTFALL_PROFILE_B_ENABLED` | `true` (only once the review is recorded; see below) |
   | `NIGHTFALL_PROFILE_B_REVIEW_REF` | `SELF:<date> owner, docs/reviews/<file>` (after the review) |
   | `NIGHTFALL_SELF_REVIEW_UNTIL` | the same date as on the lab machine, e.g. `2027-01-31` |

   Then redeploy production. Registering test identities needs only the public key.
4. **Fill in the worker's settings.** In `infra\profile-b`, copy `profile-b.env.example` to `profile-b.env`, and fill
   in `DB_HOST` (same as `lab.env`), `WORKER_DB_PASSWORD` (step 2), both keys (step 1), and the same switch, review
   reference and date as in Vercel.
5. **Start it:**
   ```powershell
   docker compose --env-file profile-b.env up -d --build
   ```
6. **Check it:**

   | Check | Command | Expected |
   |---|---|---|
   | Running as the Profile B worker | `docker compose --env-file profile-b.env logs profile-b-worker` | `PROFILE B WORKER: Profile B operations only` (never `REFUSED TO START`) |
   | Tool sandbox ready | `docker compose --env-file profile-b.env exec profile-b-worker nightfall-worker --check` | every line starts with `ok` |
   | JANUS sees it | JANUS → Audit → WATCHTOWER | **Profile B worker: online** |

## Switching Profile B on

Out of the box Profile B is **off**. It needs its review recorded (`docs/reviews/packets/3-profile-b.md`). While
you're the only person on the project, you can use the temporary self-review mode, as with BLACKSITE:

1. Do the self-review with packet 3 and save it as `docs/reviews/<date>-profile-b-self-review.md`. The packet asks
   for a run against a test application you own (check 2). Do it before switching on for anything else.
2. Set `PROFILE_B_ENABLED=true` and the `SELF:` reference **both** in Vercel (then redeploy) and in `profile-b.env`
   (then `docker compose --env-file profile-b.env up -d`).

JANUS shows "self-review, NOT independent" wherever this is in effect, and records it on every run.

## Running Profile B

1. **Prove control** of the target: in the project, add an ownership claim (DNS TXT record or a `/.well-known`
   file) and check it against the current scope version. A check must have passed in the last 24 hours.
2. **Register test identities** (owner only, fresh two-factor): in JANUS, BLACKSITE → BLACK OPS → Test identities. Use
   accounts created for testing that hold no real person's data. JANUS seals the credential to this worker's public
   key as it arrives, and can't read it back.
3. **Request the playbook** (Authentication configuration audit, Access control assessment, or Safe injection surface
   assessment). The preflight lists every gate, including "Self-hosted Profile B worker". Approve it with a fresh
   two-factor code; Profile B approvals expire after 24 hours.
4. This worker picks it up within seconds, re-checks everything, and runs it.

## Everyday use

- Stop: `docker compose --env-file profile-b.env down`. Start: `docker compose --env-file profile-b.env up -d`.
- While it's stopped, the preflight refuses new Profile B runs, and queued ones wait (until their approval expires).
- To switch Profile B off quickly: set `NIGHTFALL_PROFILE_B_ENABLED=false` in Vercel and redeploy, or just stop this
  worker. Either one is enough.
