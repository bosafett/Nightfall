# NIGHTFALL isolated lab: Windows setup

The lab is where riskier tests run against practice apps you control. Nothing in it can reach the internet,
and nothing on the internet can reach it. Your machine only connects **outward**, to the NIGHTFALL database,
to pick up lab jobs. You open no ports.

```
NIGHTFALL (Vercel) ─▶ database (Neon) ◀─ lab worker ─▶ lab-net (no internet) ─▶ practice apps
```

## What you need

- **Windows 10 or 11** with virtualization enabled.
- **Docker Desktop** using the WSL 2 backend. That's the default on install.
- About **4 GB of free RAM** and **5 GB of disk**.

## One-time setup (about 15 minutes)

1. **Install Docker Desktop.** Download it from docker.com, install, restart if asked, and open it once so it
   finishes starting.
2. **Get the code.** Either install Git for Windows and run
   `git clone https://github.com/bosafett/Nightfall`, or download the repository as a ZIP from GitHub and
   unzip it.
3. **Create the lab password.** In PowerShell:
   ```powershell
   $b = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); ($b | ForEach-Object { $_.ToString('x2') }) -join ''
   ```
   Copy the 48-character result. It only contains 0–9 and a–f, so it's safe in a connection string.
> **Before step 4:** make sure the live site is running a version with migration 0011, which confines the lab
> account to lab data (review finding F1). The Vercel runtime log shows
> `Running upgrade 0010 -> 0011` once, after that version deploys.

4. **Tell NIGHTFALL about it.** In Vercel, open Project → Settings → Environment Variables and add
   `NIGHTFALL_LAB_WORKER_DB_PASSWORD` with that value. Then redeploy (Deployments → ⋯ → Redeploy). On its next
   start, NIGHTFALL turns on the lab worker's login. Until then the lab role exists but can't log in.
5. **Fill in the lab settings.** In the repository folder, go to `infra\lab`, copy `lab.env.example` to
   `lab.env`, and fill in:
   - `DB_HOST`: Vercel → Environment Variables → `PGHOST_UNPOOLED`. It looks like `ep-….neon.tech`.
   - `LAB_DB_PASSWORD`: the same value as in step 4.
6. **Start the lab.** In PowerShell, in the `infra\lab` folder:
   ```powershell
   docker compose --env-file lab.env up -d --build
   ```
   The first build takes a few minutes.

## Check that it's sealed (do this once)

Run each command in PowerShell from `infra\lab` and compare the result:

| Check | Command | Expected |
|---|---|---|
| The worker is running in lab mode | `docker compose --env-file lab.env logs lab-worker` | `egress-lock: lab mode …` and `LAB WORKER: lab operations only` (never `LAB WORKER REFUSED TO START`) |
| The tools are ready | `docker compose --env-file lab.env exec lab-worker nightfall-worker --check` | every line starts with `ok` |
| The practice app is up, inside the lab | `docker run --rm --network nightfall-lab_lab-net curlimages/curl:8.11.1 -s -o /dev/null -w "%{http_code}" http://172.30.99.10/` | `200` |
| The lab has no internet | `docker run --rm --network nightfall-lab_lab-net curlimages/curl:8.11.1 -s -m 5 https://example.com` | fails (timeout or "could not resolve") |
| Nothing is published | `docker compose --env-file lab.env ps` | no `0.0.0.0:` ports listed |

If any check doesn't match, stop the lab (`docker compose --env-file lab.env down`) and send me the output.

## The BLACKSITE console (same machine)

Lab work is requested, approved and launched only from BLACKSITE, a small console that runs on this machine and
listens on `127.0.0.1:8443`, so only this machine can open it. Background:
`docs/blacksite-deployment.md`.

1. **Turn on its database login.** Generate another password (same PowerShell one-liner as step 3). In Vercel, add it
   as `NIGHTFALL_BLACKSITE_DB_PASSWORD`, then redeploy.
2. **Install Python 3.13** if you don't have it: `winget install Python.Python.3.13`.
3. **Fill in the settings.** In `infra\lab`, copy `blacksite.env.example` to `blacksite.env` and fill in:
   - the database URL, with that password and the same `DB_HOST` as in `lab.env`;
   - `NIGHTFALL_SECRET_KEY`: the **same value** as in Vercel (Environment Variables → `NIGHTFALL_SECRET_KEY`). It's
     needed so your two-factor code works here. Treat it like a password.
4. **Start it:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start-blacksite.ps1
   ```
   The first run sets up Python (a few minutes). It prints `BLACKSITE REFUSED TO START: …` and stops if a check fails.
   Send me that line if it does.
5. **Open** `http://127.0.0.1:8443/` on this machine and sign in with your JANUS email, password and authenticator
   code. The status line shows whether lab execution is on, and which review switched it on.

## Switching lab execution on

Out of the box everything here is **off**: the lab worker and console run, but refuse to execute lab work. Each
switch needs a recorded review (see `docs/reviews/packets/`). While you're the only person on the project, you can
use the temporary self-review mode:

1. Do the self-review with the packet (BLACKSITE first) and save it as
   `docs/reviews/<date>-blacksite-self-review.md`.
2. Set the **same values** in both `blacksite.env` and `lab.env`:

   | `blacksite.env` | `lab.env` | Value |
   |---|---|---|
   | `NIGHTFALL_SELF_REVIEW_UNTIL` | `SELF_REVIEW_UNTIL` | a date at most 90 days ahead, e.g. `2027-01-31` |
   | `NIGHTFALL_BLACKSITE_REVIEW_REF` | `BLACKSITE_REVIEW_REF` | `SELF:<date> owner, docs/reviews/<file>` |
   | (already `true`) | `BLACKSITE_ENABLED` | `true` |
   | `NIGHTFALL_LAB_PACK1_REVIEW_REF` | `LAB_PACK1_REVIEW_REF` | only after its own self-review (packet 2) |

3. Restart both: Ctrl+C and run `start-blacksite.ps1` again, then
   `docker compose --env-file lab.env up -d`.

JANUS shows "self-review, NOT independent" wherever this is in effect, and records it on every lab run. After the
date passes, lab execution switches itself off again. With an independent reviewer later, use their reference
(without `SELF:`) instead.

## Using the lab in NIGHTFALL

1. **Create a lab scope.** In a project, start a new scope version and switch it to **Lab**. Add the target
   **IP** `172.30.99.10` (Juice Shop). Lab scopes accept only addresses inside `172.30.99.0/24`. Hostnames
   and outside addresses are refused, and normal scopes can't name lab addresses. Authorize it.
2. **Request a run.** Request **Technology identification** or the **curated checks** on `172.30.99.10`.
   Every lab run waits for an explicit approval in BLACKSITE (under the single-operator policy, you approve your own,
   with a fresh two-factor code).
3. **What happens next.** Once approved, your lab machine picks it up within seconds. Lab approvals are good
   for 24 hours: if the lab machine is off longer than that, the job is refused and needs a new request. Its results are stored
   as **lab (simulation) evidence** and kept apart from real-world results.

The normal NIGHTFALL worker on Vercel never sees lab jobs, and the lab worker never sees anything else. The
database enforces this with the lab worker's own restricted account.

## Lab tool pack 1 (known-weakness scan)

The lab worker image already contains the pack: 5,566 reviewed Nuclei templates, each checked against its pinned hash
before every run. It stays **unavailable** until its own review is recorded.

1. Do the self-review with `docs/reviews/packets/2-lab-tool-pack-1.md`. The evidence is already collected in
   `docs/reviews/2026-11-09-lab-tool-pack-1-evidence.md`; you give the verdict and answers, and save it as
   `docs/reviews/<date>-lab-tool-pack-1-self-review.md`.
2. Set the reference in **both** files: `LAB_PACK1_REVIEW_REF` in `lab.env` and `NIGHTFALL_LAB_PACK1_REVIEW_REF` in
   `blacksite.env` (`SELF:<date> owner, docs/reviews/<file>`). Restart both.
3. In BLACKSITE, run **Known-weakness scan (lab)** on `172.30.99.10`. It runs three steps (CVE, configuration and
   default logins, technology), up to 30 minutes each. Matches become unverified **lab** findings.
4. Treat the practice app as disposable: after a pack run, recreate it with
   `docker compose --env-file lab.env up -d --force-recreate juice-shop`.

## WARPATH exercises (purple team)

WARPATH needs only BLACKSITE, so it works as soon as lab runs do.

1. **Plan** (JANUS, SWORD → WARPATH): create an exercise on a project with a lab scope, and add steps: a lab
   playbook, the lab target, an ATT&CK technique the playbook represents, and the detection you expect.
2. **Approve** the plan (owner, fresh two-factor). The plan is then frozen; changing it needs a new version.
3. **Run** (BLACKSITE console, WARPATH tab): start each step; it goes through the normal lab preflight and approval,
   and the lab worker runs it.
4. **Score** each step in JANUS: attack result, and whether it was detected. A step scored *missed* raises a SHIELD
   "detection gap" alert (*partly detected* raises a low one). With no detection tooling in the lab yet, expect
   *missed*: that's an honest starting point, not a failure.

## Everyday use

- Stop the lab: `docker compose --env-file lab.env down`. Start it: `docker compose --env-file lab.env up -d`.
- Lab jobs queue up while the lab is off and run when it's back.
- To turn the lab off for good, remove `NIGHTFALL_LAB_WORKER_DB_PASSWORD` from Vercel and redeploy. The
  lab account then can't log in.

## Practice apps

| App | License | Address |
|---|---|---|
| OWASP Juice Shop | MIT | `172.30.99.10` |

Other apps are added only after a license review, each on `lab-net` with a fixed address and no published
ports.
