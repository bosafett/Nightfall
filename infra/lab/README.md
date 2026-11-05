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
   -join ((1..48) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
   ```
   Copy the 48-character result. It only contains 0–9 and a–f, so it's safe in a connection string.
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
| The worker is running in lab mode | `docker compose logs lab-worker` | `egress-lock: lab mode …` and `LAB WORKER: lab operations only` |
| The tools are ready | `docker compose exec lab-worker nightfall-worker --check` | every line starts with `ok` |
| The practice app is up, inside the lab | `docker run --rm --network nightfall-lab_lab-net curlimages/curl:8.11.1 -s -o NUL -w "%{http_code}" http://172.30.99.10/` | `200` |
| The lab has no internet | `docker run --rm --network nightfall-lab_lab-net curlimages/curl:8.11.1 -s -m 5 https://example.com` | fails (timeout or "could not resolve") |
| Nothing is published | `docker compose ps` | no `0.0.0.0:` ports listed |

If any check doesn't match, stop the lab (`docker compose down`) and send me the output.

## Using the lab in NIGHTFALL

1. **Create a lab scope.** In a project, start a new scope version and switch it to **Lab**. Add the target
   **IP** `172.30.99.10` (Juice Shop). Lab scopes accept only addresses inside `172.30.99.0/24`. Hostnames
   and outside addresses are refused, and normal scopes can't name lab addresses. Authorize it.
2. **Request a run.** Request **Technology identification** or the **curated checks** on `172.30.99.10`.
   Every lab run waits for a second person's approval, the same as a real target.
3. **What happens next.** Once approved, your lab machine picks it up within seconds. Its results are stored
   as **lab (simulation) evidence** and kept apart from real-world results.

The normal NIGHTFALL worker on Vercel never sees lab jobs, and the lab worker never sees anything else. The
database enforces this with the lab worker's own restricted account.

## Everyday use

- Stop the lab: `docker compose down`. Start it: `docker compose --env-file lab.env up -d`.
- Lab jobs queue up while the lab is off and run when it's back.
- To turn the lab off for good, remove `NIGHTFALL_LAB_WORKER_DB_PASSWORD` from Vercel and redeploy. The
  lab account then can't log in.

## Practice apps

| App | License | Address |
|---|---|---|
| OWASP Juice Shop | MIT | `172.30.99.10` |

Other apps are added only after a license review, each on `lab-net` with a fixed address and no published
ports.
