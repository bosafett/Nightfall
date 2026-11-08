# SHIELD v1 and AEGIS overview: monitoring your own assets (design for review)

Status: **approved by the owner 2026-11-08 (all §11 decisions as recommended); v1 built (migration 0021).** §12 lists
how the build differs from this text. Original status: design only. The owner's decisions on the questions it rests on are
recorded in §1. SHIELD's modules stay "Planned" labels in the sidebar until a version of this is approved and built.

## 1. Decisions this design is built on (owner, 2026-11-08)

1. **Where scheduled runs happen:** Vercel Cron, using the hosted platform's existing on-demand worker (option A).
   A self-hosted scheduler (option B) can be added later without a redesign.
2. **Authorization for repeat runs:** a standing authorization, approved by the owner with fresh two-factor, valid
   for at most 30 days, renewable, and covering only passive and low-risk checks.
3. **What v1 monitors:**
   - certificate expiry and TLS changes;
   - security headers getting worse;
   - new subdomains in certificate-transparency logs;
   - DNS record changes;
   - remediated findings that come back.
4. **Alerts:** in-app only, with no external notification service.

## 2. What SHIELD v1 is, and isn't

Addendum 5 describes SHIELD as defensive operations: AEGIS overview, monitoring, alerts and detection, threat hunting,
countermeasures, incident response, recovery and verification.

**v1 builds three modules:**
- **AEGIS Overview:** monitoring health, open alerts and authorizations close to expiry, on one page.
- **Monitoring:** the schedules, their standing authorizations and their run history.
- **Alerts & Detection:** alerts raised by comparing each run with the previous one, which a person acknowledges and
  resolves.

**v1 does not build** threat hunting, countermeasures, incident response or recovery. They stay "Planned".
- Countermeasures in particular stay **recommendation-only**: AEGIS shows the fix for each alert as text and never
  executes anything.
- Addendum 5 forbids agents disabling accounts, changing firewalls or modifying infrastructure, and there are no
  integrations.

All monitoring targets the organization's **own registered assets in an authorized scope**. SHIELD never watches
anything that isn't in scope.

## 3. How a scheduled run works

### 3.1 The cron call (already deployed)

`vercel.json` already has one daily cron job: `POST /api/internal/worker/drain` at 04:17 UTC. The platform calls it
with `Authorization: Bearer <CRON_SECRET>`, and the endpoint refuses anything else.

v1 extends that same endpoint. It **first enqueues the monitor runs that are due**, then drains the queue as it does
today.
- No new cron job and, as far as the build can tell, **no change to `vercel.json`**. If the build finds a change is
  needed after all (e.g. a second time of day), that's a deployment change and it will ask first.
- On Vercel's Hobby plan cron runs at most once a day and not at an exact minute. That suits daily monitoring.

### 3.2 Throughput on the hosted platform

The scheduled call has about 25 seconds and handles a few jobs. Whatever doesn't fit stays queued, and is processed
by the drains the app already triggers when people use it, or by the next daily call.

To keep that honest, v1 caps each workspace at **30 scheduled checks per day** (target × check). A schedule that would
exceed the cap can't be authorized. The AEGIS overview shows queued checks that haven't run, and how late they are,
so a delay never looks like "all clear". A self-hosted scheduler (option B) can lift the cap later.

### 3.3 Enqueueing (CONTROL)

For each **active, unexpired** standing authorization whose last run is at least 20 hours old, and for each target and
check it covers, the run creates an ordinary operation:
- pinned to the scope version the authorization names;
- marked with the authorization's id;
- requested by the owner who authorized the schedule (recorded as automated, so CHRONICLE says "scheduled by …").

It's skipped and recorded, not queued, when:
- the scope version is no longer active, which ends the authorization automatically;
- the target was excluded, or is no longer in scope;
- the authorization was revoked or has expired.

### 3.4 The worker check (CONTROL)

Today a low-risk operation needs an approval row. v1 adds exactly one other way to satisfy that: a **valid standing
authorization**.

The worker accepts it only when all of these hold, at the moment it runs:
- it names this operation's scope version, target and tool;
- it isn't revoked or expired;
- the tool is passive or low risk;
- the operation isn't a lab, Profile B or playbook operation.

Otherwise the operation is denied, with the reason. An approval is never fabricated or copied to make this work.

## 4. Standing authorizations

- **Owner only.** Created, renewed and revoked by the workspace owner with fresh two-factor (new permission
  `monitors.manage`), under the single-operator policy. Agents have no route to them.
- **Contents:**
  - project and pinned scope version;
  - targets: hosts or domains from that scope, at most 20;
  - checks, from this fixed list:

    | Check | Risk | Tool |
    |---|---|---|
    | Certificate-transparency names | passive | `ct` |
    | DNS records | passive | `dns` |
    | TLS configuration | low | `tls` |
    | Security headers | low | `headers` |

  - cadence: daily in v1;
  - `authorized_by`, `authorized_at`, `expires_at` (at most 30 days later), `revoked_at` and a reason.
- **Renewal** creates a new authorization with a new expiry, and the old one ends. Nothing is extended silently.
- **Expiry and scope changes:** at 7 days before expiry the AEGIS overview and the alerts page say so, and an alert
  is raised at expiry. A new scope version ends every authorization pinned to the old one.
- **Records:** every create, renew, revoke and automatic end is an audit event. The authorizations themselves are
  insert-only apart from the revoke columns, enforced by the database as for ownership claims.

## 5. Detection: alerts from comparing runs

After each scheduled operation succeeds, its result is compared with the **previous successful result of the same
authorization, target and check**. A rule raises an alert only for a real difference, or a threshold crossed:

| Alert | Raised when | Severity |
|---|---|---|
| `cert.expiring` | the certificate expires within 21 days (14 → high, 7 → critical) | medium/high/critical |
| `cert.changed` | a different certificate (fingerprint) is served | info |
| `tls.weakened` | a protocol or cipher is accepted that wasn't before, or validation now fails | high |
| `headers.regressed` | a security-header check fails that passed last time | medium |
| `ct.new_names` | names under the domain appear in certificate logs that weren't seen before | info (high if outside scope) |
| `dns.changed` | A, AAAA, CNAME, MX or NS records differ (TXT changes are ignored, as too noisy) | low |
| `finding.reopened` | BLACK ICE reopens a finding someone had marked remediated | high |

- **Rules are deterministic code**, versioned like the finding rules (`alerts/2026.11-1`), with golden-file tests.
- **The first run is a baseline.** It raises no change alerts, only threshold alerts such as expiry.
- **Alerts link to evidence.** Each points to the evidence of both runs and to any finding. Alerts never change
  findings: a person decides.
- **Lifecycle:** an alert is **open**, then **acknowledged** (someone is looking), then **resolved** (with a note).
  The same unresolved alert isn't raised twice; its "last seen" date is updated instead.
- **AEGIS recommendation:** each alert kind has a fixed, reviewed recommendation, e.g. "Renew the certificate and
  automate renewal". It's shown with the alert. Nothing is executed.

## 6. Data model (one migration; nothing written yet)

- **`monitor_authorizations`:**
  - workspace, project, scope version, targets (text[]), checks (text[]), cadence;
  - authorized by and at, expires at, revoked by, at and reason, ended reason;
  - RLS by workspace; the app may insert and update only the revoke and end columns, through a trigger;
  - CHECKs: expires at most 30 days after authorization; checks ⊆ the fixed list; at most 20 targets.
- **`operations.monitor_authorization_id`:** set only at insert. A trigger requires the operation's scope, target and
  tool to match the authorization, and refuses it for lab or playbook operations.
- **`alerts`:**
  - workspace, project, authorization, kind, severity, title, detail, target;
  - the two evidence ids, a finding id, first and last seen, state, acknowledged and resolved by, at and note;
  - written by the worker; people change only the state columns;
  - RLS by workspace; nobody deletes.
- **Audit and history:** `monitor.*` and `alert.*` audit events carry the project id, so CHRONICLE shows them.

## 7. UI

- **SHIELD → AEGIS Overview:**
  - open alerts by severity;
  - checks that ran today, and checks queued and how late they are;
  - authorizations expiring within 7 days;
  - the last scheduled run;
  - and, plainly, what isn't monitored.
- **SHIELD → Monitoring:** authorizations per project. The owner creates, renews and revokes them, choosing targets
  from the active scope and checks from the fixed list. Each shows its run history.
- **SHIELD → Alerts & Detection:** a filterable list with acknowledge and resolve, plus links to the evidence, the
  finding and the asset.
- **Sidebar:** an open-alerts count next to SHIELD.
- **Still "Planned":** threat hunting, countermeasures, incident response, recovery and verification.

## 8. Threats and mitigations

| Threat | Mitigation |
|---|---|
| Monitoring becomes a way around approvals | Standing authorizations are owner-only with fresh two-factor, expire within 30 days, cover passive and low-risk checks only, and are re-checked by the worker at every run against the pinned scope |
| The cron endpoint is abused | Bearer secret (existing); the endpoint only enqueues what valid authorizations already allow and drains; it takes no input |
| Monitoring something not owned | Targets come only from the pinned, authorized scope; a scope change ends the authorization |
| "All clear" when nothing ran | Overdue checks are shown on the overview; a failed or denied scheduled check raises a `monitor.failed` alert |
| Alert noise hides real problems | Baselines; TXT records ignored; one open alert per condition with "last seen"; severities per rule |
| An agent acting on alerts | Agents may summarize alerts (once AI is on) but have no route to authorizations, operations or alert state |

## 9. Tests required

- **Authorizations:** created and renewed only by the owner with fresh two-factor; expiry over 30 days, unknown
  checks, more than 20 targets or out-of-scope targets refused; revoke and automatic end at a scope change.
- **Enqueueing:** idempotent (two cron calls in a day enqueue once); skips expired, revoked or out-of-scope entries
  with the reason; per-day cap.
- **Worker:** accepts a valid authorization; refuses an expired, revoked or mismatched one, and lab, Profile B or
  playbook use. An approval row is never created.
- **Alerts:** each rule against golden pairs of results; first-run baseline; de-duplication; lifecycle permissions.
- **Cron endpoint:** refuses without the secret.
- **End to end:** authorize, run the cron, worker, a changed fixture result, an alert, acknowledge, resolve.

## 10. Build order once approved

1. Migration, authorizations (API and Monitoring page), and the CONTROL changes to the cron endpoint and the worker.
2. The detection rules and alerts (API and Alerts page).
3. The AEGIS Overview and the sidebar count.
4. Later, separately: a self-hosted scheduler (option B), NEXUS SHIELD steps, email alerts if wanted.

Effort: about the size of NEXUS v1. One migration. No paid services and no new external services.

## 11. Owner decisions needed

1. **Approve this design for review**, or change it.
2. **Daily cap:** 30 scheduled checks per workspace per day on the hosted platform (recommended), or another number.
3. **Certificate-expiry thresholds:** 21, 14 and 7 days (recommended), or other values.
4. **New CT names outside scope:** raise them as **high**, since they may be look-alike or shadow domains (recommended),
   or as info.

## 12. As built (2026-11-08, migration 0021)

- **Decisions:** all four §11 decisions as recommended: approved; 30 checks a day per workspace; certificate warnings at
  21, 14 and 7 days; new out-of-scope CT names raised as high.
- **Code:**
  - `api/nightfall/shield/`: `rules.py` (detection rules, `alerts/2026.11-1`), `control.py` (the worker's
    standing-authorization check), `alerts.py` (raising and de-duplicating alerts), `scheduler.py` (the daily run)
    and `routes.py` (API).
  - The pages are SHIELD → AEGIS Overview, Monitoring, and Alerts & Detection, plus an open-alerts count on the
    sidebar.
- **Cron:** the existing daily call (`/api/internal/worker/drain`, bearer secret) now queues the due checks first,
  then drains. `vercel.json` didn't change.
- **Targets** are hostnames from the active, non-lab scope; IP-address targets aren't offered in v1.
- **First runs:** a check's first run is a baseline. Only the certificate-expiry threshold can fire on it.
- **Failures:** a failed or refused scheduled check raises `monitor.failed`. An authorization that expires, or whose
  scope version changes, is ended by the scheduler and raises `monitor.ended`. `monitor.expiring` is raised in the
  last 7 days.
- **Not built:** the `headers.regressed` rule is tested against stored results rather than live header runs, and the
  CT rule against a stub scope check. Both use the same comparison code the worker runs.
