# SHIELD v3: intrusion detection and response for the owner's own sites and machines (design for review)

Status: **approved by the owner 2026-11-17, all §9 decisions as recommended:** CrowdSec; the automatic tier of §4
under a standing response authorization the owner records; Vercel firewall changes person-approved; an automatic block
joins an open incident for that machine, otherwise it's an alert only. Build in the phases of §5. Requested 2026-11-17: "IDS and responses
for any intrusions on the sites I own and the hardware they run on, automated if we can so there's no lag time."

## 1. What would be protected, and what can be seen

| Asset | What runs it | What can be observed | What can be done about it |
|---|---|---|---|
| JANUS web app and API | Vercel (serverless) | JANUS's own audit trail: failed logins and two-factor (`auth.login_failed`, `auth.mfa_failed`), rate-limit hits, denied authorization and scope checks | Inside JANUS: revoke sessions and tokens, lock an account, block an address in the app. **There is no hardware to touch:** Vercel runs it |
| Vercel edge | Vercel | Vercel's firewall and its logs (if the plan includes them) | Vercel firewall rules and attack challenge mode, through the Vercel API |
| Database | Neon (managed) | Neon's own logs and settings, not visible to JANUS today | Neon's IP allow list and roles, in the Neon console |
| BLACKSITE lab machine, the Profile B worker host, and any other server the owner runs | the owner's hardware | Host logs (SSH and system auth, web server access logs, firewall drops) and network traffic, **only through a sensor installed on that machine** | That machine's own firewall (nftables), and nothing else |

JANUS today has no sensor on any machine and no log feeds, so none of this is observed yet. Customer systems are
**out of scope:** this design covers only assets the owner controls.

## 2. Recommendation: integrate a proven open-source IDS, don't write one

Writing detection for SSH brute force, web scanners and exploit attempts is a solved problem, and a homemade version
would be worse. The recommended engine is **CrowdSec** (free, open source, self-hosted, no paid tier needed):

- it reads host and web server logs, recognises scans, brute force and known exploit patterns with maintained rules;
- its **bouncers** apply decisions locally: the nftables bouncer blocks an address on that machine for a set time;
- it runs on the owner's machine, so a block takes effect in seconds, which is the "no lag time" the request asks
  for, and it keeps working if JANUS or the internet link to JANUS is down.

Alternatives: **Wazuh** (fuller host monitoring, file integrity and vulnerability inventory, but heavier: it wants
its own server) or **Suricata** (network IDS, needs to see traffic on the wire). Fail2ban works but has no shared
blocklists or web-attack rules.

**JANUS's part** is what a SIEM-lite does: collect each sensor's alerts and decisions, show them in SHIELD, open or
add to incidents, apply the response rules of §4 across machines, and keep the record in the audit trail.

## 3. Architecture

```
 owner's machine                                    JANUS (Vercel)
 ┌──────────────────────────────┐                   ┌─────────────────────────────┐
 │ logs → CrowdSec → decisions  │                   │ SHIELD: intrusion alerts,   │
 │            │                 │   outbound HTTPS  │ incidents, response rules,  │
 │            ▼                 │ ───────────────►  │ audit trail                 │
 │   nftables bouncer (local)   │   alerts, health  │                             │
 │                              │ ◄───────────────  │ approved blocks, allow list │
 │ janus-sensor (small, fixed)  │   (sensor polls)  └─────────────────────────────┘
 └──────────────────────────────┘
```

- **janus-sensor** is a small service, set up like the Profile B worker (`infra/profile-b/`): it reads CrowdSec's
  local API, sends alerts and a heartbeat to JANUS, and fetches decisions JANUS approved.
- **Outbound only.** JANUS never connects to the machine and exposes no endpoint that runs anything there. The sensor
  polls; nothing listens.
- **Fixed actions only:** the sensor can add or remove a CrowdSec decision (block an address or range for a time).
  It has no shell, runs no scripts and takes no other instruction from JANUS. This keeps the rule "no arbitrary
  shell execution, no public execution endpoints".
- **Each sensor has its own key**, registered by an admin, scoped to one machine, revocable from JANUS.

## 4. Response: what runs automatically and what waits for a person

Addendum 5 says: "No agent should independently disable accounts, change firewall configurations or modify production
infrastructure without the appropriate authorization." Automatic blocking is a firewall change, so it needs an
authorization recorded **by the owner, in advance**, the same way monitors run under a standing authorization. The
proposal, for decision 2:

| Tier | Actions | How |
|---|---|---|
| **Automatic, under a standing response authorization** | Block one address on the machine that saw it, for at most 4 hours (default 1); temporary lock of a JANUS account after repeated failed logins (already partly the rate limiter) | Deterministic rules only, never AI. The owner records the authorization: which machines, which actions, the longest block, the daily cap. It expires (90 days) and can be ended at once |
| **Proposed, a person approves** | Longer or range blocks; block on every machine; revoke all sessions of a user; Vercel firewall rules or attack challenge mode | An admin or owner approves in the incident, with fresh two-factor for anything on Vercel |
| **Never** | Deleting data, shutting down a machine or service, changing database or hosting settings beyond the firewall, anything against an address outside the owner's systems ("hacking back") | Not offered |

Safeguards on the automatic tier:

- **Allow list that can't be blocked:** the owner's own addresses, the BLACKSITE lab, Neon, Vercel, GitHub, and the
  JANUS sensor's own route. A rule that would block one of them is refused and raises an alert instead.
- **Caps:** at most N automatic blocks per machine per hour (default 50); beyond that, rules stop blocking and alert,
  so a flood or a bad rule can't lock everything out.
- **Every block expires**, is shown in SHIELD, and can be lifted by a person in one click; lifting is recorded.
- **Kill switch:** one setting ends automatic response everywhere; the sensors fall back to alert-only.
- **AI agents** may explain an alert or suggest a response, labelled as a suggestion. They can't trigger, approve or
  widen any response.
- **Every action**, automatic or approved, is an entry in the hash-chained audit trail and on the incident timeline.

## 5. Detection sources, in build order

1. **JANUS itself** (no sensor needed): repeated failed logins or two-factor for one account or from one address;
   one address trying many accounts; bursts of denied scope or authorization checks; a login just after a burst of
   failures. These become SHIELD alerts with the new kind `intrusion.*`.
   - **Already in place (automatic tier for JANUS itself):** 5 failed sign-ins lock an account for 15 minutes and
     20 lock an address, shared across Vercel instances through Postgres (`core/identity/throttle.py`); every
     mutating request is rate-limited per address. Phase 1 adds visibility and alerts, not new blocking.
   - **Gap found 2026-11-17, owner decision 5:** SHIELD alerts belong to a workspace and a project, but sign-in
     attacks happen before sign-in and belong to neither. The app's database role can't read those audit rows by
     design, and JANUS has no platform operator role. Options: **(a)** a signed-in user sees attacks on their own
     account, and workspace admins see attacks on their members, with no new privileged role (attempts on unknown
     emails stay in the audit trail only); **(b)** (a) plus a platform operator view, a new privileged role naming
     operator accounts in a setting and reading sign-in events through a narrow database function; **(c)** only
     the operator view. Recommended: (a) first, (b) later if needed. A new role that sees across workspaces is a
     change to the authorization model and needs its own review.
2. **Sensor on the BLACKSITE lab machine** (the owner already runs it): CrowdSec with the SSH, Linux and nftables
   collections.
3. **Sensor on any other server the owner runs**, including the Profile B worker host.
4. **Vercel firewall** events, if the plan exposes them, as alerts only; rules stay person-approved.

## 6. UI

- SHIELD → **Threat Hunting** stays planned. A new **Intrusion Detection** page: sensors and their health, recent
  alerts, active blocks with time left, and the response authorization with its limits.
- Intrusion alerts appear in the alert list and can open or join an incident (people open incidents today; decision
  4 asks whether automatic responses should open one).
- AEGIS Overview: sensors offline, blocks in the last 24 hours, the kill switch's state.

## 7. Threats and mitigations

| Threat | Mitigation |
|---|---|
| A stolen sensor key used to inject alerts or learn the allow list | One key per machine, revocable; alerts are data, never commands; the sensor fetches only decisions for its own machine |
| JANUS compromised and used to block the owner out | Allow list enforced on the sensor as well as in JANUS; caps; blocks expire; the owner can stop CrowdSec locally |
| A false positive blocks a real user | Short default blocks, one-click lift, caps, alert-only mode for new rules for their first week |
| An attacker floods logs to cause mass blocking | Per-hour cap, then alert-only |
| JANUS used as a remote shell | Fixed action set; no shell or script path; outbound-only sensor |
| Automation presented as stronger than it is | The UI says "blocked on <machine> until <time>" and never "threat neutralized" |

## 8. What this can't do (honest limits)

- It sees only what the sensors and JANUS's audit trail see. An intruder who gets in without tripping a rule isn't
  detected. It's a layer, not a guarantee.
- It can't put a sensor on Vercel or Neon; those are protected by their own settings and by account security (two
  factor on GitHub, Vercel, Neon and Anthropic).
- It doesn't cover customer systems.

## 9. Owner decisions needed

1. **Engine:** integrate CrowdSec (recommended), Wazuh, or build JANUS's own rules.
2. **Automatic response:** allow the automatic tier of §4 under a standing response authorization you record
   (recommended, with its safeguards); or everything person-approved (slower, minutes not seconds); or alert-only.
   This is a deliberate reading of Addendum 5's "appropriate authorization" and is yours to make.
3. **Vercel firewall:** person-approved changes through the API (recommended), recommendations only, or automatic.
   Automatic isn't recommended: it changes hosting configuration.
4. **Incidents:** should an automatic block open an incident, or only add to an open one (recommended: add to one
   if open, otherwise alert only, so a busy day doesn't create dozens)?

Effort: phase 1 (JANUS's own detection, no sensor) is about half the size of SHIELD v2 and needs one migration.
Phase 2 (sensor and response) is about the size of the Profile B worker. No paid services; the sensor is
self-hosted on machines you already run.

## 10. As built: phase 1 (2026-11-17, migration 0024)

- **Sign-in alerts** (`api/nightfall/shield/sign_in.py`, table `sign_in_alerts`), raised by the sign-in code for a
  known account only:
  - `signin.locked` (medium): the account was locked after repeated failed sign-ins;
  - `signin.password_known` (high): the correct password with a wrong two-factor code;
  - `signin.stepup_locked` (medium): a signed-in session failed the two-factor step-up repeatedly.
  One open alert per account and kind; repeats raise its count and keep the ten latest addresses.
- **Blocking is unchanged.** The existing throttles already lock an account or an address automatically for 15
  minutes. Phase 1 makes that visible; it adds no new blocking.
- **Who sees them (decision 5):** the account's own user (Account security) and the owners and admins of a
  workspace the user belongs to (SHIELD → Alerts & Detection). Only the account's user acknowledges. Attempts on
  unknown emails stay in the audit trail only.
- **Database:** written only through `nf_record_sign_in_alert`, which fixes each kind's severity; the app role has
  no INSERT and may update only the acknowledgment of its own user's alerts. Row-level security limits reads as
  above.
- **Not in phase 1:** the sensor and CrowdSec (phase 2), the standing response authorization, the Vercel firewall
  proposals, and linking sign-in alerts to incidents (incidents belong to a project; sign-in alerts don't).

## 11. Reconciling the "Active Defense & Counterintelligence" addendum (received 2026-11-17)

An addendum arrived framing SHIELD as a wider defensive-intelligence system across five divisions (AEGIS,
SENTINEL, COUNTERMEASURES, plus reuse of CHRONICLE/BLACK BOX/NEXUS) with three operating modes. Two notes before
the mapping:

- **It is defensive, and so are we.** The addendum repeats the same boundary this design already holds: no hacking
  back, no exploiting an attacker's systems, no malware, no denial-of-service, no pivoting outside authorized
  infrastructure, "attribution is not authorization," and AI may recommend but never execute. Nothing in it
  reopens strike-back, which stays refused.
- **The copy received was truncated** (it cuts off in §8, mid-sentence). The counterintelligence and deception
  material is therefore partial. It is taken here as **direction, not a finished spec** — the deception pieces get
  their own scoping before any build.

### 11.1 Terminology: the addendum's three modes are this design's §4 tiers

| Addendum mode | This design (§4) | Status |
|---|---|---|
| **WATCH** — observe, correlate, alert, recommend; no automatic change | alert-only | phase 1 built for JANUS's own sign-in signals |
| **GUARD** — narrow, pre-approved, reversible, time-limited automatic actions | **automatic tier, under the standing response authorization** (block one address on the machine that saw it, ≤4h, capped, allow-list protected, kill switch) | phase 2 |
| **COMMAND** — human-directed higher-impact response | **person-approved tier** (longer/range/all-machine blocks, session revocation, Vercel firewall with fresh 2FA) | phase 2+ |
| (the addendum's prohibited list) | **Never** tier | unchanged |

No weaker parallel approval system is introduced: COMMAND reuses the existing JANUS authorization model, as the
addendum itself requires.

### 11.2 The five divisions, against what exists

- **AEGIS (monitoring/detection):** SHIELD v2 monitors and phase-1 sign-in alerts already exist. The addendum's
  normalized event schema, separate event-time vs ingestion-time, source-reliability tracking and
  observed-fact-vs-inference labelling become part of phase 2's sensor ingestion. No assumed integrations: only
  CrowdSec on machines the owner runs, as already designed.
- **SENTINEL (investigation/intel):** incidents, the War Room, timelines and findings exist. New: an indicator
  store (IP, domain, URL, certificate fingerprint, file hash, user-agent, ATT&CK technique) with first/last-seen,
  source, confidence, expiry and false-positive correction, plus confidence labels on every assessment. This is
  **phase 3**; it adds tables but no internet-facing infrastructure.
- **COUNTERMEASURES (response):** the §4 tiers above. Every action keeps a target, action, reason, supporting
  incident, expected impact, authorization record, result and rollback — already the shape of the audit/incident
  trail.
- **CHRONICLE / BLACK BOX / NEXUS:** reuse, don't duplicate (audit trail, evidence store, workflows). The addendum
  agrees.
- **Counterintelligence / deception (honeypots, decoys, attacker profiling):** entirely new, and the only part that
  stands up new attacker-facing services. It is **phase 4** and is gated on its own explicit go-ahead and a scoping
  pass: decoys only on infrastructure the owner is authorized to operate, isolated from production with no route
  into it, never used to run code on a visitor, no plaintext passwords captured, with retention and access limits.

### 11.3 Updated phase plan

1. **Phase 1 — JANUS's own sign-in detection (built, migration 0024).** WATCH for sign-in signals.
2. **Phase 2 — CrowdSec sensor + GUARD.** Outbound-only sensor, standing response authorization, allow list, caps,
   kill switch, Intrusion Detection UI. Approved in §9. Migration held locally until approved for push.
3. **Phase 3 — SENTINEL indicator store.** Threat-intel repository, confidence labels, ATT&CK mapping, correlation
   into incidents. New tables; no new infrastructure.
4. **Phase 4 — deception / honeypots (gated).** Not started, not approved; needs its own scoping and an explicit
   decision because it means running new attacker-facing services.

### 11.4 Unchanged guardrails the addendum does not relax

No paid services and no new paid AI calls. AI agents explain and recommend only — they cannot execute a tool,
approve their own recommendation, change GUARD thresholds, or treat attacker-controlled text as instructions. No
scope expansion past the owner's own assets; customer systems remain out of scope. Migrations are held locally
until the owner approves the push, and production is unchanged by anything in this section.
