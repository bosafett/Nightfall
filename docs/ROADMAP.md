# JANUS roadmap

JANUS (internal name NIGHTFALL) is a single-operator security-operations platform: a FastAPI + SQLAlchemy +
Postgres API, a Next.js web app, deployed on Vercel with a Neon database, plus self-hosted workers the owner runs
on their own machines (the lab, Profile B, and — new in SHIELD v3 — intrusion sensors).

This roadmap is kept honest: a line is **Delivered** only if it is built and tested in the repository, **In
progress** only while it is being built, and **Planned** otherwise. Nothing here claims a capability that does not
exist. Design detail lives in `docs/designs/`; this file is the map over the top of them.

_Last updated 2026-11-17._

## Principles that bound the whole roadmap

- **Authorized assets only.** JANUS assesses and defends targets the operator is explicitly authorized to touch.
  Customer systems and anything outside the owner's own infrastructure stay out of scope. Attribution is not
  authorization.
- **Defensive, not offensive.** No hacking back, no exploiting an attacker's systems, no malware, no
  denial-of-service, no pivoting outside authorized infrastructure. This is fixed and does not move.
- **A human authorizes consequential actions.** AI agents may explain and recommend; deterministic code decides,
  and a person approves anything that changes infrastructure. An agent cannot grant itself permission.
- **No paid services added silently.** No paid hosting requirement, no provider migration, and no paid AI calls
  unless the owner turns them on themselves. The public repository and the current Vercel/Neon deployment are
  preserved.
- **Migrations are held.** A commit that carries a database migration is not pushed — not even to the branch —
  until the owner approves it.

## Where JANUS is today (Delivered)

| Area | What it does | State |
|---|---|---|
| **Core / identity** (Phase 1) | Workspaces with Postgres row-level security, opaque session tokens, two-factor for owner/admin/operator, append-only audit log | Delivered, deployed |
| **Scope & recon** (Phase 3) | Versioned, authorized scopes; passive collectors (CT, DNS); approval-gated active probes | Delivered, deployed |
| **Findings & reports** (Phase 4) | Rule findings (human-validated only), attack paths as hypotheses, frozen SHA-256 reports | Delivered, deployed |
| **Third-party tools** (Phase 4b) | Nuclei and other tools in a network-locked worker sandbox, GET-only reviewed templates | Delivered, deployed |
| **AI agents** (Phase 5) | Agents propose; a deterministic gateway decides. Off by default; off entirely on the hosted deploy | Delivered (off) |
| **BLACK ICE / BLACK OPS** | First five playbooks; Profile B controlled-validation worker (off by default, self-hosted key) | Delivered (Profile B off) |
| **CHRONICLE / BLACK BOX / NEXUS** | Audit timeline, content-addressed evidence with retention, approval/workflow engine | Delivered |
| **CONTROL / WATCHTOWER / Overview** | Shared execution-governance rules; health of JANUS from real backend state; operator overview | Delivered |
| **WARPATH** | Defensive exercises | Delivered |
| **SHIELD v1 — AEGIS** | Standing monitor authorizations; daily passive checks (CT, DNS, TLS, headers); alerts | Delivered, deployed |
| **SHIELD v2 — incidents** | Incident lifecycle (open→contained→recovering→closed), War Room, recovery & verification | Delivered, deployed |
| **SHIELD v3 phase 1 — sign-in alerts** | JANUS's own sign-in attack detection (lockouts, right-password/wrong-2FA, step-up lockouts), migration 0024 | Delivered, deployed |

Caveat carried from the README: JANUS Phase 1 / BLACKSITE is implemented and tested but **not independently
reviewed**; several review conditions (R-conditions) and owner decisions remain open in
`docs/PHASE0_ARCHITECTURE_REVIEW.md`.

## Near-term: SHIELD v3 — intrusion detection & response

Full design and the reconciled "Active Defense & Counterintelligence" addendum:
`docs/designs/2026-11-shield-v3-intrusion-detection.md` (§11 maps the addendum's WATCH/GUARD/COMMAND modes onto
JANUS's response tiers).

| Phase | Scope | State |
|---|---|---|
| **1 — JANUS's own detection** | Sign-in alerts; no sensor, no new blocking (the existing throttles already lock). WATCH mode for sign-in signals | **Delivered** (migration 0024) |
| **2 — CrowdSec sensor + GUARD** | Outbound-only `janus-sensor` on the owner's machines; standing response authorization; time-limited automatic blocks with allow list, caps and kill switch; person-approved tier; Intrusion Detection UI | **In progress** — built and tested (design §10b); awaiting safeguard validation on a real machine and the BLACKSITE review |
| **3 — SENTINEL indicator store** | Threat-intel repository (IP, domain, hash, fingerprint, ATT&CK technique) with confidence labels, first/last-seen, expiry and false-positive correction; correlation into incidents. New tables, no new infrastructure | **Design for review** (`docs/designs/2026-11-sentinel-indicator-store.md`); 6 owner decisions open |
| **4 — deception / honeypots** | Isolated decoy services to observe hostile activity, on infrastructure the owner is authorized to run. Gated: needs its own scoping and an explicit owner decision because it stands up new attacker-facing services | **Planned, gated** |
| **SHIELD v4 — host and network monitoring** | osquery-based host state, file integrity and posture on the owner's Windows and Linux machines through the existing sensor; optional Suricata IDS. Detection only, no new automatic actions. Design: `docs/designs/2026-11-shield-v4-host-network-monitoring.md` | **4a delivered** (host state, migration 0026); **4b built** (host alerts, file integrity, migration 0027 held); 4c (network IDS) later |

Phase 2 safeguards (from the design): the sensor is outbound-only with a fixed action set (no shell, no execution
endpoint); each sensor has its own revocable key scoped to one machine; automatic blocks run only under a standing
authorization the owner records (which machines, ≤4h blocks, per-hour cap, 90-day expiry); an allow list that
cannot be blocked; a one-switch kill switch to alert-only; every block expires and is one-click liftable; every
action is an audit-trail and incident-timeline entry.

## Other tracks (parallel, owner-paced)

| Track | Next step | State |
|---|---|---|
| **BLACKSITE** | Independent review of the Phase-1 security foundation; resolve R-conditions and D1/D3/D4 | Planned (self-review mode temporary) |
| **Profile B** | First controlled-validation run once its review is recorded | Ready, off |
| **Lab tool pack 1** | Self-review and first use | Designed, evidence captured |
| **WARPATH** | First exercise | Delivered, unused |
| **Operational safeguards** | Backup + tested restore, 2FA across GitHub/Vercel/Neon/Anthropic, Dependabot, branch protection, an incident runbook, rollback habit | Recommended, owner's side |

## Honest limits (what JANUS will not do)

- It does not strike back, and will not be built to. Lawful responses to an attack are: block at your own
  firewall, report to the source provider's abuse contact, contribute to community blocklists, preserve evidence,
  and report to the authorities (e.g. FBI IC3).
- It sees only what its sensors and audit trail see; an intruder who trips no rule is not detected. It is a layer,
  not a guarantee, and the UI says "blocked on <machine> until <time>", never "threat neutralized".
- It cannot put a sensor on Vercel or Neon; those rely on their own settings and on account security.
- It does not cover customer systems.
