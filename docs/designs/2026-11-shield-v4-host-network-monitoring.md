# SHIELD v4: endpoint, server and network monitoring for the owner's own machines (design for review)

Status: **decisions recorded 2026-11-19 (owner: "go with the recommendations"); step 4a in progress.** Direction: `docs/JANUS_DIRECTION.md` (pillar 1, Monitor; §5
item 5). This is a separately scoped phase: it doesn't change SHIELD v3 phase 2, the BLACKSITE review, or any
existing gate. Building it needs the owner decisions in §10 and, for its migration, explicit approval before push.

## 1. What this adds, and what it doesn't

SHIELD v3 phase 2 sees **attacks arriving** (CrowdSec reading logs). It doesn't see **the state of the machine**:
a new administrator account, a new service listening on a port, an SSH key added to `authorized_keys`, a startup
item, a changed system file, a disabled firewall or disk encryption. Nor does it see the network as a whole.

This phase adds visibility, not response:

- **Endpoint and server state** on each enrolled machine (Windows and Linux): inventory, and alerts when
  security-relevant state changes.
- **File integrity** on a short, fixed list of sensitive paths.
- **Network intrusion detection** where the owner has a point that sees the traffic (optional, hardware-gated).
- **Posture checks** (firewall on, disk encryption on, updates recent) shown per machine.

It adds **no new automatic actions** (WATCH only). Blocking stays GUARD's single-address CrowdSec ban (v3 §4).
Host containment (isolate a machine, kill a process, disable an account) isn't offered in this phase; if ever, it
would be the person-approved tier with its own design.

## 2. Machines in scope

Only machines the owner runs and enrolls: today the Windows workstation (Docker Desktop: lab, Profile B worker) and
the Linux lab host; later any other owner server. Each is enrolled the way v3 sensors are (§4). Customer systems,
Vercel and Neon stay out of scope (v3 §8).

## 3. Recommendation: build on proven open-source agents, not our own

| Need | Recommended | Why | Rejected |
|---|---|---|---|
| Host state, inventory, file integrity (Windows + Linux) | **osquery** (open source; Linux, Windows, macOS) | One agent for both OSes; scheduled SQL queries with *differential* results (only what changed); fixed query pack; writes JSON to a local file | **Wazuh**: needs its own manager and indexer server (new hosting, against the direction's boundaries). Own agent: years of work for less |
| Attacks in logs | **CrowdSec** (already in v3), including its Windows build for RDP/SMB brute force | Already integrated, already validated | — |
| Network IDS | **Suricata** in IDS (alert-only) mode with the free ET Open rules, on a box that sees the traffic | Mature, free, JSON output (`eve.json`) | **Zeek**: richer metadata, more to run and interpret; revisit later. Inline IPS: changes the network, not offered |
| Known-vulnerable software | **Later, decision 5**: match the osquery inventory against OSV (free) | Useful, but sends the software list to a third party | — |

## 4. Architecture: one sensor per machine, more modules

```
 owner's machine                                       JANUS (Vercel)
 ┌──────────────────────────────────────┐             ┌──────────────────────────────┐
 │ CrowdSec ─┐                           │  outbound   │ SHIELD: alerts, host state,  │
 │ osquery ──┼─► janus-sensor (modules) ─┼──HTTPS────► │ posture, incidents, audit    │
 │ Suricata ─┘   reads local files only  │ ◄────────── │ blocks (v3 only)             │
 └──────────────────────────────────────┘  (polls)    └──────────────────────────────┘
```

- **Reuse, don't duplicate.** The existing `janus-sensor`, key, enrolment, heartbeat, revocation, allow list,
  GUARD, audit trail and Intrusion Detection page are extended. No second agent, no second key system, no parallel
  alert store.
- **Modules** in the sensor, each switched on in the machine's `sensor.env`: `crowdsec` (exists), `osquery`,
  `suricata`. Each **only reads a local output file** (osquery's results log, Suricata's `eve.json`), the same
  way the CrowdSec module reads `cscli` output today.
- **The query pack is fixed and lives in this repository**, pinned per sensor version. **JANUS never sends a query,
  rule or command to a machine.** osquery can run arbitrary SQL against the host; pushing queries from JANUS would
  turn it into a remote-inspection channel for whoever controls JANUS. The sensor doesn't start osquery's remote
  (TLS/distributed query) features at all.
- **Windows support** for the sensor: the sensor is standard-library Python, so it ports with a Windows service
  wrapper and Windows paths; CrowdSec and osquery both ship Windows builds.

## 5. What is collected (the fixed pack, first version)

| Group | osquery tables (Linux / Windows) | Alert when |
|---|---|---|
| Accounts | `users`, `user_groups`, `groups` | a new local account; a user added to an admin group (`sudo`/`wheel` / Administrators) |
| Remote access | `authorized_keys` (Linux); `logged_in_users` | a new SSH key; a new remote session type |
| Listening services | `listening_ports` joined with `processes` (name and path only) | a new process listening on a non-loopback address |
| Persistence | `systemd_units`, `crontab`, `kernel_modules` / `services`, `scheduled_tasks`, `startup_items` | a new service, timer, cron entry, kernel module, scheduled task or startup item |
| Software | `deb_packages`/`rpm_packages` / `programs` | inventory only (decision 5 for vulnerability matching) |
| Posture | `os_version`, firewall state, `bitlocker_info` (Windows) / disk encryption (Linux) | firewall off; disk encryption off; OS out of support |
| File integrity | `file_events` (Linux) / NTFS journal events (Windows) on a fixed list: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*`, `/etc/ssh/sshd_config`, `~/.ssh/authorized_keys`, the sensor's own files; Windows `hosts` file and the sensor's own files | any change |

**Data minimization, by design:**

- No process command lines (they carry secrets), no environment variables, no file contents, no browsing or user
  data. Paths and names only.
- File-integrity events record path, action and hash, never contents.
- Inventory is kept as the latest state plus a change log; the raw osquery output isn't stored.
- Everything the sensor sends is **untrusted data**, size-capped and categorized from a fixed list, as in v3.

## 6. Data model (one migration, held for approval)

- **`shield_host_state`**: per sensor, the latest snapshot of each group in §5 (JSON, size-capped), with
  `observed_at` kept apart from `ingested_at`. Replaced on each full snapshot; RLS by workspace; app role writes
  only through the sensor routes.
- **`shield_host_changes`**: append-only change log (sensor, group, item key, `added`/`removed`/`changed`,
  observed and ingested times). Retention decision 4.
- **Alerts (step 4b, its own migration):** reuse `shield_intrusion_alerts` by adding a `source` column (`crowdsec`, `osquery`, `suricata`) and extend
  the category list (`new_admin`, `new_ssh_key`, `new_listener`, `new_persistence`, `file_changed`,
  `posture_degraded`, `network_ids`). GUARD ignores every new category: it still acts only on the four v3 attack
  categories with a single source address. Host alerts have no source address, so 4b must also make `source`
  (an `inet`, `NOT NULL` today) nullable for host categories; that's why alerts aren't in 0026.
- **Posture** is computed from `shield_host_state` when read; no table of its own.
- No change to `shield_blocks`, the authorization, the allow list or the kill switch.

## 7. Correlation and incidents (multi-source picture)

The direction asks JANUS to correlate observations into one incident picture and to separate confirmed findings,
hypotheses and unknowns. In this phase:

- The Intrusion Detection page becomes per-machine: attacks seen (CrowdSec, Suricata), state changes (osquery),
  posture, blocks.
- A **deterministic correlation rule** flags, as a *hypothesis*, a state change on a machine within a window after
  an attack alert on the same machine (e.g. a new admin account within an hour of an SSH brute force from outside).
  It's labelled "possible compromise, unconfirmed", never "breach confirmed".
- **Opening incidents** depends on v3 decision 4 (incidents belong to a project; sensors to the workspace). This
  phase shouldn't decide it separately; it inherits the answer.
- The SENTINEL indicator store (planned phase 3) is where source addresses, hashes and network indicators from
  Suricata would accumulate. This phase only emits alerts; it doesn't build SENTINEL.

## 8. Threats and mitigations

| Threat | Mitigation |
|---|---|
| JANUS compromised and used to inspect or run things on the owner's machines | JANUS sends no queries, rules or commands; the pack is fixed in the sensor's version; osquery's remote features stay off |
| A compromised machine sends false state to hide | Sensors are evidence, not proof: the UI says what the machine reported. Missing heartbeats and a sensor-file integrity alert surface tampering; an attacker with admin rights on the machine can still lie (stated limit) |
| Secrets leak through collected data | No command lines, environment, file contents; fixed column lists per query |
| Alert floods (noisy hosts, IDS rules) | Repeat alerts raise a count (one open alert per sensor/source/category, as v3); per-sensor ingest caps; IDS rule set starts small |
| The sensor becomes an attack surface on the machine | Still outbound only, no listener; reads files; runs with only the privileges each module needs (osquery itself runs as a system service) |
| Network IDS changes the network | IDS (alert-only) mode only; no inline blocking |

## 9. Honest limits

- osquery reports what the operating system shows it. A rootkit or an attacker with administrator rights can hide
  from it; detection is a layer, not a guarantee.
- Network IDS needs a vantage point that sees the traffic (a mirror port, or running on the gateway). Many home
  routers have neither; without one, Suricata on a single machine sees only that machine's traffic.
- Encrypted traffic is opaque to the IDS beyond connection metadata.
- Nothing here covers Vercel, Neon or customer systems.

## 10. Owner decisions needed

1. **Agent:** osquery for host state and file integrity (recommended), or Wazuh (needs a new server), or nothing
   beyond CrowdSec.
2. **Windows workstation:** enroll it (recommended; it hosts the lab and Profile B), or Linux servers only at first.
3. **Network IDS:** build the Suricata module now, later once a mirror port or gateway box exists (recommended),
   or not at all.
4. **Retention:** host change log and host alerts kept for 90 days (recommended), or another period.
5. **Vulnerable-software matching:** off (recommended for now), or match the inventory against OSV, which sends the
   software list (names and versions only) to that service.
6. **Correlation:** the deterministic "possible compromise" hypothesis rule of §7 (recommended), or alerts only.

**Recorded 2026-11-19 (owner):** all six as recommended: (1) osquery; (2) enroll the Windows workstation; (3)
Suricata later, once a vantage point exists; (4) 90-day retention; (5) vulnerable-software matching off; (6) the
deterministic "possible compromise" hypothesis rule.

## 11. Phases and size

| Step | Scope | Needs |
|---|---|---|
| 4a | osquery module, fixed pack, host state and change log, per-machine page, posture; Linux and Windows | Decisions 1, 2, 4; one migration (held) |
| 4b | File integrity, host alerts, the correlation rule | Decision 6; same migration if built together |
| 4c | Suricata module (IDS only) | Decision 3 and a vantage point |
| later | Vulnerable-software matching | Decision 5 |

Effort: 4a is about the size of SHIELD v3 phase 2 (sensor module, two tables, routes, one page, tests, a live run
against real osquery on Linux and Windows). 4b is about half that. 4c depends on the network. No paid services; every
agent is free and runs on machines the owner already has.

## 12. As built: step 4a (2026-11-19, migration 0026, held for approval)

- **Migration 0026:** `shield_host_state` (latest items per sensor and group) and `shield_host_changes`
  (append-only; the app role has no `DELETE`; `nf_purge_host_changes` removes only one sensor's rows older than 90
  days and is called on each ingest). RLS by workspace. Nothing for alerts (moved to 4b, see §6).
- **One mechanism:** the pack sends only full snapshots; the API diffs each against the last and logs what was
  added or removed. The first snapshot is the baseline and logs nothing; an older snapshot arriving late is
  ignored. Only the columns listed per group are kept, values are capped at 500 characters, 5,000 items per group.
- **Sensor:** `osquery` module (`JANUS_SENSOR_MODULES`), reading osquery's results log with rotation and
  partial-line handling, merging query variants (deb + rpm; Linux + Windows), hashing persistence commands.
- **Pack:** `infra/janus-sensor/osquery/janus.conf`; remote queries and extensions off.
- **UI:** each sensor's name on Intrusion Detection opens its machine page: posture, changes (90 days), current
  state per group.
- **Verified:** API, sensor and pack tests (`test_shield_host.py`); the browser suite, including a sensor posting
  host state with its key and the machine page showing it. **Not verified:** a run against real osquery (Linux
  or Windows), so pack queries are checked for syntax and columns only, against stub tables.
