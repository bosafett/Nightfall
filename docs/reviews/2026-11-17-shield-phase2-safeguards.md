# SHIELD v3 phase 2 — safeguard validation (2026-11-17)

Scope: the CrowdSec sensor and GUARD as built (design `docs/designs/2026-11-shield-v3-intrusion-detection.md` §4,
§7, §10b). This is the build-time validation by the implementer. It is **not** the independent BLACKSITE security
review, which is still outstanding.

## Environment

- API and database: this repository's test harness (real Postgres 16, app role under row-level security).
- **Real CrowdSec 1.4.6** (Ubuntu package) local API, with the packaged `crowdsecurity/sshd-logs` parser and
  `crowdsecurity/ssh-bf` scenario, and the profile from `infra/janus-sensor/README.md` (`type: janus_alert`).
- **Real nftables firewall bouncer** (`crowdsec-firewall-bouncer` 0.0.25, nftables mode).
- **Real janus-sensor code** (`infra/janus-sensor/janus_sensor.py`), driving real `cscli`.
- Attack traffic: a synthetic sshd log (failed root passwords from TEST-NET addresses) replayed through `crowdsec`,
  producing genuine `crowdsecurity/ssh-bf` alerts.

Reproduce: `JANUS_LIVE_VALIDATION=1 pytest -s tests/test_shield_live_validation.py` (root, CrowdSec running).

## Results

| # | Safeguard (design §) | How checked | Result |
|---|---|---|---|
| 1 | Automatic blocks only under a live standing response authorization (§4) | API tests; DB trigger tests; live | **Pass** |
| 2 | Authorization covers only the listed sensors and `block_ip`; insert-only apart from ending; ≤90 days; one live per workspace | DB tests (`test_shield_sensors.py`); API tests | **Pass** |
| 3 | GUARD blocks one address only, on the machine that saw it, ≤ the authorized length (≤4 h) | API tests; DB trigger; live: real ssh-bf on 203.0.113.90 → one /32 block, 15 min, on that sensor | **Pass** |
| 4 | JANUS allow list can't be blocked, either tier | API + DB tests; live: 198.51.100.30 attack → alert, no block, not in nftables | **Pass** |
| 5 | Sensor's own allow list, enforced on the machine even if JANUS says otherwise (§7) | Unit test; live: approved block of 192.0.2.10 refused locally, no CrowdSec decision, not in nftables, `shield.sensor.block_refused` audited | **Pass** |
| 6 | Never block loopback, link-local, multicast, unspecified, reserved | API and sensor unit tests | **Pass** |
| 7 | Per-hour cap per sensor, then alert-only (§4, §7 flood) | API tests; live with cap 2: third attacker in the hour got no block; `shield.guard.cap_reached` audited | **Pass** |
| 8 | Kill switch stops automatic response at once; alerts still flow | API tests; live: paused → real alert sent, no block, not in nftables; resume needs owner + fresh 2FA | **Pass** |
| 9 | Every block expires | DB `CHECK`; CrowdSec ban created with the remaining seconds; nftables element carries a timeout | **Pass** (natural expiry not waited out live) |
| 10 | One-click lift, recorded | API tests; live: lift → sensor deleted exactly its `janus:` decision, CrowdSec's own `janus_alert` record untouched, address left nftables | **Pass** |
| 11 | Fixed action set; no shell; takes no other instruction | Code review: fixed `cscli` argument lists, `shell` never used; JANUS sends only id/target/expiry | **Pass** |
| 12 | Outbound only | Code review: the sensor opens no socket for listening | **Pass** |
| 13 | One key per sensor, hash only, revocable at once (§7 stolen key) | API tests; live: revoked key → 401 | **Pass** |
| 14 | A sensor sees and reports only its own machine's blocks; workspaces isolated | API tests (other sensor's ids ignored; other workspace sees nothing); RLS tests | **Pass** |
| 15 | Browser origin (CSRF) exemption limited to key-only `/api/sensor/*`; rate limit kept | Code review; route-security test requires an auth marker on every route | **Pass** |
| 16 | AI agents can't trigger, approve or widen a response | No module outside `shield/` and the app wiring imports GUARD or the block tables | **Pass** |
| 17 | Owner + fresh 2FA to block more or blind JANUS; admins for fail-safe actions | API permission tests (admin refused on 4 owner actions; stale 2FA refused) | **Pass** |
| 18 | Every action audited | Live run produced `shield.sensor.registered`, `response.authorized/paused/resumed`, `allowlist.added`, `guard.blocked/refused/cap_reached`, `block.approved/lifted`, `sensor.alerts/decisions/block_refused/revoked` | **Pass** |
| 19 | CrowdSec's own bans don't bypass JANUS | Live: with the `janus_alert` profile, CrowdSec records the alert and the bouncer ignores it (it acts on `ban` only) | **Pass, with the README profile** |
| 20 | Alert content is data, never instructions | Category chosen from a fixed list; 8 KB cap on raw; 100 per batch; UI renders as text | **Pass** |
| 21 | New rules alert-only for their first week (§7 false positives) | — | **Not built** |

## Defects found and fixed during validation

1. **README told you to remove the profile's `decisions:` block.** On CrowdSec 1.4.6 that also drops the alert, so
   nothing would have reached JANUS. Replaced with the `janus_alert` decision type (recorded, not enforced),
   verified against the real bouncer.
2. **Orphaned bans.** A `janus:` ban whose block is no longer live in JANUS (lift reported while the sensor was
   down, or a sensor revoked and re-registered) would stay until it expired. The sensor now reconciles every cycle:
   JANUS is the source of truth for `janus:` bans, and any it doesn't list is deleted (skipped when JANUS's list
   could be truncated). Verified live: leftovers from earlier runs were removed.
3. **Refusals repeated every cycle.** A block the sensor refused locally was refused and audited again every 30 s.
   It is now reported once.

## Open items (not fixed here)

- **Ubuntu's `crowdsec-firewall-bouncer` 0.0.25 writes IPv4 addresses into nftables byte-reversed**
  (`198.51.100.20` appears as `20.100.51.198`), so it would block the wrong address. Use CrowdSec's own packages
  (current bouncer), not Ubuntu's. Not a JANUS defect, but it would defeat blocking on Ubuntu 24.04 defaults.
- `cscli decisions list` returns one decision per address per call, so when an address has several `janus:` bans,
  orphan cleanup takes one cycle per ban. It converges; it isn't instant.
- One sensor per CrowdSec local API is assumed: two sensors sharing one LAPI would remove each other's bans as
  orphans.
- Not yet run on the owner's lab host, against current CrowdSec (1.6.x), or through the Vercel deployment (client
  address forwarding and the per-address rate limit there).
- Not built: §7's first-week alert-only mode for new rules; decision 4 (linking automatic blocks to incidents);
  intrusion counts on the AEGIS overview.
