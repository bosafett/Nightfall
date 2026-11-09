# BLACKSITE self-review

> **This is a self-review and is NOT independent.** The evidence below was collected by the AI assistant that helped
> build the system. The result and answers are the owner's, given on 2026-11-08.
>
> **Limits of this review:** the owner did not check findings F2–F8 or any of the four packet questions. For those,
> this review rests on the automated tests and the assistant's evidence, not on the owner's own examination.

| | |
|---|---|
| Reviewer | Owner, self-review (not independent) |
| Commit reviewed | `194b377211cef88957368fec56e2364cd6fd5950` (2026-11-08) plus the uncommitted changes listed below |
| Packet | docs/reviews/packets/1-blacksite.md |
| Result | Approved with conditions |
| Reference for the switch | `SELF:2026-11-08 owner, docs/reviews/2026-11-08-blacksite-self-review.md`, valid only while self-review mode is on (until 2027-01-31) |

## Changes on top of the commit (uncommitted when this evidence was collected)

- `api/nightfall/tools/runner.py`: Linux-only modules load only on POSIX. On anything else, `run` and `verify_lock`
  refuse, so no tool can start without its sandbox.
- `api/nightfall/config.py`: `NIGHTFALL_LAB_PACK1_DIR` also accepts a POSIX absolute path, so settings load on Windows.
- `api/tests/test_tool_runner.py`: test for the refusal above.
- `api/nightfall/blacksite/static/index.html`, `app.css`: console wordmark, an inline SVG with no script or inline style.
- `web/app/w/[ws]/blacksite/page.tsx`, `web/tests/e2e/workbench.spec.ts`: owner-only link to the console. It adds no
  execution control to the hosted app.

The running lab worker image was built before these changes.

## What was checked

### Automated tests (throwaway Postgres 16, no network, no Neon credentials)

| Suite | Result |
|---|---|
| Packet files plus `test_tool_runner.py` | 49 passed: `test_blacksite` 19, `test_blacksite_ui` 5, `test_lab` 14, `test_warpath` 4, `test_tool_runner` 7 |
| `test_blacksite_ui.py` again, after the wordmark change | 5 passed |
| Whole backend suite | 453 passed, 1 failed, 2 skipped |
| Web type check, unit tests | Clean; 48 passed |

- **The 1 failure:** `test_blackice.py::test_freshness_follows_the_operations`. The worker image sets
  `NIGHTFALL_NUCLEI_BIN`, which the test assumes is unset. It passes with that variable cleared. A comparison run
  against the unmodified commit did not execute.
- **The 2 skips:** `test_lab_pack1.py:49` (no `yaml` module) and `test_nuclei.py:183` (no `NIGHTFALL_TEST_NUCLEI_BIN`).
- **Not run:** web browser tests (`playwright`), including the two console-link assertions. The whole backend suite
  ran before the wordmark change and the web-only link change.

### Hand checks (packet §3)

| # | Check | Evidence | Status |
|---|---|---|---|
| 1 | No internet from the worker | `example.com:443` and `1.1.1.1:443` refused | See R1 |
| 1 | Lab app reachable | `172.30.99.10:80` connected | Evidence collected |
| 1 | Host LAN not reachable | LAN address (445, 5432) and router (80, 5432) refused, but the rule allows 5432 and 53 to any address | See R1 |
| 1 | Lab range consistent (F4) | `172.30.99.0/24` in `compose.yml` and in the worker's environment | Evidence collected |
| 2 | Listener on loopback only | Listens on `127.0.0.1`; refused via this machine's LAN address; foreign `Host` header gets 404. Owner reports another device on the network could not reach it. | OK (owner tested from another device) |
| 3 | Worker database identity | `nightfall_lab_worker`; not superuser, no `BYPASSRLS`, `CREATEROLE` or `CREATEDB` | Evidence collected |
| 4 | Owner account | Two-factor re-enrolled on 2026-11-08. Owner states the password and TOTP secret aren't shared. | OK (owner's statement) |
| 5 | Findings F2–F8 status | | **Not checked by the owner** |

Also observed: the `nightfall_blacksite` role was denied when reading `audit_events`, as claim B6 describes.

## Questions (packet §4): owner's answers

- Can any path (API, database role, worker, console) start lab work without the owner, fresh two-factor, a lab scope
  and an approval younger than 24 hours? **Not checked by the owner.**
- Can the lab worker, or anything in the lab network, reach the internet, the host's LAN or the hosted database other
  than through its confined role? **R1 is the known case; beyond R1, not checked by the owner.**
- Are the restrictive database policies complete, with no lab table the BLACKSITE or lab roles can read or write beyond
  lab records? **Not checked by the owner.**
- Is the audit trail sufficient to reconstruct who did what in the lab? **Not checked by the owner.**

## Findings

### R1 (Low, owner's rating): the lab worker's firewall limits ports, not destinations

- **What:** in lab mode, `infra/tools/egress-lock.sh:35-36` lets the worker process (`nfworker`) send to **any address**
  on TCP 5432 and on TCP/UDP 53. This is documented in the design, but it's wider than "only the database".
- **Observed:** `1.1.1.1:443` was refused at once; `1.1.1.1:5432` timed out, so the firewall didn't reject it.
- **Why it matters:** a compromised worker process could send data out over those ports, including to devices on the
  LAN. Tools run by the worker are locked down separately (proxy only), so this doesn't apply to them. It qualifies the
  packet's claim that the lab can never reach a real system.
- **What would fix it:** restrict 5432 to the Neon endpoint's addresses, and DNS to the configured resolver. Neon's
  addresses can change, so the rule would need refreshing.
- **Decision:** accepted as a condition by the owner, 2026-11-08. Not fixed. See Conditions.

## Conditions (if approved with conditions)

1. **R1 stays open.** The lab worker process can send to any address on TCP 5432 and TCP/UDP 53 while this self-review
   is in effect. The owner accepted this on 2026-11-08 because it matters only if the worker itself is compromised, and
   self-review mode expires within 90 days. Revisit it before extending self-review mode or starting an independent
   review.
