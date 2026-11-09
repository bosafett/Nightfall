# Profile B: evidence for the owner's self-review

> **This is evidence, not a review.** It was collected by the AI assistant that helped build the system. It switches
> nothing on. The verdict, the answers and any conditions are the owner's, recorded in
> `docs/reviews/<date>-profile-b-self-review.md`. A self-review is **not independent**, and the packet itself
> recommends an independent reviewer for Profile B: it logs in to, and sends input to, real applications.

| | |
|---|---|
| Packet | `docs/reviews/packets/3-profile-b.md` |
| Collected | 2026-11-09 |
| Code | the commit that adds this file (includes the self-hosted Profile B worker, design §17) |

## What changed while collecting this evidence

Profile B **couldn't run anywhere** (design §17): the hosted app refused to launch it (its G5 check looked at the
server handling the request), BLACKSITE's database role can't see non-lab scopes, and there was no self-hosted worker
for real targets. The owner chose a dedicated, self-hosted Profile B worker. G5 is now checked where the run executes,
plus a readiness check in the preflight. **G1–G4 and the review switch are unchanged.** This change is part of what's
being reviewed.

## Automated tests (local Postgres 16)

| Command | Result |
|---|---|
| Packet command: `test_ownership.py test_profile_b.py test_auth_audit.py test_access_audit.py test_input_audit.py` | **44 passed** |
| Whole backend suite, ruff, mypy; web type check, 48 unit tests, 19 browser tests | all passed |

## Hand checks (packet §3)

| # | Check | Evidence | Status |
|---|---|---|---|
| 1 | Sealing in `profile_b.py` | X25519 key agreement with a **fresh ephemeral key per credential**; HKDF-SHA256 (salt = ephemeral ‖ recipient public key, fixed info string) to a 256-bit key; AES-256-GCM with a random 96-bit nonce (a key is never reused, so nonce reuse can't happen); associated data = identity id ‖ workspace id, so a blob copied to another row or workspace fails; a version byte; every failure gives the same `SealError`. The ephemeral key is bound through the HKDF salt, not the associated data, which is sufficient | Assistant's reading; **owner to confirm** |
| 2 | Run playbook 7 against a test app you own, then search for the password, username and cookie | Needs your own test application, a proven target and the Profile B worker. The automated equivalent passes: a canary password and username are searched in evidence, blobs and the audit log (`test_auth_audit.py::test_profile_b_run_end_to_end`) | **Owner to do** (the first supervised run) |
| 3 | Any path that sends before the worker's re-check | Traced `Worker.process` (`recon/worker.py`): claim (Profile B queue only) → scope re-evaluated → `profile_b.worker_check` (switch, review, Profile B worker, key, scope unchanged and not lab, fresh proof, identities) → approval present and under 24 hours → Profile B tools only inside a Profile B run → credentials opened → **only then** `tool.run`. Any refusal ends the operation as denied before a request is sent. No other code path calls the Profile B collectors | Assistant's trace; **owner to confirm** |
| 4 | Is the marker `'"<jns>` inert everywhere? | It contains no executable syntax in HTML, attributes, JavaScript, SQL or logs. But a quote **can** break a badly written SQL query or template, which shows as a server error; that's the signal the playbook looks for, and it changes no data by itself. POSTs go only to forms you mark safe | **Owner's judgment** |
| 5 | Could a registered GET path change state? | On a badly designed app, yes (e.g. `/logout`, `/delete?id=…` as GET). Playbook 8 sends three GETs per path you register. The UI asks for paths; it doesn't yet warn against action URLs | **Owner's judgment**; possible condition below |
| 6 | Address pinning instead of a per-run egress proxy | The Profile B collectors resolve the target once and pin that address for every request (`safe_http`); the per-run proxy is used for external tools only. Acceptable for v1 per design §14 | **Owner's judgment** |

## Suggested conditions (the owner decides)

1. **First run supervised**, against a test application you own and can restore, before any other target.
2. **Register only read-only GET paths** for playbook 8 (no logout, delete or action URLs).
3. **Revisit before ending self-review mode:** an independent review for Profile B, as the packet recommends.

## Questions (packet §4): for the owner to answer

- Under what conditions could Profile B touch an asset the owner doesn't control, or an account that isn't a
  designated test account?
- Could a credential leave the self-hosted worker in any form?
- Are the request budgets and stop conditions enough to prevent harm to a production application?
- Which conditions, if any, should be attached to switching it on?

## Recording the result

Save the review as `docs/reviews/<date>-profile-b-self-review.md`. If approved, set
`NIGHTFALL_PROFILE_B_ENABLED=true` and `NIGHTFALL_PROFILE_B_REVIEW_REF=SELF:<date> owner, docs/reviews/<file>` in
Vercel (then redeploy) and the same two values in `infra/profile-b/profile-b.env` (then restart the worker). See
`infra/profile-b/README.md`.
