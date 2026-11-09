# Review packet 3: Profile B (controlled validation on real targets)

**Unlocks:** `NIGHTFALL_PROFILE_B_REVIEW_REF`, together with `NIGHTFALL_PROFILE_B_ENABLED=true`, the worker key pair
and the **self-hosted Profile B worker** (`infra/profile-b/README.md`). Evidence collected for the self-review:
`docs/reviews/2026-11-09-profile-b-evidence.md`.
**Design:** [../../designs/2026-11-blackops-profile-b.md](../../designs/2026-11-blackops-profile-b.md): §2 gates,
§4 playbooks, §6 threats, §12 decisions, §13–§16 as built. **The highest-stakes review**: Profile B logs in to, and
sends input to, real applications. Have it reviewed by someone independent.

## 1. The question

> Can Profile B only act on a target whose control is proven, using only designated test accounts whose
> credentials can't leak, within fixed request budgets and methods, after a fresh two-factor approval, and is it
> rechecked immediately before anything is sent?

**In scope:**
- proof of control (`scope/ownership.py`, migration `0017`);
- sealed test identities (`blackops/profile_b.py`, `blackops/identities.py`, migration `0019`);
- the gates (`blackops/routes.py` preflight and launch, `recon/worker.py`, migrations `0019` and `0020`);
- playbooks 7, 8 and 6 (`recon/auth_audit.py`, `recon/access_audit.py`, `recon/input_audit.py`);
- finding rules R18–R28.

**Out of scope:** the lab (packets 1 and 2); Profile A collectors (already in use).

## 2. Claims, enforcement and evidence

| # | Claim | Enforced in | Test(s) |
|---|---|---|---|
| G1 | Proof of control (DNS TXT or a `/.well-known` file): a passing check of a covering claim, for this scope version, in the last 24 hours. Checked at preflight, by the database at launch, and by the worker | `scope/ownership.py` (`proof_for`), migration `0019` (`nf_playbook_run_guard`), `profile_b.worker_check` | `test_ownership.py::*`, `test_profile_b.py::test_every_gate_then_launch_then_worker_recheck`, `::test_worker_refuses_stale_proof_and_old_approval`, `::test_database_refuses_profile_b_runs_without_fresh_proof` |
| G2 | Credentials are sealed to the worker's X25519 key (bound to the identity and workspace). The API can't read them back; the app role has no SELECT on the sealed column; nothing returns or logs them | `profile_b.seal`/`unseal`, migration `0019` column grants, `identities.py` | `::test_sealing_binds_the_credential_to_its_row_and_the_worker_key`, `::test_identities_are_sealed_owner_only_and_never_returned`, `::test_without_a_worker_key_nothing_is_stored` |
| G2b | Identities are owner-only, attested, bound to one origin, retire-only; lockout testing is impossible (CHECK) | `identities.py`, migration `0019` | `::test_identities_are_sealed_owner_only_and_never_returned` |
| G3 | Off without the enable flag and the review reference | `profile_b.unavailable_reason` | `::test_each_gate_switches_profile_b_off_on_its_own`, `::test_gates_off_refuse_profile_b` |
| G4 | Per-run approval with two-factor in the last 15 minutes; Profile B approvals expire after 24 hours | approval routes (`fresh_mfa=True`), `control/approvals.py` | `::test_worker_refuses_stale_proof_and_old_approval` |
| G5 | Executes only on the self-hosted Profile B worker: it alone holds the private key and alone claims Profile B operations; the hosted worker never claims them and refuses them if it does; the key and the worker mode are refused on the hosted platform; the preflight needs that worker to have checked in within 5 minutes (design §17) | `config.py`, `recon/worker.py` (queues), `profile_b.worker_check`, `profile_b.worker_seen`, `blackops/catalog.py` | `::test_private_key_never_on_the_hosted_platform`, `::test_profile_b_worker_mode_is_self_hosted_only`, `::test_every_gate_then_launch_then_worker_recheck`, `::test_profile_b_worker_claims_nothing_else`, `::test_preflight_needs_a_recent_profile_b_worker`, `::test_profile_b_playbooks_use_only_profile_b_tools` |
| M1 | Moderate risk outside the lab only as a step of a Profile B run (database) | migration `0020` | `test_auth_audit.py::test_auth_audit_never_runs_outside_profile_b` |
| M2 | Profile B tools never run outside a Profile B run (worker) and aren't offered as collections | `recon/worker.py` (`PROFILE_B_TOOLS`), `recon/routes.py` (`PLAYBOOK_ONLY`) | same test |
| P7 | Playbook 7: GET only, apart from one POST to the registered login path; stops on a 429, three 5xx in a row or a lockout sign; at most 200 requests at 1 per second; certificates verified; no credentials, cookie values or bodies in evidence | `recon/auth_audit.py` | `test_auth_audit.py::*` (canary credential searched in evidence, blobs and audit) |
| P8 | Playbook 8: operator-registered paths only (validated twice); three GETs per path; only hashes and statuses stored | `recon/access_audit.py`, `blackops/routes.py` | `test_access_audit.py::*` |
| P6 | Playbook 6: same-host crawl of at most 20 pages; one inert marker per input from corpus `janus-markers/1`; POST only to operator-marked safe forms | `recon/input_audit.py` | `test_input_audit.py::*` (a contact form that must never be POSTed) |

## 3. Things to check by hand

1. **Read `profile_b.py` sealing:** algorithm choices, nonce handling, associated data, failure handling. Is X25519
   + HKDF-SHA256 + AES-256-GCM used correctly?
2. **Run playbook 7 against a test application you own**, with a real test account, then search the stored evidence
   and the database for the password, the username and the session cookie value.
3. **Look for a path that sends a request before the worker's re-check**, or that skips it. Follow `process()` in
   `recon/worker.py` from claim to collector.
4. **Playbook 6 corpus:** is `'"<jns>` inert in every context you can think of (HTML, attributes, JavaScript,
   SQL, logs)? Is "operator marks safe forms" a sufficient control?
5. **Playbook 8:** could a registered path cause a state change through GET on a badly designed application? Should
   the UI warn about that more strongly?
6. **The address-pinning client is used rather than a per-run egress proxy** (design §14 "not yet"). Is that
   acceptable for v1?

## 4. Questions to answer in the report

- Under what conditions could Profile B touch an asset the owner doesn't control, or an account that isn't a
  designated test account?
- Could a credential leave the self-hosted worker in any form?
- Are the request budgets and stop conditions enough to prevent harm to a production application?
- Which conditions, if any, should be attached to switching it on (e.g. a list of approved targets, a
  maintenance window, a first run under supervision)?

**Run these:**

```bash
cd api && .venv/bin/python -m pytest -q tests/test_ownership.py tests/test_profile_b.py tests/test_auth_audit.py tests/test_access_audit.py tests/test_input_audit.py
```
