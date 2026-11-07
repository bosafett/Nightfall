# BLACK OPS Profile B: controlled validation (design for review)

Status: **design, 2026-11-07. Step 1 (G1, proof of control) is built; nothing else is built or enabled.** Profile B stays switched off in code
(`blackops/catalog.py` refuses any playbook that lists it). Building starts only after an independent review
of this document is recorded and the owner decisions in §11 are made.

## 1. What Profile B is

Addendum 4 §4 defines three execution profiles:

| | A: live (built) | **B: controlled validation** | C: isolated lab (built) |
|---|---|---|---|
| Targets | Authorized real targets | Authorized real targets **whose control is proven** | Lab network only |
| Allowed | Passive collection, bounded read-only requests | A plus designated test accounts, controlled input testing, safe reproduction | Exploit reproduction, deliberately vulnerable apps |
| Never | Anything that changes state | Destructive or unauthorized actions; real users' accounts or data | Reaching anything outside the lab |

Profile B is the first time JANUS would **log in to a real application** and **send chosen input** to a real
target. Both are more intrusive than anything Profile A does, so Profile B adds gates that A doesn't need.

It unlocks the three playbooks Addendum 4 §10 lists after the first five:

- 6. Safe Injection Surface Assessment
- 7. Authentication Configuration Audit
- 8. Access-Control Assessment

## 2. Gates: every one must hold, checked on the server

The rule from the earlier reviews applies throughout: a check made at request time is made again at approval
and again by the worker immediately before anything is sent.

### G1. Proof of control over the target (review F3)

A written authorization reference shows intent, not control. Profile B requires proof.

- **Method:** either
  - a DNS TXT record `_janus-verify.<domain>` holding a token, or
  - a file at `https://<host>/.well-known/janus-verify.txt` holding the token.
- **Token:** 32 random bytes, one per workspace and target, shown once and stored only as a hash.
- **What it covers:**
  - A DNS proof covers the domain and every hostname under it.
  - A file proof covers only that host.
  - IP-address targets are **not eligible** in v1: there's no simple, reliable proof for an address.
- **Freshness:** the proof must have succeeded within the last 24 hours at approval, and again when the worker
  starts. If it fails at either point, the run is refused and the refusal is an audit event.
- **Evidence:** every check (DNS answer or HTTP response, with timestamp) is stored as evidence, so the report
  can show the proof.
- **Scope link:** each verification belongs to one scope version. A new scope version needs new proof.

### G2. Designated test identities

Profile B may only log in as accounts that exist **for testing**.

- **Registration:** each identity is registered against one target origin (`https://app.example.com`) with:
  - a label and a role description (e.g. "low-privilege customer"),
  - the login method,
  - the owner's attestation that it's a test account holding no real person's data.
- **Secret handling:**
  - Credentials are encrypted at rest with a key derived from the deployment secret (separate purpose label)
    and are never returned by the API: the UI shows only "set" or "not set".
  - Only the worker decrypts them, and only for the step that needs them.
  - They never enter evidence, prompts, logs or the audit trail. Evidence stores the request with the
    credential replaced by `<test-identity:label>`.
  - Session cookies and tokens obtained during a run are kept in memory only and redacted in stored responses.
- **Restrictions:**
  - AI agents can't see, propose or use identities.
  - An identity can't be used against any origin other than its own.
- **Lifecycle:**
  - The owner can retire an identity; retired identities can't be used.
  - Registering, changing or retiring an identity is an audit event.

### G3. Independent review recorded, and an explicit enable

Same pattern as BLACKSITE:

- `NIGHTFALL_PROFILE_B_ENABLED=true` **and** a non-empty `NIGHTFALL_PROFILE_B_REVIEW_REF` naming the recorded
  review.
- Without both, the catalog refuses Profile B, the routes refuse it, and the worker refuses it.
- Tests and self-review are not the independent review.

### G4. Per-run approval

- **Approval:** under the single-operator policy (decision D1), the owner approves each run explicitly, with
  two-factor confirmed in the last 15 minutes. One person with two accounts is not two approvers.
- **What the approval shows:**
  - the playbook and its version fingerprint,
  - the target and its proof (age, method),
  - the identities to be used,
  - the request budget,
  - the stop conditions.
- **Expiry:** approvals expire after 24 hours, shorter than Profile A's 72 hours.
- **AI:** agents may suggest a Profile B playbook in text but can't create the request or approve it.

### G5. Where it runs (owner decision, §11)

Recommended: a **self-hosted worker only**, not the Vercel deployment. This keeps the identity decryption key
and live sessions off the shared hosting platform, and lets the egress proxy (already used for Nuclei) pin
every request to the verified target. The hosted platform would show Profile B as "unavailable".

## 3. Execution model

Unchanged from A and C:

- Playbooks are reviewed definitions in code.
- Steps are registered collectors only.
- Nothing comes from the user or a model except the target and, for playbook 8, a list of URLs on the
  verified host.

Profile B adds:

- **Risk class:** steps are `moderate`.
  - Today the catalog allows moderate risk only in the lab.
  - The change: moderate is also allowed in Profile B, only when G1–G5 hold.
  - `high` stays forbidden everywhere.
- **Methods:**
  - GET, HEAD and OPTIONS to any path on the verified host.
  - POST only to the identity's registered login endpoint and to form actions found on in-scope pages
    (playbook 6).
  - No PUT, PATCH or DELETE in v1.
- **Payloads:**
  - Only from a reviewed, version-pinned, non-destructive corpus in code.
  - Each payload is a unique marker string, optionally wrapped in characters that show whether output is
    encoded (`'`, `"`, `<`, `>`).
  - No SQL that changes data.
  - No time-delay or resource-exhaustion payloads.
  - No file uploads.
  - No requests to third-party callback hosts.
- **Budgets per run:**
  - at most 200 requests,
  - at most 1 request per second,
  - one run per target at a time,
  - at most 30 minutes.
- **Stop conditions** (any of these ends the run and records why):
  - 3 consecutive 5xx responses, or any 429;
  - a response showing the account is locked;
  - the proof of control failing a re-check;
  - the approval being revoked;
  - a scope change;
  - the operator pressing Stop.
- **Network:**
  - Every connection goes through the per-run egress proxy, pinned to the verified host's addresses.
  - Redirects to other hosts are recorded, not followed.
- **Evidence:**
  - Requests and responses are stored like other evidence (hashed, insert-only), with credentials and
    session values redacted and bodies capped at 256 KB.
  - Results enter BLACK ICE. Findings start **unverified**, and the contradiction flags apply.

## 4. Playbooks 6–8 (outline; each gets its own definition, tests and fingerprint)

### 6. Safe Injection Surface Assessment

- **Steps:**
  1. Fetch up to 20 in-scope pages, starting from known assets. Links on other hosts aren't followed.
  2. List forms and query parameters.
  3. Send each input one marker payload.
  4. Record whether the marker comes back unencoded, and whether a server error discloses internals.
- **Not done:** exploitation, script execution or anything beyond showing the input is reflected.
- **Findings:**
  - "Input reflected without encoding" (a likely cross-site scripting point, needing a person to confirm),
  - "Error page discloses stack trace or query".
- **Cleanup:** none needed for GET. For POST forms, playbook 6 sends only to forms the operator marked safe
  (e.g. search), because a contact or sign-up form would create real records.

### 7. Authentication Configuration Audit

- **Steps:** sign in as one test identity over HTTPS, then check:
  - the session cookie's Secure, HttpOnly and SameSite flags;
  - whether the session identifier changes at login;
  - whether logout ends the session on the server;
  - whether the login page is served only over HTTPS.
- **Lockout checks:** optional, off by default.
  - At most 5 wrong passwords, only against the test identity, and only if the owner ticks "lockout test
    allowed" on that identity.
  - Stops at the first sign of lockout.
- **Not done:** guessing other users' passwords, enumerating usernames at volume, attacking two-factor.

### 8. Access-Control Assessment

- **Inputs:**
  - Two test identities with different roles.
  - A list of up to 50 URLs on the verified host that the operator registers (not generated by AI) as
    belonging to the higher role.
- **Steps:**
  1. Fetch each URL as the higher identity, as the lower identity and with no session.
  2. Compare the status codes and the hashes of the response bodies.
- **Findings:**
  - "Lower-privilege identity received a higher-privilege resource",
  - "Resource available without a session".
- **Methods:** GET only. Nothing is changed.

## 5. Data model (needs a migration; nothing written yet)

- **`ownership_verifications`:**
  - workspace, scope version, target, method, token hash, last success, last failure, evidence id;
  - RLS by workspace;
  - the app role inserts and updates its status; only the owner can create one.
- **`test_identities`:**
  - workspace, origin, label, role description, encrypted secret, attestation by and at, lockout-test
    allowed, retired at;
  - RLS by workspace;
  - the API may write the encrypted column but never select it;
  - only the worker role can select it.
- **`playbook_runs`:** gains the identities used (ids only) and the verification ids checked.
- **Database checks:**
  - a Profile B run can't be inserted without at least one verification id;
  - a retired identity can't be used.

## 6. Threats and mitigations

| Threat | Mitigation |
|---|---|
| Testing a site the owner doesn't control | G1 proof at approval and at start; IPs not eligible |
| Proof copied from another site | Token is per workspace and target and stored hashed; DNS proof must be under the target's own name |
| Hurting a real user | Only registered test identities; GET-only access-control checks; safe-form opt-in for POST; lockout test opt-in, capped at 5 |
| Damage or load on the target | Request, rate and time budgets; stop on 5xx, 429 or lockout; one run per target |
| Credential leak | Encrypted at rest, decrypted only on the worker, never returned, redacted from evidence, logs, audit and prompts |
| A model steering an attack | Agents can't create, approve or parameterize Profile B runs; payloads are a fixed corpus |
| Self-approval passing as review | G3 needs a recorded independent review; D1 doesn't treat a second account as a second person |
| Request leaving the target | Egress proxy pinned to the verified host; cross-host redirects not followed |
| Tampering with what happened | Evidence hashed and insert-only; audit export chain (F7) |

## 7. Tests required before enabling

- Each gate refuses on its own: no proof, stale proof, no identity, retired identity, review ref missing,
  enable flag off, approval expired, approval without fresh two-factor, hosted platform.
- The worker re-checks every gate and refuses with an audit event.
- No step sends a method or payload outside the allowlist (unit tests over every playbook definition).
- Budgets and every stop condition end a run against a local test server.
- Credentials never appear in evidence, API responses, logs, audit data or agent prompts (a canary credential
  searched for everywhere after a run).
- The egress proxy blocks any host other than the verified one, including through redirects and DNS
  rebinding.
- Golden files for the new finding rules.

## 8. What this design doesn't do

- No exploitation, state-changing methods, file uploads or out-of-band callbacks on real targets. That stays
  lab-only (Profile C) or out of scope.
- No automatic or scheduled Profile B runs.
- No AI involvement beyond reading the resulting findings.

## 9. Build order once approved

1. Ownership verification (G1). It's useful on its own: a scope can show "control proven". **Built (migration
   0017).** Differences from §2: the observation is stored hashed in the check row rather than as an evidence record
   (the app role can't write evidence), and checks run when a person asks, from the API.
2. The test identity store (G2) and the gates (G3–G5), with no playbook yet.
3. Playbook 7 (fewest requests).
4. Playbook 8.
5. Playbook 6 (most input), each with its own review sign-off.

## 10. Effort and cost

- Three migrations are expected, one per build step 1–2 and one for the new finding rules.
- No paid services.
- A self-hosted worker is needed if G5 is accepted.

## 11. Owner decisions needed

1. **Approve this design for independent review**, or change it.
2. **Where Profile B runs:** self-hosted worker only (recommended), or also the hosted platform.
3. **Who reviews it:** the review reference that will go in `NIGHTFALL_PROFILE_B_REVIEW_REF`.
4. **Lockout testing:** allowed as an opt-in per identity, or left out of v1.
5. **POST to forms in playbook 6:** only operator-marked safe forms (recommended), or none in v1.
