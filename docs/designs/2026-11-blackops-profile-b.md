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

## 12. Owner decisions (2026-11-07)

1. **Design:** approved for independent review, as written.
2. **Where it runs:** a self-hosted worker only. The hosted platform shows Profile B as unavailable.
3. **Reviewer:** to be named later. Until a review is recorded, `NIGHTFALL_PROFILE_B_REVIEW_REF` stays empty and
   Profile B stays off, even once it's built.
4. **Lockout testing:** left out of v1. §11 gave no recommendation here, so the more cautious option was recorded. It
   can be added later as a per-identity opt-in, capped at 5 attempts, as described in §4.
5. **POST to forms (playbook 6):** only forms the operator marks safe.

## 13. Step 2 as built (2026-11-07, migration 0019)

- **Credentials are sealed, not just encrypted.**
  - The API seals each credential to the self-hosted worker's X25519 public key: an ephemeral key agreement, then
    HKDF-SHA256 and AES-256-GCM, bound to the identity id and workspace id.
  - Only the worker holds the private key (`NIGHTFALL_PROFILE_B_PRIVATE_KEY`), and configuration refuses that key on
    the hosted platform. The hosted API can store a credential but never read one back.
  - This is stronger than §2's "key derived from the deployment secret".
  - `nightfall-admin profile-b-keygen` makes a key pair.
- **Database rules:**
  - The app role can insert the sealed column but has no SELECT on it (column grants). Only the worker role reads it.
  - Identities can only be retired, never edited or revived.
  - `lockout_test_allowed` is constrained to false (decision 4).
- **Registering identities:** owner only (`identities.manage`), with fresh two-factor and an explicit attestation.
  Responses and audit events carry `<test-identity:label>`, never the credential. UI: BLACKSITE → BLACK OPS → Test
  identities.
- **Gates G1–G5**, in the preflight and at launch:
  - G3: the enable flag and the review reference;
  - G5: refused on the hosted platform;
  - the worker key must be configured;
  - G1: a passing proof-of-control check of a covering claim, for this scope version, in the last 24 hours;
  - G2: the identities are active, belong to this workspace, and are registered for the target's origin, with as many
    as the playbook needs.
- **G4:** Profile B approvals expire after 24 hours. Approval already requires fresh two-factor.
- **In the database:** `playbook_runs` accepts profile `validation` only on a non-lab scope, with at least one passing
  check of that scope version from the last 24 hours, and only active identities of the workspace for the target
  (trigger).
- **The worker re-checks** every gate immediately before sending anything. A retired identity, a stale proof, a
  changed scope, a missing worker key or an old approval each deny the operation, with the reason.
- **Still not done (step 3 and after):**
  - no Profile B playbook ships, and the catalog test asserts it;
  - moderate-risk operations outside the lab are still refused by the schema;
  - the egress proxy's per-target pinning for logins, request budgets, stop conditions and credential redaction in
    evidence arrive with the first playbook (7).

## 14. Step 3 as built (2026-11-08, migration 0020): playbook 7

- **Playbook** `authentication-configuration-audit` v1.0.0: Profile B only, a hostname target, one test identity,
  one moderate-risk step (`auth-audit`).
- **Login form:**
  - GETs the login page over HTTP, then HTTPS, and parses the form (nothing is executed).
  - POSTs once, only to the identity's registered login path; a form that posts anywhere else stops the run.
  - Loads the signed-in page, follows a logout link found on it (GET only), then tries the old session again.
- **HTTP basic:** checks that the credential works over HTTPS and that plain HTTP doesn't ask for it.
- **Results, rules R18–R24 (unverified, ruleset `findings/2026.11-5`):**
  - the login page is offered over plain HTTP;
  - basic credentials are requested over plain HTTP;
  - a session cookie is missing Secure, HttpOnly or SameSite;
  - the session identifier doesn't change at sign-in;
  - logout doesn't end the session.
- **Limits and stops:**
  - at most 200 requests, 1 per second, 30 minutes; a normal run makes about 10;
  - stops on a 429, three server errors in a row, or any sign the account is locked;
  - certificates are always verified; redirects are recorded, not followed;
  - all traffic goes through the address-pinning client: no private addresses, scope exclusions honoured.
- **Credentials:**
  - The worker opens the run's identity in memory, only for an approved Profile B run that passed every gate.
  - Evidence stores methods, paths, status codes and cookie attributes only. Cookie values, bodies, the username and
    the password are never stored; requests name `<test-identity:label>`.
  - A test searches the stored evidence, the evidence blobs and the audit trail for a canary password and the
    username.
- **Schema (migration 0020):** moderate-risk operations outside the lab are allowed only as steps of a Profile B run,
  checked by a trigger at insert. An operation's risk class can't change afterwards.
- **Worker:** the worker refuses `auth-audit` anywhere but in a Profile B run. The tool isn't offered as a single
  collection, and is unavailable unless Profile B's gates hold on a live, self-hosted worker.
- **Not yet:**
  - playbooks 8 (access control) and 6 (input testing), steps 4 and 5;
  - a per-run egress proxy for Profile B (the address-pinning client is used, as for Profile A's requests).

## 15. Step 4 as built (2026-11-08, no migration): playbook 8

- **Playbook** `access-control-assessment` v1.0.0: Profile B only, a hostname target, two test identities (the
  higher role first, chosen separately in the launch panel), and up to 50 paths that the operator types in at launch.
  The paths are never generated by AI.
- **Path checks:** the preflight and the collector both accept only absolute paths on the target: no scheme, no host,
  no `//`, no fragments, no whitespace, at most 50, with duplicates removed.
- **Storing the paths:** they're stored in the operation's parameters when it's created. Operations can't change
  after insert, so no migration was needed.
- **Per path:** after one sign-in per identity (the shared login code from playbook 7), it GETs the page as the higher
  identity, as the lower identity and with no session.
  - It records the status, the redirect target, whether a login page came back, the size and the first 16 hex
    characters of the content hash. It never stores the content.
  - A path is judged only when the higher identity itself received the page.
- **Rules (ruleset `findings/2026.11-6`, unverified):**
  - R25: the lower identity received the page;
  - R26: the page is available without a session;
  - each is high severity and confidence for identical content, medium for a different page with status 200 (a
    person checks what it shows).
- **Limits:** the same budgets and stop conditions as playbook 7.
- **Rollbacks:** migrations 0019 and 0020 now restore their old constraints `NOT VALID` on downgrade, so a rollback
  doesn't fail on Profile B rows that already exist.

## 16. Step 5 as built (2026-11-08, no migration): playbook 6

- **Playbook** `safe-injection-surface-assessment` v1.0.0: Profile B only, a hostname target. No test identity in v1:
  it tests what an anonymous visitor reaches.
- **Mapping:** up to 20 pages over GET, starting at `/` and following links on the same host only (other hosts are
  never fetched). It lists the query parameters seen in links, and the forms.
- **Payload corpus** `janus-markers/1`: one unique marker per input followed by `'"<jns>`. It's inert in every
  context; nothing else is ever sent. At most 120 inputs.
- **POST** only to the form paths the operator marks safe at launch (decision 5). Every other POST form is skipped
  and recorded as skipped, and GET forms and query parameters use GET.
- **Results (ruleset `findings/2026.11-7`, unverified):**
  - R27: the marker came back with its quotes and angle brackets unencoded, a likely cross-site scripting point that
    a person must confirm (medium severity, medium confidence);
  - R28: a stack trace or database error that the page didn't show before (low severity; medium for a database
    error).
- **Limits:** the same budgets and stop conditions as playbook 7. The evidence keeps paths, parameter names,
  statuses and yes/no results, never bodies.
- **Status:** all three Profile B playbooks from §4 exist. Profile B stays off until its review, enable flag, worker
  key and self-hosted worker are in place.
