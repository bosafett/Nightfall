# SENTINEL: indicator store and correlation (design for review)

Status: **decisions recorded 2026-11-19 (owner: "go with the recommendations"); step 3a built (migration 0028, held
for approval).** Roadmap: SHIELD v3 phase 3 (`docs/ROADMAP.md`); origin: the
"Active Defense" addendum, reconciled in `docs/designs/2026-11-shield-v3-intrusion-detection.md` §11.2. Direction:
`docs/JANUS_DIRECTION.md`, pillar 2 (Detect and Investigate) and pillar 5 (Intelligence). Building it needs the
owner decisions in §12 and, for its migration, explicit approval before push.

## 1. What it's for

JANUS now has several detectors that don't know about each other: AEGIS monitoring alerts, sign-in alerts, CrowdSec
intrusion alerts, GUARD and approved blocks, and osquery host alerts. Each records an address, a hash or a
technique in its own table. Nothing says "this address also tried the other machine", "this file hash appeared on
two machines", or "this incident involves the same source as last week's".

SENTINEL adds one place for **indicators** (the observable things: addresses, domains, URLs, hashes, certificate
fingerprints, user agents), each with **sightings** (every time a detector saw it), a **confidence** that comes from
what JANUS observed, and a **person's assessment** that's kept apart from it. It serves the direction's north-star
questions directly: *what evidence supports the finding*, *what does JANUS know versus suspect*, and *what
infrastructure is affected*.

It's **analysis, not response**: no indicator blocks anything, opens an incident, or changes a machine (§8).

## 2. What already exists, and is reused

| Need | Reused | Not duplicated |
|---|---|---|
| Confidence vocabulary | `confidence_level` enum (low / medium / high); the Phase 0 rule of categorical confidence, never percentages | No new scale |
| ATT&CK techniques | WARPATH's pinned catalogue (`warpath/attack.json`, Enterprise 20.0, 706 techniques), which already has every technique below | No second copy |
| Where things were seen | `shield_intrusion_alerts`, `shield_host_alerts` / `shield_host_changes`, `sign_in_alerts`, `alerts` (AEGIS), `shield_blocks` | Sightings point at these rows; they aren't copied |
| Incident picture | Incidents, their timeline and items; decision 4 (c): a person links alerts to incidents | SENTINEL **suggests**; it never attaches |
| Audit | CHRONICLE (`audit_events`) for every assessment change | No separate log |
| Evidence files | BLACK BOX evidence stays project-scoped and isn't needed here: indicators carry values, not files | — |

## 3. Indicators

| Type | Value (normalized) | Typical source | Default expiry (decision 2) |
|---|---|---|---|
| `ip` | a single address (`inet`, no ranges) | CrowdSec alerts, sign-in alerts, blocks | 30 days after last seen |
| `domain` | lower-case, no trailing dot | AEGIS (certificate and DNS changes), entered by a person | 90 days |
| `url` | scheme, host, path; query string dropped | entered by a person | 90 days |
| `sha256` | 64 hex characters | host changes (watched files) | none |
| `cert_sha256` | certificate fingerprint | AEGIS TLS checks | none |
| `user_agent` | up to 300 characters | entered by a person (CrowdSec raw data is untrusted and not extracted in v1) | 30 days |

**Never an indicator:** any address on the SHIELD allow list, loopback, link-local and private ranges (unless a
person adds one by hand), and the owner's own sensors' addresses. This is what stops an attacker from spoofing
traffic to get the owner's own addresses marked as hostile.

Each indicator has: `first_seen`, `last_seen`, `sighting_count`, `computed_confidence`, `assessment`,
`assessment_reason`, `expires_at`, and a status (`active`, `expired`, `suppressed`).

## 4. Sightings

A sighting is one observation: which indicator, which source row (kind and id), which sensor or project, the event
time (when it happened) kept apart from the ingestion time (when JANUS learned of it), and the ATT&CK techniques the
source implies. Sightings are append-only and point at the source row instead of copying it, so the evidence chain
is: indicator → sighting → the original alert → its raw data and audit entries.

**Extraction is deterministic and runs when the source row is written**, inside the same transaction:

| Source | Indicator | ATT&CK (fixed, reviewed mapping) |
|---|---|---|
| Intrusion alert `ssh_bruteforce` | source address | T1110 (Brute Force); T1021.004 (SSH) as context |
| Intrusion alert `http_bruteforce` | source address | T1110 |
| Intrusion alert `web_scan` | source address | T1595 (Active Scanning) |
| Intrusion alert `exploit_attempt` | source address | T1190 (Exploit Public-Facing Application) |
| Sign-in alert | each recorded address | T1110 |
| Host alert `new_admin` | none (no observable) | T1098 (Account Manipulation) |
| Host alert `new_account` | none | T1136 (Create Account) |
| Host alert `new_ssh_key` | none | T1098.004 (SSH Authorized Keys) |
| Host alert `new_persistence` | none | T1543 / T1053 by kind (service / scheduled task, cron) |
| Host alert `new_listener` | none | T1505 / T1046 context only; low value, so no tag in v1 (decision 5) |
| Host change, `files` group | the file's new sha256 | none |
| GUARD or approved block | the target address | none (a response, not an observation) |

Host alerts without an observable still get technique tags, so an incident can show "brute force, then a new SSH
key" as a sequence even with no shared indicator.

## 5. Confidence and assessment are separate

- **Computed confidence** comes only from what JANUS observed, by a fixed rule:
  - **low:** one sighting from one source;
  - **medium:** repeated sightings, or sightings from two different source kinds or two machines.

  It never reaches **high** by itself.
- **Assessment** is a person's call:
  - `unreviewed` (the default);
  - `malicious`, which makes confidence high;
  - `benign`;
  - `false_positive`.

  Every change has a reason and goes into the audit trail. The history is kept and can be reversed.
- **False-positive correction:** marking an indicator `false_positive` or `benign` suppresses it. It stops counting
  in correlation and suggestions, new sightings are still recorded, and it isn't deleted. A person can lift it.
- **The UI always shows which is which:** "JANUS observed (computed)" next to "Assessed by <person>". AI agents may
  suggest an assessment, labelled as a suggestion; they can't set one (the same gateway rule as everywhere else).

## 6. Correlation (what the investigator sees)

- **Indicator page:** every sighting in time order across machines and detectors, the techniques, the assessment
  history, and the incidents those source alerts are linked to.
- **On an incident:** "related" panels, computed when the page is read:
  - other alerts sharing an indicator with the incident's linked alerts;
  - other machines where the same indicator was seen;
  - the techniques seen, in time order.

  These are **suggestions with a reason** ("shares 203.0.113.9 with 2 linked alerts"). Adding one is the same manual
  action as decision 4 (c).
- **Knows versus suspects** on the incident: what a person validated (findings, assessed indicators) is shown apart
  from what JANUS inferred (computed confidence, correlation, the "possible compromise" hypothesis, AI suggestions).
  Unknowns are a free-text list the investigator keeps on the incident. This uses existing incident fields; no
  new incident state.

## 7. Data model (one migration, held for approval)

- **`sentinel_indicators`:** workspace, type, normalized value (unique per workspace and type), first and last
  seen, sighting count, computed confidence, assessment, assessment reason and who/when, expiry, status. RLS by
  workspace. The app may update only the counters, times, confidence, status and the assessment columns. The
  assessment columns can be written only through a function that also writes the history row.
- **`sentinel_assessments`:** append-only history (indicator, from → to, reason, person, time).
- **`sentinel_sightings`:** append-only (indicator, nullable for technique-only sightings; source kind and id;
  sensor or project; event and ingestion times; techniques as a `text[]`, each checked against the pinned
  catalogue in the application). Index by indicator and by source.
- **Expiry and retention:** an indicator past its expiry becomes `expired` (computed when read and by the daily
  cron); sightings are kept for the retention period (decision 3), and then removed by a fixed-interval function
  like `nf_purge_host_changes`.

No change to alerts, blocks, incidents or GUARD.

## 8. What SENTINEL won't do

- **No automatic response.** An indicator never creates a block, an incident or a change on a machine. A later
  phase could let a person propose a block from a `malicious` indicator (the existing person-approved tier, allow
  list still wins), but that isn't in this design (decision 6).
- **No external threat-intel feeds in v1** (decision 1). Free feeds exist, but they add outbound calls, licence
  terms, and someone else's confidence mixed with ours.
- **No attribution.** An address seen attacking is a sighting, not an identity. The roadmap's rule stands:
  attribution is not authorization, and nothing here is used against third-party systems.

## 9. Threats and mitigations

| Threat | Mitigation |
|---|---|
| Poisoning: spoofed or planted traffic gets the owner's addresses marked hostile | Allow-listed, private and own addresses never become indicators; no automatic action; false-positive correction |
| Attacker-controlled text (URLs, user agents, scenario names) treated as instructions | Stored and shown as escaped data, length-capped; never passed to an AI agent as instructions; not extracted from CrowdSec raw data in v1 |
| Confidence overstated | Computed confidence stops at medium; only a person makes it high; the UI labels both |
| Indicator store becomes a dumping ground | Expiry by type; retention limit; only detectors and people add indicators, no bulk import in v1 |
| Cross-workspace leakage | RLS on every table; indicators are per workspace |

## 10. Honest limits

- Addresses are weak indicators: shared hosting, NAT, VPNs and cloud ranges mean the same address can be many
  people, and one attacker can use many addresses.
- Correlation only joins what JANUS saw. Without external feeds, the first sighting of anything is always low
  confidence.
- Technique tags describe what the detector suggests happened, not what was proven.

## 11. Phases and size

| Step | Scope |
|---|---|
| 3a | The three tables; extraction from intrusion alerts, sign-in alerts, blocks, host alerts and host file changes; the indicator list and indicator page; assessment with history; expiry |
| 3b | Incident correlation panels (related alerts, machines, technique sequence) and the knows-versus-suspects view |
| 3c | AEGIS sources (domains, certificate fingerprints); person-entered indicators from an incident |

Effort: 3a is about the size of SHIELD v4 step 4a; 3b and 3c about half each. No new infrastructure, no paid
services.

## 12. Owner decisions needed

1. **External threat-intel feeds:** none in v1 (recommended), or free feeds (outbound calls, licence terms).
2. **Expiry by type:** as in §3 (recommended: IP 30 days, domain/URL 90 days, hashes and fingerprints never), or
   other values.
3. **Retention of sightings and expired indicators:** 1 year (recommended), or 90 days like the host change log.
4. **Correlation on incidents:** suggestions only, added by a person (recommended, consistent with decision 4 (c)),
   or automatic attachment.
5. **ATT&CK tagging:** the fixed mapping in §4 (recommended), or no technique tags in v1.
6. **Blocking from indicators:** not in this phase (recommended), or allow a person to propose a block from a
   `malicious` IP indicator (person-approved tier only).

**Recorded 2026-11-19 (owner):** all six as recommended: (1) no external feeds in v1; (2) expiry IP 30 days,
domain/URL/user agent 90/90/30 days, hashes and fingerprints never; (3) sightings and expired indicators kept 1 year;
(4) incident correlation as suggestions a person adds; (5) the fixed ATT&CK mapping of §4; (6) no blocking from
indicators in this phase.

## 13. As built: step 3a (2026-11-19, migration 0028, held for approval)

- **Tables:** `sentinel_indicators`, `sentinel_assessments` (append-only), `sentinel_sightings` (append-only). The
  app role can't write assessment columns: only `nf_sentinel_assess`, which writes the history row in the same
  step and takes the assessor from the session (`nf_current_user`), not from the caller. Computed confidence is
  capped below high by a database `CHECK`.
- **Extraction** (`api/nightfall/sentinel/extract.py`), in the detector's own transaction:
  - from intrusion alerts: the source address, plus ATT&CK tags;
  - from GUARD and approved blocks: the target address, no tags;
  - from host alerts: technique-only sightings;
  - from watched-file changes: the new sha256.
- **Changes from the design:**
  - **Excluded addresses:** anything that isn't globally routable is never an indicator. That covers private,
    CGNAT, documentation, loopback, link-local and reserved addresses, as well as multicast, allow-listed addresses
    and ranges. It's slightly stricter than §3's list.
  - **Status isn't stored:** it's computed when read (suppressed by assessment, expired by `expires_at`), so it
    can't drift.
  - **Sign-in alerts are deferred to 3c.** They belong to a user, not to a workspace, so there's no single workspace
    to put their addresses in.
  - **Retention runs on ingest:** the one-year purge (`nf_purge_sentinel`, fixed interval) runs when sensors
    report, per workspace. There's no new cron.
- **UI:** SHIELD → SENTINEL Indicators. The list defaults to active indicators. Each indicator page shows observed
  versus assessed, sightings with their source and incident, ATT&CK techniques, assessment history, and the
  assessment form (analysts and above).
- **Verified:**
  - `test_sentinel.py`: extraction and exclusions, confidence, assessment, history, suppression, permissions, direct
    writes refused, expiry, retention, isolation;
  - the browser suite: a sensor alert from a public address becomes an indicator, which a person assesses.

## 14. As built: step 3b (2026-11-19, no migration)

- **`GET /sentinel/incidents/{id}/correlation`** (`api/nightfall/sentinel/correlation.py`), computed when read
  from the sensor alerts a person linked to the incident. Links are found in the incident's timeline entries,
  written by decision 4's escalation, and in intrusion alerts' `incident_id`. It returns:
  - **shared indicators:** with the machines that saw them, and their sightings outside the incident;
  - **suggestions:** other intrusion or host alerts sharing an indicator, each with its reason (for example
    "Shares ip … with 1 linked alert(s)"). Adding one is the decision 4 escalation; nothing is attached
    automatically. Indicators assessed benign or false positive suggest nothing;
  - **the technique sequence:** in time order, from the linked alerts only;
  - **knows versus suspects:**
    - *knows* (validated by a person): assessed indicators, validated, remediated and ruled-out findings;
    - *suspects* (inferred, unconfirmed): unreviewed indicators with their computed confidence, the
      possible-compromise rule, correlation, and findings not yet validated, including who proposed them
      (a rule, an AI agent or a person);
  - **unknowns:** the investigator's own list.
- **Unknowns** reuse the existing note entry: a timeline entry of type *Unknown* is a note with
  `{"unknown": true}` in its data. No new incident field or state.
- **UI:** an incident with linked sensor alerts shows a SENTINEL panel with knows, suspects, unknowns, the
  technique sequence, its indicators, and the suggestions, each with an *Add to incident* button.
- **Verified:**
  - `test_sentinel_correlation.py`: shared indicators across two machines, suggestion reason and escalation, the
    sequence limited to linked alerts, knows versus suspects before and after an assessment, unknowns, a
    suggestion disappearing once added, suppressed indicators suggesting nothing, isolation;
  - the browser suite: the panel shows, and an Unknown entry lands in its list.

## 15. As built: step 3c (2026-11-19, migration 0029)

- **AEGIS alerts as a source** (`source_kind` `aegis_alert`), extracted when the worker raises a new alert:
  - a changed certificate gives its new SHA-256 fingerprint (`cert_sha256`);
  - new certificate-log names and new CNAME, MX or NS targets give a `domain`, but **only names outside the
    authorized scope** (names in scope are the owner's own). The CT and DNS rules now keep those names in the
    alert's data;
  - no ATT&CK tags: §4 has no reviewed mapping for these, and a change on the owner's own site isn't an attack
    technique;
  - the worker role gets the same limited indicator columns as the app. It can **only insert** sightings, and
    only for an AEGIS alert in the same workspace. It can't read sightings back, so `record()` uses an insert
    without RETURNING.
- **Indicators a person enters** (`incident_entry`): `POST /sentinel/incidents/{id}/indicators` with
  `{type, value, note}`, for analysts and above, on an incident in progress:
  - the value is normalized as in §3: lower-case domains; URLs keep the scheme, host, port and path, with the
    query, fragment and credentials dropped; hashes as 64 hex characters (colons accepted); user agents up to
    300 characters;
  - a person may add a private address by hand. Ranges, loopback, multicast and allow-listed addresses are
    refused;
  - a timeline entry records it, and the sighting points at that entry. The audit action is
    `sentinel.indicator_entered`. It's an unreviewed sighting like any other; assessing it is a separate step.
- **Correlation:**
  - AEGIS alerts linked as incident items count as linked alerts. Indicators entered on the incident join the
    incident's indicators;
  - other alerts sharing them are suggested, with a reason such as "Shares domain …, entered on this incident";
  - an AEGIS alert is suggested only when it's in the incident's project and not resolved. Adding it is the
    existing *link item* action.
- **Sign-in alerts: not a source, a change from §4.** They belong to a user, not a workspace, and their
  addresses often include the account owner's own (a mistyped password or code). Extracting them would put the
  owner's addresses into every workspace the user belongs to. A person can enter an address from a sign-in
  alert on an incident instead.
- **UI:**
  - the incident's SENTINEL panel shows for anyone who can work the incident, with an *Add indicator* form;
  - AEGIS suggestions have *Add to incident*;
  - indicator pages label the new source kinds.
- **Verified:**
  - `test_sentinel_sources.py` covers:
    - AEGIS extraction through the real worker role: the fingerprint, the out-of-scope CNAME target, and an
      in-scope name left out;
    - the worker unable to read sightings or add other kinds;
    - validation and normalization, the person-entered timeline entry and audit;
    - AEGIS and intrusion-alert suggestions from an entered indicator, and the allow-list refusal;
  - the browser suite: an indicator entered on an incident appears in the panel and on the timeline;
  - the migration downgrades and upgrades cleanly.
