# SHIELD v2: incident response, with recovery and verification (design for review)

Status: **approved by the owner 2026-11-16 (all §10 decisions as recommended); built (migration 0023).** §11 lists
how the build differs from the text below, including one correction to §3.
Original status: design only; owner decisions needed are in §10.

## 1. What the spec asks for, and what v2 would cover

Addendum 5 lists SHIELD's modules: AEGIS overview, monitoring, alerts and detection (all built in v1), threat hunting,
countermeasures, incident response, and recovery and verification. It also sets limits that apply here: no agent or
automation may disable accounts, change firewall configurations or modify production infrastructure, and nothing may
present simulated activity as real.

| Module | v2 |
|---|---|
| Incident Response | **Yes:** a tracked incident built from alerts and findings, with an owner, a timeline, recorded actions and a closing review |
| Recovery & Verification | **Yes, as the last stage of an incident:** re-run the check that raised it, and show the condition is gone before closing |
| Countermeasures | **Recommendation-only, inside an incident:** the fix text SHIELD already shows, turned into a checklist a person ticks. Nothing is executed |
| Threat Hunting | **No.** Stays planned: it needs log sources, which JANUS doesn't have |

### An honest limit

JANUS sees what its own monitors and assessments see: certificates, DNS, TLS, headers, exposure checks and findings.
It has no endpoint agents, no log pipeline and no integrations. So a JANUS incident is a **record and a workflow**: what
was noticed, who decided what, what was done outside JANUS, and proof from JANUS's own checks that the condition is
gone. It doesn't contain an attacker, isolate a host or collect forensics, and the UI must not suggest it does.

## 2. Model

### Incident

- **Fields:** project, title, severity (the highest of its alerts by default; a person may change it with a reason),
  summary, lead (a member of the workspace), state, opened by and at.
- **Linked items:** one or more alerts, and optionally findings and assets. An alert belongs to at most one open
  incident. Linking is recorded; unlinking is recorded too.
- **States:** `open` → `contained` → `recovering` → `closed`. Also `cancelled` (opened by mistake), with a reason.
  - `contained`: the people handling it say the immediate exposure is stopped. A statement by a person, with a note.
  - `recovering`: the fix is in place and verification is running or due.
  - `closed`: needs the closing review (§4) and the verification result (§3).
- **Transitions** are enforced in the database: only along the lifecycle, never backwards except `closed` → `open`
  (reopen, with a reason, which keeps the whole history).

### Timeline (insert-only)

Every entry is a row that can't be edited or deleted:

- **automatic entries**, written by the same transaction as the event: opened, state changes, items linked, an alert
  seen again, a verification run requested and its result, closed, reopened;
- **notes** by people: what was observed, what was decided;
- **actions** by people: something done **outside JANUS** ("rotated the certificate", "removed the DNS record"), with
  who did it and when. JANUS records the statement; it doesn't perform or check the action itself.

This is CHRONICLE's rule applied to incidents: the timeline is the record, and corrections are new entries.

### Checklist (countermeasures, recommendation-only)

Each alert kind already carries fix text. Opening an incident copies the fix text of its alerts into a checklist. A
person ticks an item and may add a note; a tick is a timeline entry. Items can be added by hand. Nothing in the
checklist runs anything.

## 3. Recovery and verification

The point of this stage: an incident shouldn't close on someone's word alone when JANUS can check.

- **Verifiable alerts:** those raised by a monitor (`cert.*`, `tls.weakened`, `headers.regressed`, `dns.changed`,
  `ct.new_names`) or by a finding (`finding.reopened`). `monitor.failed`, `monitor.expiring`, `monitor.ended` and
  `detection.gap` aren't verifiable this way.
- **Requesting verification:** a person presses "Verify now" on the incident. For each verifiable alert, JANUS queues
  the **same check that raised it**, as an ordinary operation:
  - under the alert's live standing authorization (the monitor), so the same scope, target, tool and risk rules apply
    and the worker re-checks them, exactly as a scheduled run; or
  - if the authorization has ended, verification is "unavailable" with the reason, and the person may renew the
    authorization or close with an override (§4).
- **No new permissions.** Verification can't run a tool the monitor couldn't, can't touch a target outside the scope,
  and counts against the monitor's daily cap. A request by a person replaces waiting for tomorrow's scheduled run; it
  doesn't widen anything.
- **Result:** when the run finishes, the existing alert rules decide. If the condition is still present, the alert is
  seen again and the incident stays in `recovering` with a timeline entry "still present". If it's gone, the entry
  says "not observed in run <id>", with the evidence id.
- **Honest wording:** "not observed in the latest check" is what JANUS can say. It never says "resolved" or "secure"
  on its own; a person closes the incident.

## 4. Closing

To close, the incident needs:

1. **Verification:** every verifiable alert "not observed" in a run after the last recorded action; or an **override**
   with a written reason (e.g. the asset was decommissioned), shown on the incident and in the report as an override.
2. **A closing review:** what happened, the cause if known, what was done, what would catch it sooner next time. Free
   text with those four headings; at least the first and third are required.
3. **Its alerts resolved** by the same transaction, each noted "closed with incident <id>".

A closed incident is read-only apart from reopening. Its record can be downloaded as JSON, and included in a report as
an appendix (title, timeline, checklist, verification results, review).

## 5. Roles

- **Open, link, note, record actions, tick the checklist, request verification:** anyone with `findings.validate`
  (analyst and above), as with scoring in WARPATH.
- **Change severity, change the lead, cancel:** admin and owner.
- **Close, override verification, reopen:** admin and owner, with fresh two-factor for an override.
- Under the single-operator policy one person may do all of it. Every entry carries who did it, so that's visible.
- **AI agents:** none of the above. An agent can't open, change, verify or close an incident. (A later version could
  let Analyst draft the closing review as labelled text for a person to edit; not in v2.)

## 6. Data model (one migration, 0023; nothing written yet)

- **`incidents`:** workspace, project, title, severity, summary, lead, state, opened/contained/closed by and at,
  severity-change reason, verification override reason, closing review (JSONB with the four headings). RLS by
  workspace. A trigger enforces the lifecycle and makes a closed row immutable except for reopening.
- **`incident_items`:** incident, kind (`alert`, `finding`, `asset`), item id, added by and at, removed by and at. A
  unique index stops an alert being in two open incidents.
- **`incident_entries`:** incident, kind (`event`, `note`, `action`, `check`, `verification`), text, data (JSONB:
  ids, states), actor, at. Insert-only for every role.
- **`operations.incident_id`:** set on verification runs, so the result can be tied back. A trigger allows it only
  together with a monitor authorization of the same project.
- **Grants:** the app role reads and writes all three within its workspace; the worker may insert `incident_entries`
  of kind `verification` only (a restrictive policy), mirroring how alerts are worker-written.

## 7. UI

- **SHIELD → Incident Response** becomes a page: open incidents by severity, then closed ones.
- **Incident page:** header (state, severity, lead), linked alerts and findings, the checklist, the timeline, a
  "Verification" panel with each verifiable alert's latest result and a "Verify now" button, and "Close" with the
  review form.
- **From an alert:** "Open incident" (prefilled), or "Add to incident".
- **AEGIS Overview:** open incidents count and the oldest open incident.
- **SHIELD → Recovery & Verification:** not a separate page. The sidebar entry gets the tag "In Incidents", as BLACK
  ICE, ATLAS and CHRONICLE do.
- **Elsewhere:** incident events appear in CHRONICLE and the project history; War Room lists incidents awaiting
  verification or a closing review.

## 8. Threats and mitigations

| Threat | Mitigation |
|---|---|
| Verification used to run something the monitor couldn't | It queues the monitor's own check under its live authorization; the database trigger and the worker re-check scope, target, tool, risk and expiry, as for scheduled runs; it counts against the daily cap |
| An incident closed while the problem is still there | Closing needs "not observed" after the last action, or a labelled override by an admin or owner with fresh two-factor |
| History rewritten after the fact | Timeline entries are insert-only; a closed incident is immutable; every change is also in the hash-chained audit trail |
| JANUS presented as doing the response | Actions are recorded statements by named people; the UI and reports say "recorded", never "performed"; no integrations, nothing executed |
| AI steering an incident | Agents have no incident permissions |
| Alert floods creating incident floods | Incidents are opened by people (decision 3 below); one incident can hold many alerts |

## 9. Tests required

- **Lifecycle:** only the allowed transitions; closed rows immutable; reopen keeps history.
- **Items:** an alert in at most one open incident; link and unlink recorded.
- **Timeline:** insert-only for every role; automatic entries in the same transaction as their event.
- **Verification:** queues the monitor's own check; refused without a live authorization; counts against the cap;
  "still present" and "not observed" results; the worker can insert only verification entries.
- **Closing:** refused without verification or override; override needs admin or owner and fresh two-factor; alerts
  resolved in the same transaction.
- **Roles:** each action against each role; agents refused.
- **Export:** golden-file test of the incident record.

## 10. Owner decisions needed

1. **Scope:** incident response **with** recovery and verification (recommended: verification is what makes closing
   mean something), or incident response only.
2. **Closing rule:** verification required, with a labelled override (recommended), or verification optional.
3. **Opening:** people open incidents (recommended), or high and critical alerts open one automatically.
4. **Who closes:** admin and owner (recommended), or anyone with `findings.validate`.

Effort: about the size of WARPATH v1. One migration (0023). No paid services, no new infrastructure, nothing
self-hosted.

## 11. As built (2026-11-16, migration 0023)

- **Decisions:** all four §10 decisions as recommended: incidents with verification; closing needs verification or
  a labelled override; people open incidents; admins and owners close.
- **Correction to §3: which alerts can be verified.** Most SHIELD alerts report a **change** between two checks (a
  different certificate, changed DNS records, new names in certificate logs). Re-running the check can't say a change
  is "gone", so those aren't verifiable, and an incident holding only such alerts closes on its review, with the
  timeline saying so. Verifiable alerts are the ones that describe a **condition**:
  - `cert.expiring`: the certificate still expires within the alert window;
  - `tls.weakened`: the old protocols it named are still accepted, or the certificate still doesn't validate;
  - `headers.regressed`: any of the header checks it named still fails;
  - `finding.reopened`: the finding's check observed the problem again.
- **How "still present" is decided:** from the fresh check's own facts, compared with the facts kept with the alert
  (new column `alerts.data`), not by waiting for the alert to be raised again. An alert raised before 0023 has no kept
  facts: `tls.weakened` is then judged conservatively (any old protocol, or an untrusted certificate), and
  `headers.regressed` comes back "undecided", which doesn't count as verified.
- **A check counts only if it ran after the last recorded action.** Recording a new action makes an earlier "not
  observed" stale, and the incident asks for verification again.
- **Verification runs** are ordinary operations with `monitor_authorization_id` and the new `incident_id`. If the
  alert's own authorization was renewed, the project's live one covering the same target and check is used. No live
  authorization, a changed scope, the daily cap or a check already waiting each skip the run with the reason.
- **Permissions:** new `incidents.manage` (admin and owner): severity, lead, cancel, close, reopen. Closing with an
  override also needs two-factor in the last 15 minutes. Everything else needs `findings.validate`.
- **Database:** the lifecycle, the frozen closed row, one in-progress incident per alert, the insert-only timeline
  (ordered by a sequence column), and the rule that a verification run must be a monitored operation of the
  incident's project are all enforced by triggers and grants. The worker may insert verification results only, and
  the API may not insert them at all.
- **Checklist:** stored as timeline entries (the latest entry per item is its state), so every tick is on the record.
- **UI:** SHIELD → Incident Response (list and incident page); "Open incident" and "In an incident" on each alert;
  incidents in progress on AEGIS. Recovery & Verification is tagged "In Incidents" in the sidebar.
- **Not built in this version:** the report appendix (the JSON export exists); War Room entries for incidents;
  automatic "alert seen again" timeline entries; linking findings and assets from the UI (the API accepts them).
