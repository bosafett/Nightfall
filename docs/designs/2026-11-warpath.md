# WARPATH v1: purple-team exercises in the lab (design for review)

Status: **design only, 2026-11-08.** Nothing here is built. WARPATH stays a "Planned" label until a version of this is
approved and built. The owner's decisions on the questions it rests on are in §1.

## 1. Decisions this design is built on (owner, 2026-11-08)

1. **v1 focus:** an exercise runner with manual detection scoring (option A). No lab log pipeline yet.
2. **ATT&CK:** steps are tagged with MITRE ATT&CK technique IDs, from a pinned copy of the catalogue.
3. **Who starts steps:** a person starts every step, as in NEXUS. Nothing chains automatically.
4. **SHIELD:** a missed detection raises a SHIELD alert ("detection gap").

## 2. What the spec asks for, and what v1 covers

Addendum 5 §4.3 describes WARPATH as an adversarial simulation environment that tests security posture by simulating
controlled adversarial activity **against authorized lab environments**. It must not introduce unrestricted
autonomous attack execution, and it reports to BLACK ICE and SHIELD.

| Capability in §4.3 | v1 |
|---|---|
| Attack-path simulation | **Yes:** an exercise can start from an Attack Graph path, step by step |
| Purple-team exercises | **Yes:** the attacking step and the defenders' detection score sit side by side |
| Detection coverage validation | **Yes, scored by a person:** detected, partly detected or missed, per technique |
| Defensive control testing | **Partly:** a step whose attack was blocked is recorded as blocked |
| Security response evaluation | **Partly:** an optional time-to-detect per step; no incident workflow yet (SHIELD's incident response is still planned) |
| Adversary behaviour modelling | **No:** exercises are composed by a person from reviewed playbooks; no adversary profiles yet |

### An honest limit

The lab's playbooks today are discovery and scanning: web exposure checks, TLS and header audits, and lab tool pack 1.
So v1 exercises simulate the **reconnaissance and initial-access probing** stages of an attack (e.g. ATT&CK T1595
Active Scanning, T1046 Network Service Discovery, T1592 Gather Victim Host Information). Later stages (exploitation,
persistence, lateral movement) need new reviewed lab playbooks. WARPATH will run them unchanged once they exist, and
the UI says so plainly instead of offering techniques nothing can perform.

## 3. Prerequisites: everything already gated

- **BLACKSITE enabled**, with its recorded review, the lab machine and the lab worker. Lab runs are launched only from
  the host-only BLACKSITE app (decision D3), so running WARPATH steps happens there too.
- **A lab scope** on the project. Targets are lab addresses only, enforced by the scope rules, the lab worker's
  network confinement and the database, all as today.
- **Lab tool pack 1** is optional. Its playbook joins the step choices only once its own review is recorded.

Until these hold, WARPATH's pages show exercises, plans and past scorecards, and running is "unavailable" with the
reason.

## 4. Model

### Exercise plan (authored in the main app; owner approves)

- **Fields:** project (with a lab scope), name, objective, optional source Attack Graph path, and an ordered list of up
  to 20 steps.
- **Each step:**
  - a lab-capable playbook from the catalog (today: `web-exposure-audit`, `tls-configuration-audit`,
    `http-security-assessment` and, once reviewed, `known-weakness-scan-lab`);
  - a lab target from the lab scope;
  - one ATT&CK technique ID (from the pinned list, filtered to techniques the playbook's activity actually
    represents, see §5);
  - the expected detection: free text, e.g. "IDS alert for vulnerability scanning".
- **States:** a draft is editable. **Approving** it needs the owner, fresh two-factor and the plan's SHA-256. After
  that the plan is frozen: changing it means a new version and a new approval.
- **Approval approves nothing that runs.** As in NEXUS, approving the plan is permission to begin. Every step's lab
  playbook still needs the normal per-run lab approval, which expires after 24 hours.

### Running (NEXUS, from BLACKSITE)

An approved plan runs as a NEXUS run of a new **plan-driven** definition, `warpath-exercise`:
- **The definition, in code and fingerprinted,** fixes the step kinds and rules. Each plan step becomes:
  1. a `playbook` step: a person starts it from BLACKSITE, it goes through the normal lab preflight and approval, and
     the lab worker runs it;
  2. a `review` step: a defender records the detection score.
- **The plan supplies the sequence** and is pinned by its hash. NEXUS refuses a run whose plan changed.
- NEXUS gains plan-driven runs for this. Nothing else about its rules changes: no permissions of its own, checks when
  each step starts, every transition recorded.

### Scoring (the purple part)

For each step, a person with `findings.validate` records:
- **attack result:** succeeded (the playbook found what it looked for), failed, or blocked (refused or stopped by a
  control);
- **detection:** detected, partly detected, missed or not applicable;
- **optional:** time to detect (minutes), and a note (which alert, which tool).

Under the single-operator policy the person who launches can also score. The scorecard shows who did each, so that's
visible, not hidden.

### Results

- **BLACK ICE:** the playbooks' findings arrive as today, labelled as lab results.
- **SHIELD:** a step scored **missed** raises a SHIELD alert of a new kind, `detection.gap`, with medium severity. It
  links the exercise, the step, the technique and the evidence. **Partly detected** raises a low-severity one.
- **Scorecard per exercise:**
  - techniques attempted, succeeded and blocked;
  - detection coverage (detected, partly detected and missed per technique);
  - time to detect;
  - a matrix by ATT&CK tactic.
  - It can be downloaded as JSON, and later included in a report.

## 5. ATT&CK catalogue

- **Source:** a pinned subset of MITRE ATT&CK Enterprise (technique ID, name, tactic), with the release number and
  source file hash recorded. It's bundled as a small JSON file in the repo, built by a script from the official STIX
  release. The release is chosen at build time, at least two weeks old.
- **Licence:** ATT&CK is free to use under MITRE's terms of use. The attribution is shown on the WARPATH page.
- **Which techniques each playbook may claim:** each lab playbook declares the techniques its activity represents, a
  reviewed mapping in code, e.g.
  - `web-exposure-audit` → T1595.002 (Vulnerability Scanning) and T1592;
  - `tls-configuration-audit` → T1595 and T1590;
  - `http-security-assessment` → T1592.002.

  A step can only be tagged with a technique its playbook declares, so a scorecard can't claim "T1059 Command
  Execution tested" for a header audit.

## 6. Data model (one migration; nothing written yet)

- **`warpath_exercises`:**
  - workspace, project, name, objective, source path id, version, plan (JSONB) and plan_sha256;
  - state (draft, approved, running, finished, cancelled), created by, approved by and at;
  - the NEXUS run id;
  - RLS by workspace.
  - Plan and hash are immutable once approved; the trigger allows only state changes along the lifecycle.
- **`warpath_scores`:**
  - exercise, step ordinal, technique, attack result, detection, time to detect, note, scored by and at;
  - insert-only: re-scoring adds a row, and the latest row counts.
- **`alerts.kind`:** gains `detection.gap`.

## 7. UI

- **SWORD → WARPATH:**
  - a list of exercises with their scorecards;
  - a plan editor for drafts (choose an Attack Graph path, or add steps: playbook, lab target, technique, expected
    detection);
  - owner approval;
  - scorecard pages with the tactic matrix.
  - Running shows where to go: BLACKSITE on the lab machine.
- **In BLACKSITE:** the exercise run view: start each step, see the lab approval, and score detection after each step.
- **Elsewhere:** CHRONICLE and the project history show exercise events, and SHIELD shows detection-gap alerts.

## 8. Threats and mitigations

| Threat | Mitigation |
|---|---|
| WARPATH used to attack something real | Lab scopes only; lab worker network confinement; the BLACKSITE host-only boundary; the same scope, database and worker checks as every lab run |
| Autonomous attack chains | A person starts every step; each step's playbook needs its own lab approval; approving a plan approves nothing; no AI step kinds |
| Plans changed after approval | Plan hash pinned by the approval and by the NEXUS run; database immutability once approved |
| Inflated coverage claims | A technique tag is limited to what the playbook declares; scoring by a named person; missed detections become SHIELD alerts, not footnotes |
| AI steering exercises | Agents may suggest an exercise in text; they can't create, approve, run or score one |

## 9. Tests required

- **Plans:** validation (lab scope only, lab-capable playbooks only, technique allowed for the playbook, at most 20
  steps).
- **Approval:** owner and fresh two-factor only; the hash is pinned; an approved plan can't be edited.
- **NEXUS plan-driven runs:** a refused start if the plan changed; each playbook step goes through the lab preflight
  and lab approval; review steps complete only with a score.
- **Gates:** running is refused unless BLACKSITE is enabled with its review and the request comes through the
  BLACKSITE app.
- **Scoring and alerts:** scoring permissions; insert-only history; `detection.gap` alerts raised for missed and
  partly detected steps and resolved like other alerts.
- **Scorecard:** golden-file tests.
- **ATT&CK catalogue:** the file's hash pinned; the playbook-to-technique mappings reviewed.

## 10. Build order once approved

1. The ATT&CK catalogue file and the playbook mappings.
2. Migration, plans and approval (API and the WARPATH page).
3. NEXUS plan-driven runs, and the BLACKSITE run view with scoring.
4. Scorecards, and SHIELD `detection.gap` alerts.

Effort: about the size of SHIELD v1. One migration. No paid services and no new infrastructure.

## 11. Owner decisions needed

1. **Approve this design for review**, or change it.
2. **Scoring:** anyone with `findings.validate` may score detection (recommended), or only someone other than the
   person who launched the step. Under the single-operator policy that second option would block scoring.
3. **Partly detected raises a low-severity SHIELD alert** (recommended), or only "missed" raises alerts.
4. **Building before the lab exists:** build WARPATH now, switched off, as with Profile B (recommended), or wait until
   BLACKSITE is enabled.
